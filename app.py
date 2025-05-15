import streamlit as st
import socket
import struct
import time  # Ajout de l'import time

# -- Utility functions --
def calc_lrc(data: bytes) -> bytes:
    """Calcule le LRC sur les données (XOR de tous les octets)."""
    lrc = 0
    for b in data:
        lrc ^= b
    return bytes([lrc])


def build_concert_message(body: bytes) -> bytes:
    """
    Encapsule `body` avec STX/ETX, longueur et LRC selon Concert V3.
    STX = 0x02, ETX = 0x03.
    """
    stx = b'\x02'
    etx = b'\x03'
    # Longueur sur 2 octets big-endian
    length = struct.pack('>H', len(body))
    frame = stx + length + body + etx
    # LRC sur length + body + ETX
    lrc = calc_lrc(frame[1:])
    return frame + lrc


def send_payment_request(ip: str, port: int, amount_cents: int, tx_id: str = None, timeout: float = 5.0) -> str:
    """
    Envoie une requête de paiement au TPE et retourne le statut.
    - amount_cents: montant en centimes (1000 = 10,00 EUR)
    - tx_id: identifiant de transaction (chaîne);
    """
    if tx_id is None:
        tx_id = "STREAMLIT" + str(int(time.time()))

    # Montage du corps XML Concert V3
    xml_body = (
        '<Payment>'
          f'<Amount>{amount_cents}</Amount>'
          '<Currency>EUR</Currency>'
          f'<TransactionID>{tx_id}</TransactionID>'
        '</Payment>'
    ).encode('ascii')

    msg = build_concert_message(xml_body)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(msg)
            # Lecture de l'en-tête (STX + 2-octets longueur)
            hdr = sock.recv(3)
            if len(hdr) < 3 or hdr[0] != 0x02:
                return "Réponse invalide du TPE"
            length = struct.unpack('>H', hdr[1:3])[0]
            # Lecture du corps + ETX + LRC
            rest = sock.recv(length + 2 + 1)
            # (Optionnel) vérification LRC
            # On extrait le payload XML entre le STX/ETX
            payload = rest[:-1]  # sans LRC
            # parser entre ETX
            # Simplifions: recherche de <Status> dans le payload
            try:
                xml = payload.decode('ascii', errors='ignore')
                if '<Status>' in xml and '</Status>' in xml:
                    status = xml.split('<Status>')[1].split('</Status>')[0]
                else:
                    status = 'OK (pas de statut explicite trouvé)'
            except Exception:
                status = 'OK (payload reçu)'
            return status
    except Exception as e:
        return f"Erreur de communication: {e}"

# -- Streamlit app --
st.title("Demo Streamlit - Connexion Caisse Concert V3")

st.sidebar.header("Paramètres de connexion")
ip = st.sidebar.text_input("IP du TPE", value="192.168.0.100")
port = st.sidebar.number_input("Port du TPE", value=2300, min_value=1, max_value=65535)
amount_eur = st.sidebar.number_input("Montant (€)", value=10.0, step=0.01, format="%.2f")

if st.sidebar.button("Envoyer la transaction"):
    amount_cents = int(amount_eur * 100)
    st.info(f"Envoi de la transaction de {amount_eur:.2f} € au TPE {ip}:{port}...")
    status = send_payment_request(ip, port, amount_cents)
    if status.lower() in ['accepted', 'ok', 'autorisé', 'autorisé']:
        st.success(f"Statut de paiement : {status}")
    else:
        st.error(f"Statut de paiement : {status}")
