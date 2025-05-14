# car_device.py

import socket, os, json
from Crypto.PublicKey import RSA # type: ignore
from Crypto.Cipher import PKCS1_OAEP # type: ignore
import hmac, hashlib
from config import HMAC_KEY
from loggers import setup_logging
os.system('cls' if os.name == 'nt' else 'clear')
setup_logging()
os.system('cls' if os.name == 'nt' else 'clear')

# Parse command-line arguments for car ID and port (for simplicity, hardcoded here)
car_id = "car2"
HOST = 'localhost'
CAR_PORT = 6002

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise EOFError("Socket closed prematurely")
        data.extend(packet)
    return bytes(data)

# Generate or load car's RSA keys
if not os.path.exists(f"secrets/{car_id}_private.pem"):
    key = RSA.generate(2048)
    with open(f"secrets/{car_id}_private.pem", "wb") as f:
        f.write(key.export_key())
    with open(f"secrets/{car_id}_public.pem", "wb") as f:
        f.write(key.publickey().export_key())
    print(f"[{car_id}] RSA key pair generated.")
car_private = RSA.import_key(open(f"secrets/{car_id}_private.pem", "rb").read())
car_cipher = PKCS1_OAEP.new(car_private)

# Load server's public key for encrypting the response
server_pub_key = RSA.import_key(open("secrets/server_public.pem", "rb").read())
server_cipher = PKCS1_OAEP.new(server_pub_key)

# Listen for connection from server
print(f"[{car_id}] Listening for commands on port {CAR_PORT}")
car_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
car_sock.bind((HOST, CAR_PORT))
car_sock.listen(1)

while True:
    conn, addr = car_sock.accept()
        # Read tag + ciphertext
    n_tag   = int.from_bytes(recvall(conn, 4), 'big')  
    tag     = recvall(conn, n_tag)  
    n_ct    = int.from_bytes(recvall(conn, 4), 'big')  
    enc_msg = recvall(conn, n_ct)
    # Verify HMAC on ciphertext :contentReference[oaicite:6]{index=6}
    if not hmac.compare_digest(tag, hmac.new(HMAC_KEY, enc_msg, hashlib.sha256).digest()):
        print(f"[{car_id}] HMAC verification failed")
        conn.close()
        continue
    try:
        data = json.loads(car_cipher.decrypt(enc_msg).decode())
        cmd = data.get("command")
    except Exception as e:
        print(f"[{car_id}] Decryption failed.")
        conn.close()
        continue

    # Execute mock action
    if cmd == "lock":
        print(f"[{car_id}] Car LOCKED")
        status = "success"
    elif cmd == "unlock":
        print(f"[{car_id}] Car UNLOCKED")
        status = "success"
    else:
        status = "error"
    # Prepare and send encrypted response
    response = {"message": status, "car_id": car_id}
    enc_response = server_cipher.encrypt(json.dumps(response).encode())
    # Tag response ciphertext
    resp_tag = hmac.new(HMAC_KEY, enc_response, hashlib.sha256).digest()
    conn.sendall(len(resp_tag).to_bytes(4,'big') + resp_tag
                 + len(enc_response).to_bytes(4,'big') + enc_response)
    conn.close()
