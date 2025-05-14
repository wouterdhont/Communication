#server.py

import socket, os, json, base64, cv2, base64 # type: ignore
import numpy as np
import hmac, hashlib
from Crypto.PublicKey import RSA # type: ignore
from Crypto.Cipher import PKCS1_OAEP # type: ignore
from logic_admin import create_user
from logic_user import *
from loggers import setup_logging, log_message
from datetime import datetime, timedelta
from config import HMAC_KEY
from two_factor import *
os.system('cls' if os.name == 'nt' else 'clear')

# boiler plate code
# ----------------------------------------------------------------------------------------------------
HOST = 'localhost'
CLIENT_PORT = 4545   # port to listen for users
CARS_INFO = {        # mapping of car IDs to (host, port, public_key_file)
    '1': ('localhost', 6001, 'secrets/car1_public.pem'),
    '2': ('localhost', 6002, 'secrets/car2_public.pem')
}

# Generate or load server RSA keys
if not os.path.exists("secrets/server_private.pem"):
    key = RSA.generate(2048)
    with open("secrets/server_private.pem", "wb") as f:
        f.write(key.export_key())
    with open("secrets/server_public.pem", "wb") as f:
        f.write(key.publickey().export_key())
    print("[Server] RSA key pair generated.")
server_private = RSA.import_key(open("secrets/server_private.pem","rb").read())
server_cipher = PKCS1_OAEP.new(server_private)

print(f"[Server] Listening for users on {HOST}:{CLIENT_PORT}...")
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create TCP socket
server_sock.bind((HOST, CLIENT_PORT))
server_sock.listen()  # start listening
# ----------------------------------------------------------------------------------------------------

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise EOFError("Socket closed prematurely")
        data.extend(packet)
    return bytes(data)

def send_with_hmac(sock, ciphertext: bytes):
    tag = hmac.new(HMAC_KEY, ciphertext, hashlib.sha256).digest()            # HMAC over ciphertext :contentReference[oaicite:6]{index=6}
    sock.sendall(len(tag).to_bytes(4,'big') + tag
                 + len(ciphertext).to_bytes(4,'big') + ciphertext)

def recv_with_hmac(sock):
    tlen = int.from_bytes(recvall(sock,4),'big')
    tag  = recvall(sock,tlen)
    clen = int.from_bytes(recvall(sock,4),'big')
    ctxt = recvall(sock,clen)
    expected = hmac.new(HMAC_KEY, ctxt, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("HMAC verification failed")                         # prevents tampering :contentReference[oaicite:7]{index=7}
    return ctxt



#actual receive, process and send
while True:
    # receive from user
    client_conn, addr = server_sock.accept()  # accept user connection
    print(f"\n[Server] Connection from {addr}")
        # 1) Read tag + ciphertext
    n_tag = int.from_bytes(client_conn.recv(4),'big')
    tag   = client_conn.recv(n_tag)
    n_ct  = int.from_bytes(client_conn.recv(4),'big')
    enc_request = client_conn.recv(n_ct)
    # 2) Verify HMAC before decrypting :contentReference[oaicite:5]{index=5}
    if not hmac.compare_digest(tag, hmac.new(HMAC_KEY, enc_request, hashlib.sha256).digest()):
        print("[Server] HMAC verification failed; dropping") 
        client_conn.close()
        continue
    try:
        # Decrypt request with server private key
        request_json = server_cipher.decrypt(enc_request).decode()
        request = json.loads(request_json)
    except Exception as e:
        print("[Server] Decryption failed or invalid message.")
        client_conn.close()
        continue

    # ------------------------------------------------------------------------------------------
    
    type = request.get("type")

    if type == "register":
        new_user_data = {
            "name": request.get("name"),
            "age": request.get("age"),
            "user_id": request.get("user_id"),
            "role": "user",
            "has_drivers_license": True,
            "able_to_drive": True,
            "totp_secret": request.get("totp_secret")
        }
        
        # call create_user() from Authorisation/admin_logic
        succes = create_user(admin_id=9000, new_user_data=new_user_data)
                
        result = {"status": succes, "message": "Registration succeeded"}

    elif type == "login":
        result = {"user_id": authenticate_two_factor(request.get("otp"))}

    elif type == "share access":
        print(f'[Server] Received request from user {request.get("user_id")} to share car {request.get("car_id")} with user {request.get("target_id")}')
        succes = share_access(request.get("user_id"), request.get("target_id"), request.get("car_id"))
        if succes:
            print(f'[Server] Authorized request from user {request.get("user_id")} to share car {request.get("car_id")} with user {request.get("target_id")}')
        else:
            print(f'[Server] Denied request from user {request.get("user_id")} to share car {request.get("car_id")} with user {request.get("target_id")}')
        result = {"status": succes, "message": "Car shared"}

    elif type == "delete access":
        print(f'[Server] Received request from user {request.get("user_id")} to remove acces to car {request.get("car_id")} of user {request.get("target_id")}')
        succes = remove_access(request.get("user_id"), request.get("target_id"), request.get("car_id"))
        if succes:
            print(f'[Server] Authorized request from user {request.get("user_id")} to remove acces to car {request.get("car_id")} of user {request.get("target_id")}')
        else:
            print(f'[Server] Denied request from user {request.get("user_id")} to remove acces to car {request.get("car_id")} of user {request.get("target_id")}')
        result = {"status": succes, "message": "Car access removed"}

    elif type == "lock" or type == "unlock":
        timestamp_str = request.get("timestamp")
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str)  # Convert string back to datetime
                current_time = datetime.now()
                time_diff = abs(current_time - timestamp)
                if time_diff <= timedelta(seconds=30):
                    print(f"[Server] Timestamp check OK, proceeding")
                else:
                    print("[Server] Timestamp check not OK")
            except ValueError:
                print("Invalid timestamp format")
        else:
            print("[Server] Timestamp missing or null")
        
        if type == "lock":
           succes = lock_car(request.get("user_id"), request.get("car_id"))
        else:
           succes = unlock_car(request.get("user_id"), request.get("car_id"))
        
        if succes:
            # send command to car
            print(f'[Server] User {request.get("user_id")} authorized to {type} car {request.get("car_id")}, sending command to car')

            try:
                # Encrypt request
                car_host, car_port, car_pub_file = CARS_INFO[f"{request.get('car_id')}"]
                car_pub_key = RSA.import_key(open(car_pub_file, "rb").read())              # recipient’s public key :contentReference[oaicite:1]{index=1}
                car_cipher  = PKCS1_OAEP.new(car_pub_key)                                 # create OAEP cipher for car :contentReference[oaicite:2]{index=2}
                enc_request = car_cipher.encrypt(json.dumps({"command": type}).encode())
                tag = hmac.new(HMAC_KEY, enc_request, hashlib.sha256).digest()

                # Send to server
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((car_host, car_port))
                    # Send: 4‑byte tag length, tag, 4‑byte payload length, payload
                    sock.sendall(len(tag).to_bytes(4,'big') + tag
                                + len(enc_request).to_bytes(4,'big') + enc_request)

                    # Receive and decrypt response
                    # First read response tag
                    n_tag = int.from_bytes(recvall(sock, 4),'big')
                    resp_tag = recvall(sock, n_tag)
                    # Then read ciphertext
                    n_data = int.from_bytes(recvall(sock, 4),'big')
                    enc_response = recvall(sock, n_data)
                    # Verify integrity before decrypting
                    if not hmac.compare_digest(resp_tag,
                            hmac.new(HMAC_KEY, enc_response, hashlib.sha256).digest()):
                        raise ValueError("Response HMAC check failed")
                    response = json.loads(server_cipher.decrypt(enc_response).decode())
            

            except Exception as e:
                print("[Client] Error communicating with server:", e)
                response = {"message": "fail"}

            print(f"[Server] Car {request.get('car_id')} successfully {type}ed sending confirmation to user {request.get('user_id')}")

            try:
                if response.get("message") == "success":
                    result = {"message": f"Successfully {type}ed \n"}
                else:
                    result = {"message": "Command could not be resolved"}
            except Exception as e:
                result = {"message": "Invalid response from car"}
        else:
            result = {"message": "You're not able to open this car\n"}

    



    # ------------------------------------------------------------------------------------------

    # Send result back to user, encrypted with user's public key
    nr = request.get("nr")
    user_pub_file = f"secrets/device{nr}_public.pem"
    if user_pub_file:
        user_pub_key = RSA.import_key(open(user_pub_file, "rb").read())
        user_cipher = PKCS1_OAEP.new(user_pub_key)
        enc_result = user_cipher.encrypt(json.dumps(result).encode())
        # Compute HMAC on the ciphertext before send
        resp_tag = hmac.new(HMAC_KEY, enc_result, hashlib.sha256).digest()
        client_conn.sendall(len(resp_tag).to_bytes(4,'big') + resp_tag
                            + len(enc_result).to_bytes(4,'big') + enc_result)
    else:
        print("[Server] Unknown user or missing public key.")
    client_conn.close()
