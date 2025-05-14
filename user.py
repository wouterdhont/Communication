import socket, os, json, cv2, time, base64, face_recognition, pyotp # type: ignore
import numpy as np
from Crypto.PublicKey import RSA # type: ignore
from Crypto.Cipher import PKCS1_OAEP, AES # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
from logic_admin import view_logs
from datetime import datetime, timedelta
from two_factor import *
import hmac, hashlib
from config import HMAC_KEY 
from Crypto.Cipher import AES # type: ignore
from Crypto.Util.Padding import pad, unpad # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
setup_logging()
os.system('cls' if os.name == 'nt' else 'clear')



# just some general info
SERVER_HOST = 'localhost'
SERVER_PORT = 4545
COUNTER_FILE = "storage/counter.json"
user_id = None
IMAGE_DIR_PATH = "faces"

def register():
    # clear screen, print some information and get user info
    os.system('cls' if os.name == 'nt' else 'clear')
    print('***********************************************')
    print('************** REGISTRATION PAGE **************')
    print('***********************************************\n')
    name = input("What's your name? ").strip()
    age = input("How old are you? ").strip()
    while not age.isdigit():
        age = input("Enter an integer as your age: ").strip()
    age = int(age)
    user_id = input("What is your user id? ").strip()
    while not user_id.isdigit():
        user_id = input("Enter an integer as your user_id: ").strip()
    user_id = int(user_id)

    # get totp for the new user
    totp = pyotp.TOTP(pyotp.random_base32())
    secret = totp.secret
    uri = totp.provisioning_uri("Driver", issuer_name="SecureApp")
    new_totp = new_user_totp()

    new_user = {
        "name": name,
        "age": age,
        "user_id": user_id,
        "nr": count,
        "type": "register",
        "totp_secret": new_totp
    }

    result = send_to_server(new_user)
    print(result.get("message"))
    
    # ask if face id is wanted
    while True:
        action = input('\nDo you want to add Face ID Authentication? ').strip().lower()
        if action == "yes" or action == "no":
            break
        else:
            print("Invalid choice, please type 'yes' or 'no'. Try again.")
    
    # add face id authentication
    if action == "yes":
        for i in range(5, 0, -1):
            print(f"Taking picture in {i} seconds...")
            time.sleep(1)

        faces_drivers_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "faces"))
        os.makedirs(faces_drivers_path, exist_ok=True)
        camera = cv2.VideoCapture(0)
        ret, frame = camera.read()
        if ret:
            face_img_path = os.path.join(faces_drivers_path, f"{user_id}.jpg")
            cv2.imwrite(face_img_path, frame)
            print("Face ID authentication added successfully!\n")
        else:
            print("Face ID authentication could not be added.")
        
        camera.release()

    print("\n \nRegistration done succesfully, you will shortly be redirected.")
    time.sleep(3)
    return user_id


def login():
    # clear screen, print some information and get user info
    os.system('cls' if os.name == 'nt' else 'clear')
    print('**********************************************')
    print('***************** LOGIN PAGE *****************')
    print('**********************************************\n')

    while True:
        choice = int(input("Do you want to login with face-id (1) or 2-factor authentication (2)? ").strip())
        if choice == 1 or choice == 2:
            break
        else:
            print("Invalid choice, please type '1' or '2'. Try again.")

    if choice == 1:
        print("\nLet's start the Face ID Authentication.")
        user_id = authenticate_face_id()
    elif choice == 2:
        print("\nLet's start the 2-Factor Authentication.")
        print("2-Factor Authentication System")
        otp = input("Enter the 6-digit OTP: ")
        new_user = {
            "nr": count,
            "type": "login",
            "otp": otp
        }
        user_id = send_to_server(new_user).get("user_id")

    print("\nLogged in successfully, you will shortly be redirected.")
    time.sleep(3)

    return user_id


def un_lock(car_id, command, user_id):
    timestamp = datetime.now().isoformat()

    new_user = {
        "user_id": user_id,
        "car_id": car_id,
        "nr": count,
        "type": command,
        "timestamp": timestamp
    }

    result = send_to_server(new_user)
    print(result.get("message"))


def un_share_car(user_id, target_id, car_id, command):
    request = {
        "user_id": user_id,
        "target_id": target_id,
        "car_id": car_id,
        "nr": count,
        "type": command
    }

    result = send_to_server(request)
    print(result.get("message"))


def authenticate_face_id():
    print("Face ID Authentication System")

    known_encodings = []
    known_ids = []

    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    IMAGE_DIR_PATH = os.path.join(SCRIPT_DIR, "faces")
    print(f"Loading images from: {IMAGE_DIR_PATH}")
    # Load and encode all known faces
    for filename in os.listdir(IMAGE_DIR_PATH):
        if filename.endswith(".jpg") or filename.endswith(".jpeg") or filename.endswith(".png"):
            driver_id = os.path.splitext(filename)[0]
            image_path = os.path.join(IMAGE_DIR_PATH, filename)

            print(f"Processing file: {filename}")
            image = face_recognition.load_image_file(image_path)
            encodings = face_recognition.face_encodings(image)

            if encodings:
                print(f"Face encoding found for {filename}")
                known_encodings.append(encodings[0])
                known_ids.append(driver_id)
            else:
                print(f"No face found in {filename}")

    print(f"Loaded {len(known_encodings)} known face encodings.")
    
    # Start webcam
    video_capture = cv2.VideoCapture(0)

    while True:
        ret, frame = video_capture.read()
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        face_locations = face_recognition.face_locations(rgb_frame)
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

        for face_encoding in face_encodings:
            matches = face_recognition.compare_faces(known_encodings, face_encoding)
            face_distances = face_recognition.face_distance(known_encodings, face_encoding)

            if len(face_distances) == 0:
                print("Face distances are empty; skipping frame.")
                continue
            
            best_match_index = np.argmin(face_distances)

            if matches[best_match_index]:
                matched_id = known_ids[best_match_index]
                print(f"Match Found! Driver ID: {matched_id}")
                video_capture.release()
                cv2.destroyAllWindows()
                return matched_id
            else:
                print("Face not recognized.")

        cv2.imshow("Face ID", frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    video_capture.release()
    cv2.destroyAllWindows()
    return None


def send_to_server(data: dict):
    try:
        aes_key = get_random_bytes(16)

        # Step 1: Encrypt user's public key with AES
        with open(f"secrets/device{count}_public.pem", "rb") as f:
            pub_key_data = f.read()
        aes_cipher = AES.new(aes_key, AES.MODE_CBC)
        enc_user_pub = aes_cipher.encrypt(pad(pub_key_data, AES.block_size))

        # Step 2: Encrypt AES key with server's initial public key
        server_pub_key = RSA.import_key(open("secrets/server_public.pem", "rb").read())
        server_cipher_init = PKCS1_OAEP.new(server_pub_key)
        enc_aes_key = server_cipher_init.encrypt(aes_key)

        # Step 3: Connect to server and send key exchange payload
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((SERVER_HOST, SERVER_PORT))

            sock.sendall(len(enc_aes_key).to_bytes(4, 'big') + enc_aes_key)
            sock.sendall(len(enc_user_pub).to_bytes(4, 'big') + enc_user_pub + aes_cipher.iv)

            # Step 4: Receive and decrypt server's new public key
            server_key_len = int.from_bytes(sock.recv(4), 'big')
            enc_server_pub = sock.recv(server_key_len)
            iv = sock.recv(16)
            aes_cipher_dec = AES.new(aes_key, AES.MODE_CBC, iv)
            server_pub_json = unpad(aes_cipher_dec.decrypt(enc_server_pub), AES.block_size)
            server_key = RSA.import_key(server_pub_json)
            server_cipher = PKCS1_OAEP.new(server_key)

            # Step 5: Encrypt and send request
            enc_request = server_cipher.encrypt(json.dumps(data).encode())
            tag = hmac.new(HMAC_KEY, enc_request, hashlib.sha256).digest()

            sock.sendall(len(tag).to_bytes(4, 'big') + tag
                         + len(enc_request).to_bytes(4, 'big') + enc_request)

            # Step 6: Receive and verify response
            n_tag = int.from_bytes(sock.recv(4), 'big')
            resp_tag = sock.recv(n_tag)
            n_data = int.from_bytes(sock.recv(4), 'big')
            enc_response = sock.recv(n_data)

            if not hmac.compare_digest(resp_tag, hmac.new(HMAC_KEY, enc_response, hashlib.sha256).digest()):
                raise ValueError("Response HMAC check failed")

            response = user_cipher.decrypt(enc_response).decode()
            return json.loads(response)

    except Exception as e:
        print("Error communicating with server:", e)
        return None


# This is just some startup code
os.system('cls' if os.name == 'nt' else 'clear')
print('***********************************************')
print('**** Welcome to your digital car unlocker! ****')
print('***********************************************')

# Check if the file exists, if not, initialize it
if os.path.exists(COUNTER_FILE):
    with open(COUNTER_FILE, "r") as f:
        data = json.load(f)
        count = data.get("count", 0) + 1
else:
    count = 1

# Save the updated count
with open(COUNTER_FILE, "w") as f:
    json.dump({"count": count}, f)

# Generate/load user's RSA keys
user_priv_file = f"secrets/device{count}_private.pem"
if not os.path.exists(user_priv_file):
    key = RSA.generate(2048)
    with open(user_priv_file, "wb") as f:
        f.write(key.export_key())
    with open(f"secrets/device{count}_public.pem", "wb") as f:
        f.write(key.publickey().export_key())

user_private = RSA.import_key(open(user_priv_file, "rb").read())
user_cipher = PKCS1_OAEP.new(user_private)

# Load server's public key
#server_pub_key = RSA.import_key(open("secrets/server_public.pem", "rb").read())
#server_cipher = PKCS1_OAEP.new(server_pub_key)

while True:
    action = input('\nDo you want to register a new account or login? \n').strip().lower()
    
    if action == "register" or action == "login" or action == "lock":
        break
    else:
        print("Invalid choice, please type 'register' or 'login'. Try again.")

if action == "register":
    user_id = register()
elif action == "login":
    user_id = login()

# we know that you can get here without properly loggin in or registering but then your user_id will be None
# and thus all your requests will be invalid

os.system('cls' if os.name == 'nt' else 'clear')
print('***********************************************')
print('**************** (UN)LOCK PAGE ****************')
print('***********************************************')
print(f"Your id: {user_id} \n")
print("What action do you want to perform?")
print("(1) Unlock a car")
print("(2) Lock a car")
print("(3) Share access of a car")
print("(4) Remove access of a car")
print("(0) Exit the application")

while True:
    while True:
        command = int(input("\nMake your choice: "))
        if command >= 0 and command <= 4:
            break

    if command == 1:
        car_id = int(input(f"Wich car do you want to unlock? "))
        un_lock(car_id, "unlock", user_id)
    elif command == 2:
        car_id = int(input(f"Wich car do you want to lock? "))
        un_lock(car_id, "lock", user_id)
    elif command == 3:
        car_id = int(input(f"Wich car do you want to share? "))
        target_id = int(input(f"With who do you want to share? "))
        un_share_car(user_id, target_id, car_id, "share access")
    elif command == 4:
        car_id = int(input(f"Wich car do you want to delete access from? "))
        target_id = int(input(f"Whose access do you want to delete? "))
        un_share_car(user_id, target_id, car_id, "delete access")
    else:
        print("Exiting the application. Goodbye!")
        break