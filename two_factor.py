import pyotp # type: ignore
import json
import os
import qrcode # type: ignore
from cryptography.fernet import Fernet # type: ignore
from loggers import log_message, setup_logging # type: ignore


# -------------------------- Setup Logging ----------------------------------

setup_logging()


# -------------------------- Encryption Setup ------------------------------


key_path = os.path.join(os.path.dirname(__file__), "secrets", "encryption.key")
with open(key_path, "rb") as f:
    _fernet = Fernet(f.read())

def encrypt(value: str) -> str:
    return _fernet.encrypt(str(value).encode()).decode()

def decrypt(value: str) -> str:
    return _fernet.decrypt(value.encode()).decode()

# -------------------------- Paths -----------------------------------------

users_storage_path = os.path.dirname(os.path.abspath(__file__)) + "/storage/users.json"

# -------------------------- 2FA Functions ---------------------------------

def authenticate_two_factor(otp):
    

    # Load drivers
    with open(users_storage_path, "r") as f:
        drivers = json.load(f)

    for driver in drivers:
        secret_encrypted = driver.get("totp_secret")

        if not secret_encrypted:
            log_message(f"User {driver['user_id']} does not have a TOTP secret", "ERROR")
            continue

        try:
            secret = decrypt(secret_encrypted)
            totp = pyotp.TOTP(secret)
            if totp.verify(otp):
                name = driver.get("name", "Unknown")
                try:
                    name = decrypt(name)
                except: pass

                print(f"[Server] Authentication successful: {name} (ID: {driver['user_id']})")
                log_message(f"User {name} (ID: {driver['user_id']}) authenticated successfully", "INFO")
                return driver["user_id"]
        except: pass
            


    print(f"Error verifying OTP for user ID {driver['user_id']}")
    log_message(f"Error verifying OTP for user ID {driver['user_id']}", "ERROR")
    return None


def new_user_totp():
    totp = pyotp.TOTP(pyotp.random_base32())
    secret = totp.secret
    uri = totp.provisioning_uri("Driver", issuer_name="SecureApp")

    # Generate and show QR code
    img = qrcode.make(uri)
    img.show()

    log_message(f"New TOTP secret generated for user: {secret}", "INFO")
    return secret


def add_user(info):
    if "totp_secret" in info:
        info["totp_secret"] = encrypt(info["totp_secret"])
    if "role" in info:
        info["role"] = encrypt(info["role"])
    if "name" in info:
        info["name"] = encrypt(info["name"])

    with open(users_storage_path, "r") as f:
        users = json.load(f)

    users.append(info)

    with open(users_storage_path, "w") as f:
        json.dump(users, f, indent=4)

    print(f"User {info.get('user_id', 'Unknown')} added successfully")