import logging, os
from datetime import datetime
from cryptography.fernet import Fernet # type: ignore

global _key, _fernet


def setup_logging():
    os.makedirs("/logs", exist_ok=True)

    log_filename = datetime.now().strftime("/logs/%Y-%m-%d.log")

    logging.basicConfig(
        filename=log_filename,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    
    print("Logging setup complete.")
    return log_filename

def init_logging():
    base_dir = os.path.dirname(__file__)
    key_path = os.path.dirname(os.path.abspath(__file__)) + "/secrets/encryption.key"

    with open(key_path, "rb") as f:
        _key = f.read()
        _fernet = Fernet(_key)
    return  _key, _fernet

def log_message(message: str, level: str = "INFO"):
    _key, _fernet = init_logging()

    encrypted_message = _fernet.encrypt(message.encode()).decode()

    if level == "INFO":
        logging.info(encrypted_message)
    elif level == "ERROR":
        logging.error(encrypted_message)
    elif level == "DEBUG":
        logging.debug(encrypted_message)
    else:
        logging.warning(f"Unknown log level: {level}. Message: {encrypted_message}")
