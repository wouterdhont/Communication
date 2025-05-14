import logging, os
from datetime import datetime
from cryptography.fernet import Fernet # type: ignore

def setup_logging():
    log_dir = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_filename = os.path.join(log_dir, datetime.now().strftime("%Y-%m-%d.log"))

    logging.basicConfig(
        filename=log_filename,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    print(f"Logging setup complete. Log file: {log_filename}")
    return log_filename

def init_logging():
    key_path = os.path.join(os.path.dirname(__file__), "secrets", "encryption.key")
    with open(key_path, "rb") as f:
        key = f.read()
        fernet = Fernet(key)
    return key, fernet

def log_message(message: str, level: str = "INFO"):
    _, fernet = init_logging()
    encrypted_message = fernet.encrypt(message.encode()).decode()

    if level == "INFO":
        logging.info(encrypted_message)
    elif level == "ERROR":
        logging.error(encrypted_message)
    elif level == "DEBUG":
        logging.debug(encrypted_message)
    else:
        logging.warning(f"Unknown log level: {level}. Message: {encrypted_message}")
