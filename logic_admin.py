import json
import os
from cryptography.fernet import Fernet # type: ignore
from loggers import log_message, init_logging, setup_logging
setup_logging()


# -------------------------- Encryption Setup ------------------------------
key_path = os.path.dirname(os.path.abspath(__file__)) + "/secrets/encryption.key"

with open(key_path, "rb") as f:
    _fernet = Fernet(f.read())

def encrypt(value: str) -> str:
    return _fernet.encrypt(str(value).encode()).decode()

def decrypt(value: str) -> str:
    return _fernet.decrypt(value.encode()).decode()

# -------------------------- Storage Paths --------------------------------

users_storage_path = os.path.dirname(os.path.abspath(__file__)) + "/storage/users.json"
permissions_per_role_path = os.path.dirname(os.path.abspath(__file__)) + "/storage/permission_per_role.json"

# -------------------------- Actions ---------------------------------------

def view_logs(admin_id: int, key: str, day: str = None):
    _key, _fernet_local = init_logging()

    print("VIEW_LOGS: admin id --", admin_id)
    if not is_role_allowed(admin_id, "view_logs"):
        print("Access denied: role is not allowed to view logs")
        return False

    logs_dir = os.path.join(os.path.dirname(__file__), "logs")
    if not os.path.exists(logs_dir):
        print("No logs directory found.")
        return

    if day is None:
        log_files = [f for f in os.listdir(logs_dir) if f.endswith(".log")]
    else:
        log_files = [f for f in os.listdir(logs_dir) if f.endswith(f"{day}.log")]

    if key == _key.decode():
        print("Key is correct, access granted")
        for log_file in log_files:
            with open(os.path.join(logs_dir, log_file), "r") as f:
                for line in f:
                    try:
                        parts = line.strip().split(" - ", 2)
                        if len(parts) < 3:
                            print("Skipping malformed line:", line)
                            continue
                        timestamp, level, encrypted_message = parts
                        decrypted_message = _fernet_local.decrypt(encrypted_message.encode()).decode()
                        print(f"{timestamp} - {level} - {decrypted_message}")
                    except Exception as e:
                        print(f"Error decrypting log message: {e}")
    else:
        print("Key is incorrect, access denied")
        return False



def create_user(admin_id: int, new_user_data: dict):
    if not is_role_allowed(admin_id, "create_user"):
        log_message(f"Admin {admin_id} denied creating user {new_user_data['user_id']}: insufficient role", "ERROR")
        return False
    #try:
    with open(users_storage_path, "r") as f:
        drivers = json.load(f)

    if any(d["user_id"] == new_user_data["user_id"] for d in drivers):
        log_message(f"Admin {admin_id} attempted to create user {new_user_data['user_id']}, but user already exists", "ERROR")
        return False

    # Encrypt sensitive fields
    new_user_data["totp_secret"] = encrypt(new_user_data["totp_secret"])
    new_user_data["role"] = encrypt(new_user_data.get("role", "user"))
    if "name" in new_user_data:
        new_user_data["name"] = encrypt(new_user_data["name"])

    drivers.append(new_user_data)

    with open(users_storage_path, "w") as f:
        json.dump(drivers, f, indent=4)

    log_message(f"Admin {admin_id} created user {new_user_data['user_id']}", "INFO")
    return True

    # except Exception as e:
    #     #log_message(f"Error creating user {new_user_data['user_id']} by admin {admin_id}: {e}", "ERROR")
    #     return False


def delete_user(admin_id: int, target_user_id: int):
    if not is_role_allowed(admin_id, "delete_user"):
        log_message(f"Admin {admin_id} denied deleting user {target_user_id}: insufficient role", "ERROR")
        return False

    try:
        with open(users_storage_path, "r") as f:
            drivers = json.load(f)

        new_drivers = [d for d in drivers if d["user_id"] != target_user_id]

        if len(new_drivers) == len(drivers):
            log_message(f"Admin {admin_id} attempted to delete user {target_user_id}, but user not found", "ERROR")
            return False

        with open(users_storage_path, "w") as f:
            json.dump(new_drivers, f, indent=4)

        log_message(f"Admin {admin_id} deleted user {target_user_id}", "INFO")
        return True

    except Exception as e:
        log_message(f"Error deleting user {target_user_id} by admin {admin_id}: {e}", "ERROR")
        return False


def assign_role(admin_id: int, target_user_id: int, new_role: str):
    if not is_role_allowed(admin_id, "assign_roles"):
        log_message(f"Admin {admin_id} denied assigning role '{new_role}' to user {target_user_id}: insufficient role", "ERROR")
        print("1")
        return False

    try:
        with open(users_storage_path, "r") as f:
            drivers = json.load(f)

        for driver in drivers:
            if driver["user_id"] == target_user_id:
                driver["role"] = encrypt(new_role)
                break
        else:
            log_message(f"Admin {admin_id} attempted to assign role '{new_role}' to user {target_user_id}, but user not found", "ERROR")
            return False

        with open(users_storage_path, "w") as f:
            json.dump(drivers, f, indent=4)

        log_message(f"Admin {admin_id} assigned role '{new_role}' to user {target_user_id}", "INFO")
        return True

    except Exception as e:
        log_message(f"Error assigning role '{new_role}' to user {target_user_id} by admin {admin_id}: {e}", "ERROR")
        return False


def view_all_users(admin_id: int):
    if not is_role_allowed(admin_id, "view_logs"):
        log_message(f"Admin {admin_id} denied viewing all users: insufficient role", "ERROR")
        return False

    try:
        with open(users_storage_path, "r") as f:
            drivers = json.load(f)

        log_message(f"Admin {admin_id} viewed all registered users", "INFO")
        print("Registered Users:")
        for driver in drivers:
            try:
                name = decrypt(driver["name"]) if "name" in driver else "Unknown"
                role = decrypt(driver["role"]) if "role" in driver else "user"
            except Exception:
                name = driver.get("name", "Corrupt")
                role = driver.get("role", "Corrupt")

            print(f"ID: {driver['user_id']}, Name: {name}, Role: {role}")
        return True

    except Exception as e:
        log_message(f"Error viewing all users by admin {admin_id}: {e}", "ERROR")
        return False

# -------------------------- Role Permission Check -------------------------

def is_role_allowed(user_id: int, action: str) -> bool:
    try:
        with open(users_storage_path, "r") as f:
            users = json.load(f)

        user = next((u for u in users if u["user_id"] == user_id), None)
        if not user:
            log_message(f"Permission check failed: user {user_id} not found", "ERROR")
            print("user not found")
            return False

        encrypted_role = user.get("role", "")
        try:
            role = decrypt(encrypted_role)
        except Exception:
            role = encrypted_role  # fallback to plaintext or malformed

        with open("storage/permission_per_role.json", "r") as f:
            permissions = json.load(f)

        if action in permissions.get(role, []):
            return True
        else:
            log_message(
                f"Permission denied: user {user_id} with role '{role}' attempted unauthorized action '{action}'",
                "ERROR"
            )
            return False

    except Exception as e:
        log_message(f"Error checking role permissions for user {user_id}: {e}", "ERROR")
        return False


