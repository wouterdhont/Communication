import json
import sys
import os
from loggers import log_message # type: ignore
from cryptography.fernet import Fernet # type: ignore

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
cars_storage_path = os.path.dirname(os.path.abspath(__file__)) + "/storage/cars.json"
permission_per_role_path = os.path.dirname(os.path.abspath(__file__)) + "/storage/permission_per_role.json"

# -------------------------- Actions ---------------------------------------

def unlock_car(user_id: int, car_id: int):
    if not is_role_allowed(user_id, "unlock_car"):
        log_message(f"User {user_id} denied unlocking car {car_id}: insufficient role", "ERROR")
        return False
    

    if not is_able_to_access_car(user_id, car_id):
        log_message(f"User {user_id} denied unlocking car {car_id}: failed access checks", "ERROR")
        return False

    try:
        with open(cars_storage_path, "r") as f:
            cars = json.load(f)

        for car in cars:
            if car["id"] == car_id:
                if not decrypt(car.get("locked", encrypt("True"))) == "True":
                    log_message(f"User {user_id} attempted to unlock car {car_id}, but it was already unlocked", "INFO")
                    return True
                car["locked"] = encrypt("False")
                log_message(f"User {user_id} unlocked car {car_id}", "INFO")
                break
        else:
            log_message(f"User {user_id} attempted to unlock car {car_id}, but it was not found", "ERROR")
            return False

        with open(cars_storage_path, "w") as f:
            json.dump(cars, f, indent=4)

        return True

    except Exception as e:
        log_message(f"Error unlocking car {car_id} by user {user_id}: {e}", "ERROR")
        return False


def lock_car(user_id: int, car_id: int):
    if not is_role_allowed(user_id, "lock_car"):
        log_message(f"User {user_id} denied locking car {car_id}: insufficient role", "ERROR")
        return False
    

    if not is_able_to_access_car(user_id, car_id):
        log_message(f"User {user_id} denied locking car {car_id}: failed access checks", "ERROR")
        return False
    

    try:
        with open(cars_storage_path, "r") as f:
            cars = json.load(f)

        for car in cars:
            if car["id"] == car_id:
                if decrypt(car.get("locked", encrypt("True"))) == "True":
                    log_message(f"User {user_id} attempted to lock car {car_id}, but it was already locked", "INFO")
                    return True
                car["locked"] = encrypt("True")
                log_message(f"User {user_id} locked car {car_id}", "INFO")
                break
        else:
            log_message(f"User {user_id} attempted to lock car {car_id}, but it was not found", "ERROR")
            return False

        with open(cars_storage_path, "w") as f:
            json.dump(cars, f, indent=4)

        return True

    except Exception as e:
        log_message(f"Error locking car {car_id} by user {user_id}: {e}", "ERROR")
        return False


def share_access(owner_id: int, target_user_id: int, car_id: int):
    if not is_role_allowed(owner_id, "share_access"):
        log_message(f"User {owner_id} denied sharing car {car_id} with user {target_user_id}: insufficient role", "ERROR")
        return False

    try:
        with open(users_storage_path, "r") as f:
            users = json.load(f)

        owner = next((u for u in users if u["id"] == owner_id), None)
        target_user = next((u for u in users if u["id"] == target_user_id), None)

        if not owner or not target_user:
            log_message(f"Share access failed: invalid user {owner_id} or target user {target_user_id}", "ERROR")
            return False

        if not (owner.get("is_owner") and owner["is_owner"].get("car_id") == car_id):
            log_message(f"User {owner_id} denied sharing car {car_id}: not the car owner", "ERROR")
            return False

        if "has_access_to" not in target_user:
            target_user["has_access_to"] = []

        if any(entry["car_id"] == car_id for entry in target_user["has_access_to"]):
            log_message(f"User {owner_id} attempted to share car {car_id} with user {target_user_id}, but access already exists", "INFO")
            return True

        target_user["has_access_to"].append({"car_id": car_id})

        with open(users_storage_path, "w") as f:
            json.dump(users, f, indent=4)

        log_message(f"User {owner_id} shared access to car {car_id} with user {target_user_id}", "INFO")
        return True

    except Exception as e:
        log_message(f"Error sharing access from user {owner_id} to user {target_user_id} for car {car_id}: {e}", "ERROR")
        return False

# -------------------------- Role Permission Check -------------------------

def is_role_allowed(user_id: int, action: str) -> bool:
    try:
        with open(users_storage_path, "r") as f:
            users = json.load(f)


        user = next((u for u in users if u["user_id"] == user_id), None)
        if not user:
            log_message(f"Role check failed: user {user_id} not found", "ERROR")
            return False
        

        try:
            role = decrypt(user.get("role", ""))
        except Exception:
            role = user.get("role", "user")


        with open(permission_per_role_path, "r") as f:
            permissions = json.load(f)

        allowed_actions = permissions.get(role, [])

        if action in allowed_actions:
            return True
        else:
            log_message(f"Role '{role}' (user {user_id}) not allowed to perform action '{action}'", "ERROR")
            return False

    except Exception as e:
        log_message(f"Error checking role permissions for user {user_id}: {e}", "ERROR")
        return False

# -------------------------- Helper Functions ------------------------------

def is_able_to_access_car(user_id: int, car_id: int) -> bool:
    try:
        with open(users_storage_path, "r") as f:
            registered_users = json.load(f)

        user = next((u for u in registered_users if u["user_id"] == user_id), None)

        if not check_if_authenticated(user):
            log_message(f"User {user_id} not authenticated", "ERROR")
            return False

        if not check_if_allowed_to_drive(user):
            log_message(f"User {user_id} not allowed to drive", "ERROR")
            return False

        if not check_if_access_to_car(user, car_id):
            log_message(f"User {user_id} has no access to car {car_id}", "ERROR")
            return False

        return True

    except Exception as e:
        log_message(f"Authorization error for user {user_id} on car {car_id}: {e}", "ERROR")
        return False

def check_if_authenticated(user: dict) -> bool:
    return user is not None

def check_if_allowed_to_drive(user: dict) -> bool:
    return user.get("has_drivers_license") and user.get("able_to_drive")

def check_if_access_to_car(user: dict, car_id: int) -> bool:
    if user.get("is_owner") and user["is_owner"].get("car_id") == car_id:
        return True

    if "has_access_to" in user:
        return any(entry["car_id"] == car_id for entry in user["has_access_to"])

    return False