import json
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

# -------------------------- Paths -----------------------------------------

cars_storage_path = os.path.dirname(os.path.abspath(__file__)) + "/storage/cars.json"
users_storage_path = os.path.dirname(os.path.abspath(__file__)) + "/storage/users.json"
permissions_per_role_storage_path = os.path.dirname(os.path.abspath(__file__)) + "/permission_per_role.json"

# -------------------------- Car Distributor Actions -----------------------

def register_car(distributor_id: int, car_data: dict):
    
    
    if not is_role_allowed(distributor_id, "register_car"):
        log_message(f"Distributor {distributor_id} denied car registration: insufficient role", "ERROR")
        return False

    
    
    
    try:
        with open(cars_storage_path, "r") as f:
            cars = json.load(f)

        

        if any(car["id"] == car_data["id"] for car in cars):
            log_message(f"Distributor {distributor_id} attempted to register car {car_data['id']}, but it already exists", "ERROR")
            return False
    
    

    # car_data.setdefault("license_plate", "")
    # car_data.setdefault("owner_id", None)
    # car_data.setdefault("locked", True)

        # Encrypt sensitive fields
        car_data["license_plate"] = encrypt(car_data["license_plate"])
        car_data["owner_id"] = encrypt(car_data["owner_id"])
        car_data["locked"] = encrypt(str(car_data["locked"]))

        cars.append(car_data)

        with open(cars_storage_path, "w") as f:
            json.dump(cars, f, indent=4)

        log_message(f"Distributor {distributor_id} registered car {car_data['id']}", "INFO")
        return True

    except Exception as e:
        log_message(f"Error registering car {car_data['id']} by distributor {distributor_id}: {e}", "ERROR")
        return False


def assign_ownership(distributor_id: int, user_id: int, car_id: int):
    
    
    if not is_role_allowed(distributor_id, "assign_ownership"):
        log_message(f"Distributor {distributor_id} denied assigning car {car_id} to user {user_id}: insufficient role", "ERROR")
        return False
    
    

    #try:
    with open(users_storage_path, "r") as f:
        drivers = json.load(f)

    with open(cars_storage_path, "r") as f:
        cars = json.load(f)

    

    driver = next((d for d in drivers if d["user_id"] == user_id), None)
    car = next((c for c in cars if c["id"] == car_id), None)
    print("hallo")

    if not driver or not car:
        log_message(f"Distributor {distributor_id} attempted to assign ownership of car {car_id}, but driver or car not found", "ERROR")
        return False
    print("dag")
    for d in drivers:
        if d.get("is_owner") and d["is_owner"].get("car_id") == car_id:
            d.pop("is_owner", None)

    print("jow")

    driver["is_owner"] = {"car_id": car_id}
    car["owner_id"] = encrypt(user_id)

    with open(users_storage_path, "w") as f:
        json.dump(drivers, f, indent=4)

    with open(cars_storage_path, "w") as f:
        json.dump(cars, f, indent=4)

    log_message(f"Distributor {distributor_id} assigned ownership of car {car_id} to user {user_id}", "INFO")
    return True

    # except Exception as e:
    #     log_message(f"Error assigning ownership of car {car_id} to user {user_id} by distributor {distributor_id}: {e}", "ERROR")
    #     return False


def view_car_inventory(distributor_id: int):
    if not is_role_allowed(distributor_id, "view_car_inventory"):
        log_message(f"Distributor {distributor_id} denied viewing car inventory: insufficient role", "ERROR")
        return False
    
    try:
        with open(cars_storage_path, "r") as f:
            cars = json.load(f)

        log_message(f"Distributor {distributor_id} viewed car inventory", "INFO")
        print("Registered Cars:")
        for car in cars:
            print(f"ID: {car['id']}, Make: {car['make']}, Model: {car['model']}, Year: {car['year']}, "
                    f"License_plate: {decrypt(car['license_plate'])}, "
                    f"Owner: {decrypt(car['owner_id'])}, "
                    f"Locked: {decrypt(car['locked'])}")
        return True

    except Exception as e:
        log_message(f"Error viewing car inventory by distributor {distributor_id}: {e}", "ERROR")
        return False


def set_license_plate(distributor_id: int, car_id: int, plate: str):
    if not is_role_allowed(distributor_id, "register_car"):
        log_message(f"Distributor {distributor_id} denied setting license plate for car {car_id}: insufficient role", "ERROR")
        return False

    try:
        with open(cars_storage_path, "r") as f:
            cars = json.load(f)

        for car in cars:
            if car["id"] == car_id:
                car["license_plate"] = encrypt(plate)
                break
        else:
            log_message(f"Distributor {distributor_id} attempted to set license plate for car {car_id}, but car not found", "ERROR")
            return False

        with open(cars_storage_path, "w") as f:
            json.dump(cars, f, indent=4)

        log_message(f"Distributor {distributor_id} set license plate '{plate}' for car {car_id}", "INFO")
        return True

    except Exception as e:
        log_message(f"Error setting license plate for car {car_id} by distributor {distributor_id}: {e}", "ERROR")
        return False


# -------------------------- Role Check Utility ----------------------------

def is_role_allowed(user_id: int, action: str) -> bool:
    try:
        with open(users_storage_path, "r") as f:
            users = json.load(f)

        user = next((u for u in users if u["user_id"] == user_id), None)
        if not user:
            log_message(f"Permission check failed: user {user_id} not found", "ERROR")
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

