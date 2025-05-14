import json
import os
from loggers import log_message, setup_logging
from cryptography.fernet import Fernet # type: ignore
setup_logging()


# -------------------------- Encryption Setup ------------------------------

with open("secrets/encryption.key", "rb") as f:
    _fernet = Fernet(f.read())

def encrypt(value: str) -> str:
    return _fernet.encrypt(str(value).encode()).decode()

def decrypt(value: str) -> str:
    return _fernet.decrypt(value.encode()).decode()

# -------------------------- Storage Paths ---------------------------------

users_storage_path = os.path.dirname(os.path.abspath(__file__)) + "/storage/users.json"
permissions_per_role_path = os.path.dirname(os.path.abspath(__file__)) + "/storage/permission_per_role.json"

# -------------------------- Actions ---------------------------------------

def revoke_license(authority_id: int, target_user_id: int):
    if not is_role_allowed(authority_id, "revoke_license"):
        log_message(f"Authority {authority_id} denied revoking license of user {target_user_id}: insufficient role", "ERROR")
        return False

    return _update_license_status(target_user_id, False, authority_id)


def reinstate_license(authority_id: int, target_user_id: int):
    if not is_role_allowed(authority_id, "reinstate_license"):
        log_message(f"Authority {authority_id} denied reinstating license of user {target_user_id}: insufficient role", "ERROR")
        return False

    return _update_license_status(target_user_id, True, authority_id)


def view_license_status(authority_id: int, target_user_id: int):
    if not is_role_allowed(authority_id, "view_license_status"):
        log_message(f"Authority {authority_id} denied viewing license of user {target_user_id}: insufficient role", "ERROR")
        return False

    try:
        with open(users_storage_path, "r") as f:
            drivers = json.load(f)

        target = next((d for d in drivers if d["user_id"] == target_user_id), None)

        if not target:
            log_message(f"Authority {authority_id} tried to view license of user {target_user_id}, but user not found", "ERROR")
            return False

        has_license = target.get('has_drivers_license')
        can_drive = target.get('able_to_drive')
        log_message(f"Authority {authority_id} viewed license status of user {target_user_id}: has_license={has_license}, able_to_drive={can_drive}", "INFO")
        print(f"Driver {target_user_id} - has_license: {has_license}, able_to_drive: {can_drive}")
        return True

    except Exception as e:
        log_message(f"Error viewing license status of user {target_user_id} by authority {authority_id}: {e}", "ERROR")
        return False

# -------------------------- Internal Helpers ------------------------------

def _update_license_status(user_id: int, status: bool, authority_id: int) -> bool:
    try:
        with open(users_storage_path, "r") as f:
            drivers = json.load(f)

        updated = False

        for driver in drivers:
            if driver["user_id"] == user_id:
                driver["has_drivers_license"] = status
                driver["able_to_drive"] = status
                updated = True
                break

        if not updated:
            log_message(f"Authority {authority_id} tried to update license for user {user_id}, but user not found", "ERROR")
            return False

        with open(users_storage_path, "w") as f:
            json.dump(drivers, f, indent=4)

        action = "Reinstated" if status else "Revoked"
        log_message(f"Authority {authority_id} {action.lower()} license for user {user_id}", "INFO")
        print(f"{action} license for driver {user_id}")
        return True

    except Exception as e:
        log_message(f"Error updating license status for user {user_id} by authority {authority_id}: {e}", "ERROR")
        return False

# -------------------------- Role Check Utility ----------------------------

def is_role_allowed(user_id: int, action: str) -> bool:
    #try:
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

    # except Exception as e:
    #     log_message(f"Error checking role permissions for user {user_id}: {e}", "ERROR")
    #     return False

