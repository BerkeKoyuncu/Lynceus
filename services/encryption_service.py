import base64
import hashlib
import os
from cryptography.fernet import Fernet
from services.runtime_paths import ensure_runtime_directories, secret_dir

def get_fernet_key(secret_string: str) -> bytes:
    # Hash the secret string using SHA-256 to get exactly 32 bytes
    key_bytes = hashlib.sha256(secret_string.encode('utf-8')).digest()
    # Base64 urlsafe encode it as required by Fernet
    return base64.urlsafe_b64encode(key_bytes)

def get_or_create_local_secret(filename):
    """
    Retrieves a persisted secret key from a local file in the project root.
    If the file does not exist, generates a cryptographically secure random key
    and saves it.
    """
    ensure_runtime_directories()
    secret_file = secret_dir() / filename
    if secret_file.exists():
        try:
            with secret_file.open("r", encoding="utf-8") as f:
                saved_key = f.read().strip()
                if saved_key:
                    return saved_key
        except Exception:
            pass

    import secrets
    new_key = secrets.token_hex(32)
    try:
        with secret_file.open("w", encoding="utf-8") as f:
            f.write(new_key)
    except Exception:
        pass
    return new_key

def get_flask_secret_key():
    return os.environ.get("SECRET_KEY") or get_or_create_local_secret(".secret_key_flask")

def get_encryption_secret_key():
    return os.environ.get("OTP_ENCRYPTION_KEY") or get_or_create_local_secret(".secret_key")

def encrypt_val(val: str) -> str:
    if not val:
        return val
    secret = get_encryption_secret_key()
    fernet = Fernet(get_fernet_key(secret))
    return fernet.encrypt(val.encode('utf-8')).decode('utf-8')

def decrypt_val(val: str) -> str:
    if not val:
        return val
    # If the value is a Fernet token (typically starts with gAAAA), decrypt it.
    if val.startswith("gAAAA"):
        try:
            secret = get_encryption_secret_key()
            fernet = Fernet(get_fernet_key(secret))
            return fernet.decrypt(val.encode('utf-8')).decode('utf-8')
        except Exception:
            return val
    return val
