import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Configuration files
CONFIG_FILE = 'data/config.json'
VAULT_FILE = 'data/vault.json'

class Process: 

    # Create Fernet Key
    def generate_fernet_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key)

    # Save changes to the vault
    def save_vault(vault_data, key):
        fernet = Fernet(key)
        json_data = json.dumps(vault_data).encode('utf-8')
        encrypted_data = fernet.encrypt(json_data)
        encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        with open(VAULT_FILE, 'w') as f:
            json.dump({"data": encrypted_b64}, f)

