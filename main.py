import sys
from pathlib import Path
import bcrypt
import json
import os
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

modules_route = Path(__file__).parent / "modules"  # __file__ is the actual file rute (main.py)
sys.path.append(str(modules_route))

#Local Modules
from modules import security
from modules import cli
from modules import vault

# Configuration files
CONFIG_FILE = 'data/config.json'
VAULT_FILE = 'data/vault.json'

# Main Function
def main():
    cli.clean_terminal() 

    if not os.path.exists(CONFIG_FILE):
        create_master_password()
    else:
        login_result = login()
        if login_result:
            vault_data, key = login_result
            cli.show_menu(vault_data, key)

# Create master password
def create_master_password():
    print("\n🖥️🛠️ First Start: Create Master Password ⚙️🔧")
    print("\n⚠️ It is important not to forget the master password. ⚠️\nDo not share it with anyone or your data will be vulnerable.")
    print("\nFor more information about the program, visit the following repository: ")
    print("https://github.com/PuRiToX/strong-pass")
    while True:
        password = getpass("\nCreate your master password: ")
        confirm = getpass("Confirm your master password: ")
        if password == confirm:
            break
        print("❌ The passwords don't match! Please try again.")

    # Generate bcrypt hash
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    # Generate salt for key derivation
    salt = os.urandom(16)
    
    # Save configuration
    config = {
        "hash": hashed.decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8')
    }
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
    except FileNotFoundError:
        os.mkdir("data")
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)

    # Create empty vault
    key = security.generate_fernet_key(password, salt)
    vault.save_vault([], key)
    
    print("\n✅ Setup complete! Your vault is ready. \nPlease restart the app.")

# Authentication
def login():
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        print("❌ Error: Configuration file not found")
        return None

    stored_hash = config['hash'].encode('utf-8')
    salt = base64.b64decode(config['salt'].encode('utf-8'))
    
    print("🔒 Cipher Vault - Your Offline Password Fortress 🔒")
    print("\nFor more information about the program, visit the following repository: ")
    print("https://github.com/PuRiToX/strong-pass")

    password = getpass("\nEnter your master password: ")
    
    if not bcrypt.checkpw(password.encode(), stored_hash):
        print("\n❌ Incorrect password")
        return None
    
    key = security.generate_fernet_key(password, salt)
    
    try:
        with open(VAULT_FILE, 'r') as f:
            vault = json.load(f)
    except FileNotFoundError:
        print("❌ Error: Vault not found")
        return None
    
    encrypted_b64 = vault['data']
    encrypted_data = base64.b64decode(encrypted_b64)
    
    try:
        fernet = Fernet(key)
        json_data = fernet.decrypt(encrypted_data)
        vault_data = json.loads(json_data)
    except:
        print("\n❌ Error decrypting vault - possible data corruption")
        return None
    
    return (vault_data, key)

    cli.show_menu

if __name__ == "__main__":
    main()