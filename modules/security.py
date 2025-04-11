#All the handling encryption and authentication module

import bcrypt
import json
import os
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

import vault

# Configuration files
CONFIG_FILE = 'data/config.json'
VAULT_FILE = 'data/vault.json'

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


# Change master password
def change_password(vault_data, current_key):
    print("\n🔄 Change Master Password 🔄")
            
    try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
    except FileNotFoundError:
            print("❌ Error: Configuration not found")
            return None
            
    # Check current password
    current = getpass("Current password: ")
    if not bcrypt.checkpw(current.encode(), config['hash'].encode()):
        print("\n❌ Incorrect password")
        return None
        
    # Get New Password
    while True:
        new_pass = getpass("New password: ")
        confirm = getpass("Confirm new password: ")
        if new_pass == confirm:
            break
        print("\n❌ Passwords do not match")
    
    # Generate new values
    new_salt = os.urandom(16)
    new_hash = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt())
    new_key = generate_fernet_key(new_pass, new_salt)
        
    # Update configuration
    config['hash'] = new_hash.decode()
    config['salt'] = base64.b64encode(new_salt).decode()
        
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)
        
    # Re-encrypt the entire vault with the new key
    vault.save_vault(vault_data, new_key)
        
    print("\n✅ Password updated successfully!")
    return new_key  # Returns the new key for future operations

def strong_pass(password):
    issues = []
    
    if not password:
        print("\nThe password cannot be empty")
        return False

    # Minimum lenght
    if len(password) < 8:
        issues.append("Must have at least 8 characters")
    
    # Uppercase and lowercase
    if not any(c.isupper() for c in password):
        issues.append("Must contain at least one capital letter")
    if not any(c.islower() for c in password):
        issues.append("Must contain at least one lowercase letter")
    
    # Numbers and special characters
    if not any(c.isdigit() for c in password):
        issues.append("Must include at least one number")
    if not any(not c.isalnum() for c in password):
        issues.append("Must include at least one special character (ej. !@#)")
    
    # Show results
    if not issues:
        return True
    else:
        print("🔴 The password has problems encountered:")
        for issue in issues:
            print(f"- {issue}")
        return False
