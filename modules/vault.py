#Vault Operations Module

import json
import base64
import bcrypt
import os
from cryptography.fernet import Fernet
from getpass import getpass

# Configuration files
CONFIG_FILE = 'data/config.json'
VAULT_FILE = 'data/vault.json'

# Save changes to the vault
def save_vault(vault_data, key):
    fernet = Fernet(key)
    json_data = json.dumps(vault_data).encode('utf-8')
    encrypted_data = fernet.encrypt(json_data)
    encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
    with open(VAULT_FILE, 'w') as f:
        json.dump({"data": encrypted_b64}, f)

# List the services
def list_services(vault_data):
    print("\n🗂️ Stored Services 🗂️")
    if not vault_data:
        print("❌ There are no passwords stored")
        return
        
    for entry in vault_data:
        print(f"Service: {entry['service']} - User: {entry['username']}")

# List passwords
def find_password(vault_data):
    print("\n🔍 Search password 🔍")
    service = input("Enter the name of the service: ")

    results = [entry for entry in vault_data if entry['service'].lower() == service.lower()]
        
    if not results:
        print("\n❌ No results found")
        return
        
    for entry in results:
        print(f"\nService: {entry['service']}")
        print(f"User: {entry['username']}")
        print(f"Password: {entry['password']}")

# Reset settings
def factory_reset():
    print("\n⚠️ Vault Reset ⚠️")
        
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        print("❌ There is no configuration to delete")
        return False
        
# Authentication
    password = getpass("Master password to confirm: ")
    if not bcrypt.checkpw(password.encode(), config['hash'].encode()):
        print("\n❌ Authentication failed")
        return False
        
# Delete files
    try:
        os.remove(CONFIG_FILE)
        os.remove(VAULT_FILE)
        print("\nAll data has been deleted!")
        return True
    except Exception as e:
        print(f"\n❌ Error deleting: {str(e)}")
        return False


# Add new password
def add_password(vault_data, key):
    print("\n📝 Add new password 📝")
    service = input("Service name: ")
    username = input("Username: ")
    password = getpass("Password: ")

    vault_data.append({
        "service": service,
        "username": username,
        "password": password
    })

    save_vault(vault_data, key)
    print(f"\n✅ Password for {service} saved successfully!")
