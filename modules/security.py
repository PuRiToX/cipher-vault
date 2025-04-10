import bcrypt
import json
import os
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from process import Process

# Configuration files
CONFIG_FILE = 'data/config.json'
VAULT_FILE = 'data/vault.json'

class Security:

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
        new_key = Process.generate_fernet_key(new_pass, new_salt)
        
        # Update configuration
        config['hash'] = new_hash.decode()
        config['salt'] = base64.b64encode(new_salt).decode()
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
        
        # Re-encrypt the entire vault with the new key
        Process.save_vault(vault_data, new_key)
        
        print("\n✅ Password updated successfully!")
        return new_key  # Returns the new key for future operations

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
        
        Process.save_vault(vault_data, key)
        print(f"\n✅ Password for {service} saved successfully!")

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