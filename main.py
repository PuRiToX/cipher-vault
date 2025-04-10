import bcrypt
import json
import os
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Configuration files
CONFIG_FILE = 'config.json'
VAULT_FILE = 'vault.json'

# Main Function
def main():
    clean_terminal() 

    if not os.path.exists(CONFIG_FILE):
        create_master_password()
    else:
        login_result = login()
        if login_result:
            vault_data, key = login_result
            show_menu(vault_data, key)

def clean_terminal():
    # For Windows
    if os.name == 'nt':
        os.system('cls')
    # For Unix/Linux/MacOS
    else:
        os.system('clear')

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
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)
    
    # Create empty vault
    key = generate_fernet_key(password, salt)
    save_vault([], key)
    
    print("\n✅ Setup complete! Your vault is ready.")

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
    
    key = generate_fernet_key(password, salt)
    
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

# Show menu
def show_menu(vault_data, key):
    while True:

        print("\n📁 Main Menu 📁")
        print("1. ➕ Add new password")
        print("2. 📋 See all services")
        print("3. 🔍 Search for password")
        print("4. 🔄 Change master password")
        print("5. ⚠️ Vault reset")
        print("6. 🚪 Go out")
        
        choice = input("\nChoose an option: ")
        clean_terminal()
        wait = ''
        
        if choice == '1':
            add_password(vault_data, key)
            wait = input("\nPress Enter to continue...")
            clean_terminal()
        elif choice == '2':
            list_services(vault_data)
            wait = input("\nPress Enter to continue...")
            clean_terminal()
        elif choice == '3':
            find_password(vault_data)
            wait = input("\nPress Enter to continue...")
            clean_terminal()
        elif choice == '4':
            new_key = change_password(vault_data, key)
            if new_key:
                key = new_key  # Actualizamos la clave en memoria
            wait = input("\nPress Enter to continue...")
            clean_terminal()    
        elif choice == '5':
            if factory_reset():
                print("\n✅ Vault deleted! Please restart the app.")
                return  # Salimos sin guardar
            wait = input("\nPress Enter to continue...")
            clean_terminal() 
        elif choice == '6':
            save_vault(vault_data, key)
            print("\n✅ Your vault is safe! See you soon.")
            break
        else:
            print("\n❌ Invalid option. Please try again.")

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
    save_vault(vault_data, new_key)
    
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
    
    save_vault(vault_data, key)
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

if __name__ == "__main__":
    main()