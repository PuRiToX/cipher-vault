#Module for the console line interface (CLI)

from getpass import getpass
import os

import security
import vault

# Configuration files
CONFIG_FILE = 'data/config.json'
VAULT_FILE = 'data/vault.json'

#Clean Terminal
def clean_terminal():
    # For Windows
    if os.name == 'nt':
        os.system('cls')
    # For Unix/Linux/MacOS
    else:
        os.system('clear')

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
            vault.add_password(vault_data, key)
            wait = input("\nPress Enter to continue...")
            clean_terminal()
        elif choice == '2':
            vault.list_services(vault_data)
            wait = input("\nPress Enter to continue...")
            clean_terminal()
        elif choice == '3':
            vault.find_password(vault_data)
            wait = input("\nPress Enter to continue...")
            clean_terminal()
        elif choice == '4':
            new_key = security.change_password(vault_data, key)
            if new_key:
                key = new_key  # Actualizamos la clave en memoria
            wait = input("\nPress Enter to continue...")
            clean_terminal()    
        elif choice == '5':
            if vault.factory_reset():
                print("\n✅ Vault deleted! Please restart the app.")
                return  # Salimos sin guardar
            wait = input("\nPress Enter to continue...")
            clean_terminal() 
        elif choice == '6':
            vault.save_vault(vault_data, key)
            print("\n✅ Your vault is safe! See you soon.")
            break
        else:
            print("\n❌ Invalid option. Please try again.")