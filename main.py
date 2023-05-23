import passwordmanager as pm
from cryptography.fernet import Fernet

if __name__ == "__main__":
    manager = pm.PasswordManger()
    manager.initialise_db()
    manager.add_credentials()
    manager.get_credentials()