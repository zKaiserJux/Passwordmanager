from cryptography.fernet import Fernet
import bcrypt
import base64
import hashlib
import os

# encrypts the master key and returns it decoded
def encrypt_master_key(master_key : str):
    master_key = master_key.encode("utf-8")
    master_key = base64.b64encode(hashlib.sha256(master_key).digest())
    hashed = bcrypt.hashpw(master_key, bcrypt.gensalt())
    return hashed

# generates the encryption key and saves it in a file
def generate_encryption_key(key_file : str):
    key = Fernet.generate_key()
    with open(key_file, "wb") as file:
        file.write(key)

# encrypts the encryption key an saves it in a file
def encrypt_encryption_key(master_key : str, encryption_key : bytes, key_file : str):
    # use the master key to derive the key for the encryption key
    derived_key = bcrypt.kdf(master_key, salt=bcrypt.gensalt(), desired_key_bytes=32, rounds=100)
    cipher_suite = Fernet(base64.b64encode(derived_key))

    # encrypt the encryption key
    encrypted_encryption_key = cipher_suite.encrypt(encryption_key)

    # save the encrypted encryption key in a file
    with open(key_file, "wb") as file:
        file.write(encrypted_encryption_key)
    
    return derived_key
    
# decrypts the encryption key and returns it decoded
def decrypt_encryption_key(master_key : bytes, key_file : str):
    if os.path.isfile(key_file):
        # if file with the master_key exists read the file and extract the encrypted encryption key
        with open(key_file) as file:
            encrypted_key = file.read().strip().encode("utf-8")
        cipher_suite = Fernet(base64.urlsafe_b64encode(master_key))
        decrypted_encryption_key = cipher_suite.decrypt(encrypted_key)
        return decrypted_encryption_key

# encrypts a passwort with the encryption key
def encrypt_password(password : str, encryption_key : bytes):
    cipher_suite = Fernet(encryption_key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# decrypts a passwort with the encryption key
def decrypt_password(encrypted_password : bytes, encryption_key : bytes):
    cipher_suite = Fernet(encryption_key)
    decrypted_password = cipher_suite.decrypt(encrypted_password)
    return decrypted_password.decode()
