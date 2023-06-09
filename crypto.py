from cryptography.fernet import Fernet
import bcrypt
import base64
import hashlib

# hashes the master key and saves it in a file
def hash_master_key(master_key : str, master_key_file : str):
    master_key = master_key.encode("utf-8")
    master_key = base64.b64encode(hashlib.sha256(master_key).digest())
    hashed = bcrypt.hashpw(master_key, bcrypt.gensalt())

    # creates a file and saves the hashed master key bytes
    with open(master_key_file, "wb") as file:
        file.write(hashed)
    
    return hashed

# generates the encryption key, encrypts it with a derived key and saves it in a file
def generate_encryption_key(hashed_master_key : bytes, key_file : str):
    # generates the encryption key to en- and decrypt the passwords later on
    key = Fernet.generate_key()

    # generates the derived key form the hashed master key
    derived_key = bcrypt.kdf(hashed_master_key, salt=bcrypt.gensalt(), desired_key_bytes=32, rounds=12)
    cipher_suite = Fernet(base64.urlsafe_b64encode(derived_key))

    # the encryption key is encrypted with the derived key
    encrypted_encryption_key = cipher_suite.encrypt(key)

    # save the derived key in an extra file called derived_key.txt"
    with open('derived_key.txt', "wb") as file:
        file.write(derived_key)

    # save the enrypted encryption key in an extra file
    with open(key_file, "wb") as file:
        file.write(encrypted_encryption_key)

    return derived_key, encrypted_encryption_key

# decrypts the encryption key and returns it
def decrypt_encryption_key(derived_key : bytes, encrypted_key : bytes):
        # use the derived key to decrypt the encrypted encryption key
        cipher_suite = Fernet(base64.urlsafe_b64encode(derived_key))
        decrypted_encryption_key = cipher_suite.decrypt(encrypted_key)
        return decrypted_encryption_key
    
# encrypts the encryption key if the passwordmanager gets locked
def encrypt_encryption_key(derived_key : bytes, decrypted_key : bytes):
    cipher_suite = Fernet(base64.urlsafe_b64encode(derived_key))
    encrypted_key = cipher_suite.encrypt(decrypted_key)
    return encrypted_key

# encrypts a passwort with the decrypted encryption key
def encrypt_password(password : str, decrypted_encryption_key : bytes):
    cipher_suite = Fernet(decrypted_encryption_key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# decrypts a passwort with the decrypted encryption key
def decrypt_password(encrypted_password : bytes, decrypted_encryption_key : bytes):
    cipher_suite = Fernet(decrypted_encryption_key)
    decrypted_password = cipher_suite.decrypt(encrypted_password)
    return decrypted_password.decode()