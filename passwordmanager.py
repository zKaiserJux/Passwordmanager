import sqlite3
import getpass
import sys
from crypto import encrypt_master_key, generate_encryption_key, encrypt_password

class PasswordManger:
    def __init__(self):
        self.master_key = ""
        self.logged_in_status = False
        self.encryption_key = None

    # Lässt den User einen Master-Key beim ersten Starten der Applikation festlegen und speichert diesen anschließend in der Datenbank
    def set_masterkey(self):
        self.master_key = getpass.getpass("* Legen Sie bitte einen Master-Key fest: ")
        confirm_masterkey = getpass.getpass("* Bitte wiederholen Sie den Master-Key: ")
        if confirm_masterkey != self.master_key:
            print("Die eingegebenen Master-Keys stimmen nicht überein! \n Bitte wiederholen Sie den Vorgang.")
            self.set_masterkey()
        # encryption of the master key
        self.master_key = encrypt_master_key(self.master_key)

    # Fragt den Nutzer nach einem neuen Account und erhält die Login-Daten mit samt der URL
    def add_credentials(self):
        url = input("* Name / URL: ")
        email_username = input("* email/username: ")
        password = getpass.getpass("* Password: ")
        password = encrypt_password(password, self.encryption_key)

        conn = sqlite3.connect("passwordmanager.db")
        cur = conn.cursor()

         # SQL-Befehl zum Einfügen eines neuen Eintrages in die Tabelle
        insert_query = '''
        INSERT INTO passwords (url, email_username, password)
        VALUES (?, ?, ?)
        '''
        # Eintrag in die Tabelle einfügen
        cur.execute(insert_query, (url, email_username, password))
        conn.commit()

        conn.close()


    # Datenbank, die die Website als URL speichert, den Usernamen/E-Mail für einen Account und das dazugehörige Passwort
    def initialise_db(self):
        # Verbindung zur Datenbank herstellen
        conn = sqlite3.connect('passwordmanager.db')
        cur = conn.cursor()

        # key zum Ver- und Entschlüsseln der Passwörter wird initialisiert und in einer Datei namens encrypted_key.txt gespeichert
        # Der key wird mit dem Master-Key verschlüsselt
        self.encryption_key = generate_encryption_key()

        # SQL-Befehl zum Erstellen der Datentabelle
        create_table_query = '''
        CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        email_username TEXT,
        password TEXT,
        master_key TEXT
        )
        '''
        # Datenbank ersellen und Daten in die Tabelle einfügen
        cur.execute(create_table_query)
        check_master_key_query = '''
        SELECT master_key FROM passwords LIMIT 1
        '''
        result = cur.execute(check_master_key_query)
        stored_master_key = result.fetchone()

        # Wenn kein Master-Key in der Datenbank gespeichert ist, wird ein Master-Key erstellt und anschließend gehashed
        if not stored_master_key:
            self.set_masterkey()
            
            # SQL-Befehl zum Speichern des Master-Keys in der Datenbank
            insert_master_key = '''
            INSERT INTO passwords (master_key) VALUES (?)
            '''
            # Speicherung des gehashten Master-Keys in der Datenbank
            cur.execute(insert_master_key, (self.master_key,))
            conn.commit()
            print("Der Master-Key wurde erfolgreich in der Datenbank gespeichert")

        # if a master key already exists the user has to login
        else:
            tries = 0
            max_attempts = 3
            while tries < max_attempts:
                user_masterkey = getpass.getpass("Please enter your master-key to login: ")
                if user_masterkey == stored_master_key[0]:
                    self.logged_in_status = True
                    print("Login successfull.")
                    break
                
                else:
                    tries += 1
                    remaining_attempts = 3 - tries
                    print(f"The master key is incorrect! You only have {remaining_attempts} attempt/s left.")
            if not self.logged_in_status:
                print("Too many tries. Access will be denied!")
                sys.exit(0)

        # Verbindung zur Datenbank schließen
        conn.close()