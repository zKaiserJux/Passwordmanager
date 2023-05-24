import sqlite3
import getpass
from base64 import b64encode
from hashlib import sha256
import sys
import os
from crypto import hash_master_key, generate_encryption_key, encrypt_password, decrypt_password, generate_encryption_key, generate_encryption_key, decrypt_encryption_key
from bcrypt import checkpw

class PasswordManger:
    def __init__(self):
        self.master_key = ""
        self.master_key_file = "master_key.txt"
        self.encryption_key_file = "encryption_key.txt"
        self.logged_in_status = False
        self.encryption_key = None
        self.derived_key = None
        self.decrypted_encryption_key = None

    # Lässt den User einen Master-Key beim ersten Starten der Applikation festlegen und speichert diesen anschließend in einer separaten Datei
    def set_masterkey(self):
        self.master_key = getpass.getpass("* Legen Sie bitte einen Master-Key fest: ")
        confirm_masterkey = getpass.getpass("* Bitte wiederholen Sie den Master-Key: ")
        if confirm_masterkey != self.master_key:
            print("Die eingegebenen Master-Keys stimmen nicht überein! \nBitte wiederholen Sie den Vorgang.")
            self.set_masterkey()
        # Master-Key wird gehashed und in der Datei self.master_key_file gespeichert
        self.master_key = hash_master_key(self.master_key, self.master_key_file)

    # Gibt den gehashten Master-Key aus der Datei self.master_key_file zurück
    def get_masterkey(self):
        if os.path.isfile(self.master_key_file):
            with open(self.master_key_file, "rb") as file:
                self.master_key = file.read()
                return self.master_key
        else:
            return None

    # Zugriff bei Bedarf auf den Master-Key -> Datei in der sich der Master-Key befindet wird ausegelesen und der Inhalt in self.master_key geladen
    def get_derived_key(self):
        # Wenn eine Datei "master_key.txt" existiert, wird diese im read-mode geöffnet und ausgelesen
        if os.path.isfile("derived_key.txt"):
            with open("derived_key.txt", 'rb') as file:
                self.derived_key = file.read()
                return self.derived_key
        else:
            return None
        
    # Gibt den entschlüsselten encryption zurück
    def get_decrypted_encryption_key(self, encrypted_key):
        self.decrypted_encryption_key = decrypt_encryption_key("derived_key.txt", encrypted_key)
        return self.decrypted_encryption_key
        
    # Wird aufgerufen, wenn ein Master-Key bereits existiert und sich der User mit diesem anmleden muss
    def user_login(self):
        tries =  0
        max_attempts = 3

        # Solange die maximalen Versuche noch nicht überschritten sind, wird dem User die Möglichkeit gegeben den Master-Key nocheinmal einzugeben
        while tries < max_attempts:
            self.get_masterkey()
            user_input = getpass.getpass("Bitte geben Sie den Master-Key ein, um sich einzuloggen: ")
            user_input = user_input.encode("utf-8")
            user_input = b64encode(sha256(user_input).digest())
            if checkpw(user_input, self.master_key):
                self.logged_in_status = True
                print("[+] Login successfull.")
                break
            else:
                tries += 1
                remaining_attempts = max_attempts - tries
                print(f"[-] Master-Key inkorrekt! Sie haben noch {remaining_attempts} Versuch/e übrig.")

        # Wenn sich der login Status nicht auf True gesetzt wurde, bedeutet das, dass der User zu viele Versuche gebraucht hat        
        if not self.logged_in_status:
            print("[-] Sie haben zu viele Verusche benötigt. Zugang verweigert!")
            sys.exit()
            
    # Fragt den Nutzer nach einem neuen Account und erhält die Login-Daten mit samt der URL
    def add_credentials(self):
        url = input("* Name / URL: ")
        email_username = input("* email/username: ")
        password = getpass.getpass("* Password: ")

        # Holen des entschlüsselten encryption keys mit dem die Passwörter verschlüsselt werden
        # self.decrypted_encryption_key = self.get_decrypted_encryption_key()
        password = encrypt_password(password, self.decrypted_encryption_key)

        # Verbinden mit der Datenbank, um die eingebenen credentials in die Datenbank aufzunehmen
        conn = sqlite3.connect("passwordmanager.db")
        cur = conn.cursor()

        # Credentials werden in die Tabelle eingefügt
        cur.execute("INSERT INTO passwords (url, email_username, password) VALUES (?, ?, ?)", (url, email_username, password))
        conn.commit()

        # Verbindung mit der Datenbank wird beendet
        conn.close()

    # Initialisierung der Datenbank, die später die Credentials aller Online-Accounts speichert
    def initialise_db(self):
        # Wenn keine master_key Datei existiert, wird set_masterkey ausgeführt
        if not os.path.isfile(self.master_key_file):
            self.set_masterkey()
            # key zum Ver- und Entschlüsseln der Passwörter wird generiert
            # generate_encryption_key(self.master_key, self.encryption_key_file)

        # Wenn ja, dann muss sich der User einloggen
        else:
            self.user_login()

        # Verbindung zur Datenbank herstellen
        conn = sqlite3.connect('passwordmanager.db')
        cur = conn.cursor()

        # Der key wird mit dem Master-Key verschlüsselt und in der Datei "encryption_key.txt" gespeichert
        self.derived_key, self.encryption_key = generate_encryption_key(self.master_key, self.encryption_key_file)
        self.decrypted_encryption_key = self.get_decrypted_encryption_key(self.encryption_key)

        # SQL-Befehl zum Erstellen der Datentabelle
        create_table_query = '''
        CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        email_username TEXT,
        password TEXT
        )
        '''
        # Datenbank ersellen und Daten in die Tabelle einfügen
        cur.execute(create_table_query)
        
        # Verbindung zur Datenbank schließen
        conn.close()

    # Zeigt dem Nutzer bei Eingabe des chars "g" das Password für einen jeweiligen Account
    def get_credentials(self):
        # Nutzer wird nach der spezifischen Website geafragt auf dem er den Account angelegt hat
        account = input("* Geben Sie die Seite ein auf dem Sie den Account erstellt haben: ")

        # Verbindung mit der Datenbank wird aufgebaut
        conn = sqlite3.connect("passwordmanager.db")
        cur = conn.cursor()

        # Datenbank wird nach der Website durchsucht
        cur.execute("SELECT email_username, password FROM passwords WHERE url = ? ", (account,))
        result = cur.fetchone()

        # Falls eine Zeile mit Daten gefunden wurde, werden die credentials für den Account ausgegeben
        if result is not None:
            # self.encryption_key = decrypt_encryption_key(self.master_key.encode("utf-8"), self.encryption_key_file)
            password = decrypt_password(result[1], self.decrypted_encryption_key)
            print(f"[+] Benutzername: {result[0]}, Passwort: {password}")

        # Wenn kein Eintrag gefunden werden konnte, wird dem Nutzer ein entsprechender Hinweis ausgegeben
        else:
            print("[-] Es existiert kein Account auf der von Ihnen angegebenen Plattform.")