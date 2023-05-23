import sqlite3
import getpass
from base64 import b64encode
from hashlib import sha256
import sys
import os
from crypto import encrypt_master_key, generate_encryption_key, encrypt_password, decrypt_password, generate_encryption_key
from bcrypt import checkpw

class PasswordManger:
    def __init__(self):
        self.master_key = ""
        self.master_key_file = "master_key.txt"
        self.encryption_key_file = "encryption_key.txt"
        self.logged_in_status = False
        self.encryption_key = None

    # Lässt den User einen Master-Key beim ersten Starten der Applikation festlegen und speichert diesen anschließend in einer separaten Datei
    def set_masterkey(self):
        self.master_key = getpass.getpass("* Legen Sie bitte einen Master-Key fest: ")
        confirm_masterkey = getpass.getpass("* Bitte wiederholen Sie den Master-Key: ")
        if confirm_masterkey != self.master_key:
            print("Die eingegebenen Master-Keys stimmen nicht überein! \nBitte wiederholen Sie den Vorgang.")
            self.set_masterkey()
        # encryption of the master key
        self.master_key = encrypt_master_key(self.master_key)
        
        # Speicherung des Master-Keys in einer separaten Datei:
        with open (self.master_key_file, 'w') as file:
            file.write(self.master_key)

    # Zugriff bei Bedarf auf den Master-Key -> Datei in der sich der Master-Key befindet wird ausegelesen und der Inhalt in self.master_key geladen
    def get_masterkey(self):
        # Wenn eine Datei "master_key.txt" existiert, wird diese im read-mode geöffnet und ausgelesen
        if os.path.isfile(self.master_key_file):
            with open(self.master_key_file, 'r') as file:
                self.master_key = file.read().strip()
        else:
            return None
        
    # Holt sich den encryption key bei der Ver- und Entschlüsselung von Passwörtern
    def get_encryption_key(self):
        if os.path.isfile(self.encryption_key_file):
            with open(self.encryption_key_file, "r") as file:
                self.encryption_key = file.read().strip()
        return self.encryption_key
        
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
            if checkpw(user_input, self.master_key.encode("utf-8")):
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
        self.encryption_key = self.get_encryption_key().encode("utf-8")
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
        # Wenn keine master_key Datei existiert, wird set_masterkey ausgeführt
        if not os.path.isfile(self.master_key_file):
            self.set_masterkey()
            # key zum Ver- und Entschlüsseln der Passwörter wird initialisiert
            generate_encryption_key(self.encryption_key_file)

        # Wenn ja, dann muss sich der User einloggen
        else:
            self.user_login()

        # Verbindung zur Datenbank herstellen
        conn = sqlite3.connect('passwordmanager.db')
        cur = conn.cursor()

        # Der key wird mit dem Master-Key verschlüsselt und in der Datei "encryption_key.txt" gespeichert
        # self.encryption_key = encrypt_encryption_key(self.master_key, self.encryption_key, self.encryption_key_file)

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
            self.encryption_key = self.get_encryption_key()
            password = decrypt_password(result[1], self.encryption_key)
            print(f"[+] Benutzername: {result[0]}, Passwort: {password}")

        # Wenn kein Eintrag gefunden werden konnte, wird dem Nutzer ein entsprechender Hinweis ausgegeben
        else:
            print("[-] Es existiert kein Account auf der von Ihnen angegebenen Plattform.")