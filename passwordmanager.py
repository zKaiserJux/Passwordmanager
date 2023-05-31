import sqlite3
import getpass
from base64 import b64encode
from hashlib import sha256
import sys
import os
from crypto import hash_master_key, generate_encryption_key, encrypt_password, decrypt_password, generate_encryption_key, generate_encryption_key, decrypt_encryption_key, encrypt_encryption_key
from bcrypt import checkpw
from tabulate import tabulate

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
    def get_decrypted_encryption_key(self):
        # Wenn die Datei mit dem verschlüsselten Key existiert, wird diese geöffnet und der Schlüssel extrahiert
        if os.path.isfile(self.encryption_key_file):
            with open(self.encryption_key_file, "rb") as file:
                self.encryption_key = file.read()

        # Holt sich den abgeleiteten Schlüssel, um den verschlüsselten encryption key zu entschlüsseln
        self.derived_key = self.get_derived_key()
        self.decrypted_encryption_key = decrypt_encryption_key(self.derived_key, self.encryption_key)
        return self.decrypted_encryption_key
        
    # Wird aufgerufen, wenn ein Master-Key bereits existiert und sich der User mit diesem anmleden muss
    def user_login(self):
        tries =  0
        max_attempts = 3

        # Solange die maximalen Versuche noch nicht überschritten sind, wird dem User die Möglichkeit gegeben den Master-Key nocheinmal einzugeben
        while tries < max_attempts:
            # Holt sich den gehasten Master-Key aus der Datei self.master_key.txt zur Überprüfung mit dem vom Nutzer eingegebenen Passwort
            self.get_masterkey()
            user_input = getpass.getpass("Bitte geben Sie den Master-Key ein, um sich einzuloggen: ")
            user_input = user_input.encode("utf-8")
            user_input = b64encode(sha256(user_input).digest())
            if checkpw(user_input, self.master_key):
                # Lade die für die Sitzung benötigten Variablen in den Arbeitsspeicher
                self.derived_key = self.get_derived_key()
                self.decrypted_encryption_key = self.get_decrypted_encryption_key()

                # Ändere den Login-Status auf True
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

    # Initialisierung der Datenbank, die später die Credentials aller Online-Accounts speichert
    def initialise_db(self):
        # Master-Key wird erstellt
        self.set_masterkey()
        self.logged_in_status = True

        # Der key wird mit dem Master-Key verschlüsselt und in der Datei "encryption_key.txt" gespeichert
        self.derived_key, self.encryption_key = generate_encryption_key(self.master_key, self.encryption_key_file)
        self.decrypted_encryption_key = self.get_decrypted_encryption_key()

        # Verbindung zur Datenbank herstellen
        conn = sqlite3.connect('passwordmanager.db')
        cur = conn.cursor()
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
            password = decrypt_password(result[1], self.decrypted_encryption_key)
            print(f"[+] Benutzername: {result[0]}, Passwort: {password}")

        # Wenn kein Eintrag gefunden werden konnte, wird dem Nutzer ein entsprechender Hinweis ausgegeben
        else:
            print("[-] Es existiert kein Account auf der von Ihnen angegebenen Plattform.")

    # Gibt True zurück, falls ein Account mit der gegebenen URL existiert
    def search(self):
        url = input("* Bitte geben Sie die URL ein nach der Sie suchen: ")

        # Verbindung mit der Datenbank aufbauen
        conn = sqlite3.connect("passwordmanager.db")
        cur = conn.cursor()

        # Geht die Einträge der Datenbank durch und vergleicht die URL mit der eingegebenen
        cur.execute("SELECT url FROM passwords WHERE url = ? ", (url,))
        entries = cur.fetchone()
        for entry in entries:
            if entry == url:
                print("[+] Mit der eingegebenen URL existiert ein Account")
                return True
        conn.close()

        # Wenn kein Eintrag gefunden wurde dessen URL mit der eingegebenen übereinstimmt, dann wird False zurückgegeben
        print("[-] Mit der eingegebenen URL existiert kein Account in der Datenbank")


    # Zeigt dem Nutzer die komplette Datenbank
    def show_all(self):
        # Stellt die Verbindung zur Datenbank her
        conn = sqlite3.connect("passwordmanager.db")
        cur = conn.cursor()

        # Datenbank wird Zeile für Zeile durchlaufen und als Tupel von Tupeln in entries gespeichert
        cur.execute("SELECT * FROM passwords")
        entries = cur.fetchall()

        # Liste in der die Einträge mit den enschlüsselten Passwörter gespeichert werden, da sich die Einträge in einem Tupel nicht ändern lassen
        decrypted_entries = []

        # Das Passwort jedes Eintrages muss vor dem printen noch mit dem encryption key entschlüsselt werden
        for entry in entries:
            decrypted_password = decrypt_password(entry[3], self.decrypted_encryption_key)
            decrypted_entry = (entry[1], entry[2], decrypted_password)
            decrypted_entries.append(decrypted_entry)

        # Ausgabe der gesamten Werte
        table = tabulate(decrypted_entries, headers=["website", "username/email", "password"], tablefmt="simple_grid")
        print(table)

        # Verbindung mit der Datenbank wird getrennt
        conn.close()

    # Fragt den Nutzer nach einem neuen Account und erhält die Login-Daten mit samt der URL
    def add_credentials(self):
        url = input("* Name / URL: ")
        email_username = input("* email/username: ")
        password = getpass.getpass("* Password: ")

        # Holen des entschlüsselten encryption keys mit dem die Passwörter verschlüsselt werden
        password = encrypt_password(password, self.decrypted_encryption_key)

        # Verbinden mit der Datenbank, um die eingebenen credentials in die Datenbank aufzunehmen
        conn = sqlite3.connect("passwordmanager.db")
        cur = conn.cursor()

        # Credentials werden in die Tabelle eingefügt
        cur.execute("INSERT INTO passwords (url, email_username, password) VALUES (?, ?, ?)", (url, email_username, password))
        conn.commit()

        # Verbindung mit der Datenbank wird beendet
        conn.close()

    # Verschlüsselt den Verschlüsselungsschlüssel
    def lock(self):
        # Verschlüsselt den Verschlüsselungsschlüssel mit dem abgeleiteten Schlüssel
        encrypt_encryption_key(self.derived_key, self.decrypted_encryption_key)
        self.logged_in_status = False