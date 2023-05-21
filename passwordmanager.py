import sqlite3
import getpass

class PasswordManger:
    def __init__(self):
        self.master_key = ""

    # Lässt den User einen Master-Key beim ersten Starten der Applikation festlegen und speichert diesen anschließend in der Datenbank
    def set_masterkey(self):
        self.master_key = getpass.getpass("* Legen Sie bitte einen Master-Key fest: ")
        confirm_masterkey = getpass.getpass("* Bitte wiederholen Sie den Master-Key: ")
        if confirm_masterkey != self.master_key:
            print("Die eingegebenen Master-Keys stimmen nicht überein! \n Bitte wiederholen Sie den Vorgang.")
            self.set_masterkey()

    # Fragt den Nutzer nach einem neuen Account und erhält die Login-Daten mit samt der URL
    def get_credentials(self):
        url = input("* Name / URL: ")
        email_username = input("* email/username: ")
        password = getpass.getpass("* Password: ")
        return url.strip(), email_username.strip(), password.strip()

    # Datenbank, die die Website als URL speichert, den Usernamen/E-Mail für einen Account und das dazugehörige Passwort
    def initialise_db(self):
        # Verbindung zur Datenbank herstellen
        conn = sqlite3.connect('passwordmanager.db')
        cur = conn.cursor()

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

        # Wenn kein Master-Key in der Datenbank gespeichert ist, wird ein Master-Key erstellt
        if not stored_master_key:
            self.set_masterkey()
            
            # SQL-Befehl zum Speichern des Master-Keys in der Datenbank
            insert_master_key = '''
            INSERT INTO passwords (master_key) VALUES (?)
            '''
            # Speicherung des Master-Keys in der Datenbank
            cur.execute(insert_master_key, (self.master_key,))
            conn.commit()
            print("Der Master-Key wurde erfolgreich in der Datenbank gespeichert")

        # Die vom Nutzer eingegebene credentials für eine bestimmten Online-Account
        url, email_username, password = self.get_credentials()

        # SQL-Befehl zum Einfügen eines neuen Eintrages in die Tabelle
        insert_query = '''
        INSERT INTO passwords (url, email_username, password)
        VALUES (?, ?, ?)
        '''
        # Eintrag in die Tabelle einfügen
        cur.execute(insert_query, (url, email_username, password))
        conn.commit()

        # Verbindung zur Datenbank schließen
        conn.close()