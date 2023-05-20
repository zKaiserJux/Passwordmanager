import sqlite3
import pwinput

class Passwordmanger:
    def __init__(self):
        self.masterkey = ""
        self.password_list = []
        self.active = True

    def get_credentials(self):
        url = input("* Name / URL: ")
        email_username = input("* email/username: ")
        password = pwinput.pwinput(prompt="* Password: ", mask="*")
        return url, email_username, password

    # Datenbank, die die Website als URL speichert, den Usernamen/E-Mail für einen Account und das dazugehörige Passwort
    def initialise_db(self):
        # Die vom Nutzer eingegebene credentials für eine bestimmten Online-Account
        url, email_username, password = self.get_credentials()

        # Verbindung zur Datenbank herstellen
        conn = sqlite3.connect('passwordmanager.db')
        
        # SQL-Befehl zum Erstellen der Datentabelle
        create_table_query = '''
        CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        email_username TEXT,
        password TEXT
        )
        '''
        # Datenbank ersellen
        conn.execute(create_table_query)

        # SQL-Befehl zum Einfügen eines neuen Eintrages in die Tabelle
        insert_query = '''
        INSERT INTO passwords (url, email_username, password)
        VALUES (?, ?, ?)
        '''
        # Eintrag in die Tabelle einfügen
        conn.execute(insert_query, (url, email_username, password))

        # Aenderungen in der Datenbank speichern
        conn.commit()

        # SQL-Befehl zum Abrufen aller Einträge in der Datenbank
        select_query = '''
        SELECT url, email_username, password
        FROM passwords
        '''

        # Daten abrufen und in der Variable result speichern
        result = conn.execute(select_query)

        # Ereignisse anzeigen
        for entry in result:
            print("URL: ", entry[0])
            print("email/username: ", entry[1])
            print("password: ", entry[2])

        # Verbindung zur Datenbank schließen
        conn.close()
            
