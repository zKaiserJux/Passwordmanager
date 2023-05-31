import sys
import passwordmanager as pm 

# menu for the passwordmanager
def run(manager):
    # set the self variables:
    user_command = input("Choose a command [(g)et / (s)earch / show (all) / (a)dd / (d)elete / (q)uit]: ")
    # user can get the credentails for an account
    if user_command == "g":
        pm.PasswordManger.get_credentials(manager)

    # user can search for an account if it exists
    elif user_command == "s":
        result = pm.PasswordManger.search(manager)
        if result:
            print("[+] Mit der angegebenen URL existiert ein Account in der Datenbank")
        else:
            print("[-] Mit der angebeben URL existiert kein Account in der Datenbank")

    # shows the user all the stored credentials in the database
    elif user_command == "all":
        pm.PasswordManger.show_all(manager)

    # lets the user add an account with its credentials
    elif user_command == "a":
        pm.PasswordManger.add_credentials(manager)

    elif user_command == "d":
        pm.PasswordManger.delete_credentials(manager)

    # quits the application
    elif user_command == "q":
        # encrypts all the data before the application terminates
        pm.PasswordManger.lock(manager)
        sys.exit(0)