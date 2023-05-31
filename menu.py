import sys
import passwordmanager as pm 
from crypto import generate_encryption_key, hash_master_key

# menu for the passwordmanager
def run(manager):
    # set the self variables:
    user_command = input("Choose a command [(g)et / (s)earch / show (all) / (a)dd / (q)uit]: ")
    # user can get the credentails for an account
    if user_command == "g":
        pm.PasswordManger.get_credentials(manager)

    # user can search for an account if it exists
    elif user_command == "s":
        pm.PasswordManger.search(manager)

    # shows the user all the stored credentials in the database
    elif user_command == "all":
        pm.PasswordManger.show_all(manager)

    # lets the user add an account with its credentials
    elif user_command == "a":
        pm.PasswordManger.add_credentials(manager)

    # quits the application
    elif user_command == "q":
        # encrypts all the data before the application terminates
        pm.PasswordManger.lock(manager)
        sys.exit(0)