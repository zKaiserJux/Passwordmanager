import sys
import passwordmanager as pm 

# menu for the passwordmanager
def menu():
    user_command = input("Choose a command [(g)et / (s)earh / show (all) / (a)dd / (q)uit]: ")
    # user can get the credentails for an account
    if user_command == "g":
        pass

    # user can search for an account if it exists
    elif user_command == "s":
        pass

    # shows the user all the stored credentials in the database
    elif user_command == "all":
        pass

    # lets the user add an account with its credentials
    elif user_command == "a":
        pm.PasswordManger.add_credentials()

    # quits the application
    elif user_command == "q":
        sys.exit(0)