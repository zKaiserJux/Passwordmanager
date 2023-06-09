import passwordmanager as pm
import os
from menu import run

if __name__ == "__main__":
    # create an instance of the password manager class
    manager = pm.PasswordManger()

    # runs the initialise_db class, if the database does not exist yet
    if not os.path.isfile("passwordmanager.db"):
        manager.initialise_db()
        while manager.logged_in_status:
            run(manager)
    # if so the user will be asked to login
    else:
        manager.user_login()
        while manager.logged_in_status:
            run(manager)