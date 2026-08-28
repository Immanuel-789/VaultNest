import json
from json import JSONDecodeError
import hashlib
import secrets
import hmac
import base64
from cryptography.fernet import Fernet,InvalidToken
import smtplib
from email.message import EmailMessage
import os
from datetime import datetime, timedelta


DATABASE_KEY = os.getenv("VAULTNEST_DB_KEY")

if DATABASE_KEY is None:
    raise RuntimeError("VAULTNEST_DB_KEY is not configured")

DATABASE_FERNET  = Fernet(DATABASE_KEY.encode())



def welcome():
    print("Welcome to Password Manager")


def login_success():
    print("Login Successful")


def account_created():
    print("Account created successfully")


def password_added():
    print("Password added successfully")


def is_locked(user):

    locked_until = Members[user]["Login Security"]["Locked Until"]

    if locked_until is None:
        return False

    locked_until = datetime.fromisoformat(locked_until)

    if datetime.now() < locked_until:
        return True

    Members[user]["Login Security"]["Locked Until"] = None
    Members[user]["Login Security"]["Failed Attempts"] = 0

    dump_data(Members)

    return False



def locked_out(user):

    if Members[user]["Login Security"]["Failed Attempts"] == 7:

        locked_until = datetime.now() + timedelta(minutes=15)
        locked_until = datetime.isoformat(locked_until)
        Members[user]["Login Security"]["Locked Until"] = locked_until

    dump_data(Members)



def login():
    username = non_empty_input("Enter username: ")

    if username not in Members:
        print("Username not found...")

        if yes_no_input("Forgot username: [Yes/No]") == "yes":
            email = non_empty_input("Enter your email address: ")

            if forgot_username(email):
                print("Login")
                return login()

        return None


    if is_locked(username):
        print("Account is locked")
        print("Please try again later")
        if yes_no_input("Forgot password: [Yes/No]") == "yes":
            forgot_password(username)
            return login()
        return None


    stored_hash = Members[username]["Master Password"]["Hashed Password"]
    stored_salt = Members[username]["Master Password"]["Salt"]

    encryption_key = verify(stored_hash, stored_salt, username,max_attempts=7)

    if encryption_key:
        login_success()
        password_key = Fernet(encryption_key)
        return username, password_key

    locked_out(username)

    if yes_no_input("Forgot password: [Yes/No]") == "yes":
        if forgot_password(username):
            print("Login")
            return login()
    else:
        print("Returning to main menu")

    return None


def verify(stored_hash, stored_salt, username,max_attempts=3):
    attempts_left = max_attempts
    salt = string_to_bytes(stored_salt)

    while attempts_left > 0:
        entered_password = non_empty_input("Enter your master password: ")
        password_bytes = entered_password.encode()

        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password_bytes,
            salt,
            100000,
            dklen=32
        )

        calculated_hash_string = bytes_to_string(calculated_hash)

        if hmac.compare_digest(calculated_hash_string, stored_hash):

            master_key = Fernet(bytes_to_fernet(calculated_hash))
            encrypted_key = Members[username]["Encrypted Key"]

            encryption_key = master_key.decrypt(encrypted_key.encode())

            Members[username]["Login Security"]["Failed Attempts"] = 0
            dump_data(Members)
            return encryption_key

        print("Incorrect password")
        attempts_left -= 1
        print("Attempts left: ", attempts_left)
        Members[username]["Login Security"]["Failed Attempts"] += 1
        dump_data(Members)

    return None


def string_to_bytes(data):
    return base64.b64decode(data)


def account_creation():
    while True:
        username = non_empty_input("Enter username: ")

        if username in Members:
            print("Username already taken")
            continue

        generate_password_choice = yes_no_input(
            "Do you want a generated password [Yes/No]: "
        )

        if generate_password_choice == "yes":
            master_password = generate_password()

            view_generated = yes_no_input(
                "Do you want to view it [Yes/No]: "
            )

            if view_generated == "yes":
                print("Generated Password: ", master_password)

        else:
            master_password = valid_password("Enter master password: ")

        email = valid_email()

        password_hash, salt = hash_password(master_password)

        encryption_key = Fernet.generate_key()

        master_key = Fernet(bytes_to_fernet(password_hash))
        encrypted_key = master_key.encrypt(encryption_key).decode()

        stored_hash = bytes_to_string(password_hash)
        stored_salt = bytes_to_string(salt)

        Members[username] = {
            "Master Password": {
                "Hashed Password": stored_hash,
                "Salt": stored_salt
            },
            "Encrypted Key": encrypted_key,
            "Saved Passwords": {},
            "Email Address": email,
            "Login Security":{"Locked Until":None,"Failed Attempts":0}
        }

        dump_data(Members)
        account_created()
        break


def yes_no_input(question):
    while True:
        answer = input(question).lower()

        if answer in ("yes", "no"):
            return answer

        print("Type 'Yes' or 'No' ")


def add_password(username, password_key):
    while True:
        website_name = non_empty_input(
            "Under what name/website do you want this password to be stored: "
        ).lower()

        if website_name not in Members[username]["Saved Passwords"]:
            break

        print("Password already exists.....")

        update_choice = yes_no_input(
            "Do you wish to update password [Yes/No]: "
        )

        if update_choice == "yes":
            print("Please choose number 5 ")
            return

        print("Please choose another name")

    account_username = non_empty_input("Enter username: ")

    password_type = password_choice(
        "Do you want to generate a password or input an existing password "
        "[Generate/Exists]: "
    )

    if password_type == "generate":
        saved_password = generate_password()

        view_generated = yes_no_input(
            "Do yo want to view it [Yes/No]: "
        )

        if view_generated == "yes":
            print("Generated Password: ", saved_password)

    else:
        saved_password = non_empty_input("Enter password: ")

    encrypted_password = password_key.encrypt(
        saved_password.encode()
    ).decode()

    Members[username]["Saved Passwords"][website_name] = {
        "Username": account_username,
        "Password": encrypted_password
    }

    dump_data(Members)
    password_added()


def non_empty_input(question):
    while True:
        value = input(question)

        if value == "":
            print("This input cannot be empty")
        else:
            return value


def view_password(username, password_key):
    saved_passwords = Members[username]["Saved Passwords"]

    if not saved_passwords:
        print("You have no current saved passwords")
        return

    for website_name, credentials in saved_passwords.items():
        print("Website:", website_name)
        print("Username:", credentials["Username"])

        decrypted_password = password_key.decrypt(
            credentials["Password"].encode()
        ).decode()

        print("Password:", decrypted_password)


def generate_password():
    characters = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "1234567890"
        "./!@#$%^&*"
    )

    while True:
        generated_password = ""

        try:
            password_length = int(
                input("Enter the length of the password (Above 8): ")
            )

            if password_length > 8:
                for _ in range(password_length):
                    generated_password += secrets.choice(characters)

                return generated_password

            print("Invalid password length")

        except ValueError:
            print("Please enter a number")


def search_password(username, password_key):
    website_name = non_empty_input(
        "Enter name of website: "
    ).lower()

    saved_passwords = Members[username]["Saved Passwords"]

    if website_name not in saved_passwords:
        print("Website not found")
        return

    show_password = yes_no_input(
        "Do you want to see your password for this website [Yes/No]: "
    )

    if show_password == "yes":
        print("Website:", website_name)
        print(
            "Username: ",
            saved_passwords[website_name]["Username"]
        )

        decrypted_password = password_key.decrypt(
            saved_passwords[website_name]["Password"].encode()
        ).decode()

        print("Password: ", decrypted_password)

    else:
        print("Password hidden")


def password_choice(question):
    while True:
        choice = input(question).lower()

        if choice in ("generate", "exists"):
            return choice

        print("Type 'Generate' or 'Exists' ")


def delete_password(username):
    website_name = non_empty_input(
        "Enter name of website: "
    ).lower()

    saved_passwords = Members[username]["Saved Passwords"]

    if website_name not in saved_passwords:
        print("Website not found")
        return

    delete_choice = yes_no_input(
        "Are you sure you want to delete this password [Yes/No]: "
    )

    if delete_choice == "yes":
        saved_passwords.pop(website_name)
        dump_data(Members)
        print("Password removed")
    else:
        print("Password not removed")


def update_password(username, password_key):
    website_name = non_empty_input(
        "Enter name of website: "
    ).lower()

    saved_passwords = Members[username]["Saved Passwords"]

    if website_name not in saved_passwords:
        print("Website not found")
        return

    attempts_left = 3

    while attempts_left > 0:
        old_password = non_empty_input("Enter old password: ")

        decrypted_password = password_key.decrypt(
            saved_passwords[website_name]["Password"].encode()
        ).decode()

        if old_password == decrypted_password:
            password_reset(
                "website",
                username,
                website_name,
                password_key
            )
            return

        print("Old password incorrect")
        attempts_left -= 1
        print("Attempts left: ", attempts_left)

    print("Too many failed attempts...")
    print("Returning to main menu")


def update_master_password(username):
    stored_hash = Members[username]["Master Password"]["Hashed Password"]
    stored_salt = Members[username]["Master Password"]["Salt"]

    encryption_key = verify(
        stored_hash,
        stored_salt,
        username
    )

    if encryption_key:
        return password_reset(
            "master",
            username,
            key=encryption_key
        )

    print("Reset Failed")
    return False


def password_reset(
    reset_type,
    username,
    website_name=None,
    key = None
):
    while True:
        generate_choice = yes_no_input(
            "Do you want a generated password [Yes/No]: "
        )

        if generate_choice == "yes":
            new_password = generate_password()

            view_generated = yes_no_input(
                "Do yo want to view it [Yes/No]: "
            )

            if view_generated == "yes":
                print("Generated Password: ", new_password)

            confirmation_password = new_password

        else:
            if reset_type == "master":
                new_password = valid_password("Enter new password: ")
                confirmation_password = non_empty_input("Enter new password again: ")
            else:
                new_password = non_empty_input(
                "Enter new password: "
                )
                confirmation_password = non_empty_input(
                "Enter new password again: "
                )

        if new_password != confirmation_password:
            print("Passwords do not match")
            continue

        if reset_type == "master":
            password_hash, salt = hash_password(new_password)

            new_master_key = Fernet(
                bytes_to_fernet(password_hash)
            )

            encrypted_key = new_master_key.encrypt(key).decode()

            Members[username]["Master Password"]["Hashed Password"] = (
                bytes_to_string(password_hash)
            )
            Members[username]["Master Password"]["Salt"] = (
                bytes_to_string(salt)
            )
            Members[username]["Encrypted Key"] = encrypted_key

            print("Master password reset successfully")
            dump_data(Members)

            return True

        encrypted_password = key.encrypt(
            new_password.encode()
        ).decode()

        Members[username]["Saved Passwords"][website_name]["Password"] = (
            encrypted_password
        )

        print("Password reset successfully")
        dump_data(Members)

        return True


def load_data():
    try:
        with open("Members.json", "rb") as file:
            encrypted_data = file.read()



        decrypted_data = DATABASE_FERNET.decrypt(encrypted_data)


        json_text = decrypted_data.decode()


        return json.loads(json_text)

    except FileNotFoundError:
        return {}

    except InvalidToken:
        raise RuntimeError("Members could not be decrypted. "
                           "Check DB key.")

    except JSONDecodeError:
        raise RuntimeError("Members database contains invalid JSON.")


def dump_data(data):
    json_text = json.dumps(data)

    json_data = json_text.encode()


    encrypted_data = DATABASE_FERNET.encrypt(json_data)

    with open("Members.json", "wb") as file:
        file.write(encrypted_data)




def delete_account(username):
    delete_choice = yes_no_input(
        "Are you sure you want to delete your account [Yes/No]: "
    )

    if delete_choice == "no":
        print("Account deletion cancelled")
        return

    stored_hash = Members[username]["Master Password"]["Hashed Password"]
    stored_salt = Members[username]["Master Password"]["Salt"]

    encryption_key = verify(
        stored_hash,
        stored_salt,
        username
    )

    if encryption_key:
        Members.pop(username)
        dump_data(Members)
        print("Account deleted successfully")
    else:
        print("Failed to delete account")


def hash_password(password):
    password_bytes = password.encode()

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password_bytes,
        salt,
        100000,
        dklen=32
    )

    return password_hash, salt


def bytes_to_string(data):
    return base64.b64encode(data).decode()


def bytes_to_fernet(data):
    return base64.urlsafe_b64encode(data)


def forgot_password(username):
    one_time_passcode = otp_generator()

    receiver_email = Members[username]["Email Address"]


    if  send_email(receiver_email, one_time_passcode,"password", user=username):
        verification = verify_otp(one_time_passcode)
    else:
        print("Password reset failed")
        return False



    if not verification:
        print("Password reset failed")
        return False

    stored_hash = Members[username]["Master Password"]["Hashed Password"]
    encrypted_key = Members[username]["Encrypted Key"]

    hashed_bytes = string_to_bytes(stored_hash)
    hashed_fernet = Fernet(bytes_to_fernet(hashed_bytes))

    encryption_key = hashed_fernet.decrypt(
        encrypted_key.encode()
    )

    return password_reset(
        "master",
        username,
        key = encryption_key
    )


def verify_otp(otp):
    attempts_left = 3

    while attempts_left > 0:
        entered_otp = input(
            "Enter OTP sent to your email address: "
        )

        if hmac.compare_digest(otp, entered_otp):
            return True

        print("Invalid OTP")
        attempts_left -= 1
        print("Attempts left: ", attempts_left)

    return False


def otp_generator():
    digits = "1234567890"
    one_time_passcode = ""

    for _ in range(6):
        one_time_passcode += secrets.choice(digits)

    return one_time_passcode


def send_email(receiver, code, email_type, user=None):
    sender_email = os.getenv("SENDER_EMAIL")
    app_password = os.getenv("EMAIL_APP_PASSWORD")

    if sender_email is None or app_password is None:
        print("Email credentials not configured")
        return False

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)

        server.login(sender_email, app_password)

        message = EmailMessage()

        message["From"] = sender_email
        message["To"] = receiver

        if email_type == "password":
            message["Subject"] = "Password Reset One-Time-Passcode"
            message.set_content(
                f"Your OTP for the password reset for user {user} is: {code}"
            )

        else:
            message["Subject"] = "Retrieval of Username One-Time-Passcode"
            message.set_content(
                f"Your OTP is: {code}"
            )

        server.send_message(message)
        server.quit()

        return True

    except smtplib.SMTPAuthenticationError:
        print("Email authentication failed")
        return False

    except (smtplib.SMTPException, OSError):
        print("Could not send email")
        return False

def forgot_username(receiver_email):
    found_username = None

    for username, account_details in Members.items():
        if account_details["Email Address"] == receiver_email:
            found_username = username
            break

    if found_username is None:
        print("Email address not registered")
        return False

    print("Email address found")

    one_time_passcode = otp_generator()

    if not send_email(
        receiver_email,
        one_time_passcode,
        "username"
    ):
        return False

    verification = verify_otp(one_time_passcode)

    if verification:
        print("Your username is: ", found_username)
        return True

    return False



def valid_email():
    while True:
        email = non_empty_input("Enter email address: ")

        if email.endswith("@gmail.com"):
            return email
        else:
            print("Email address not valid")
            print("Enter a valid email address")



def valid_password(question):
    symbols = "!@#$%^&*/."
    while True:
        password = non_empty_input(question)

        if (
            len(password) >= 10
            and any(character.isdigit() for character in password)
            and any(character.islower() for character in password)
            and any(character.isupper() for character in password)
            and any(character in symbols for character in password)
        ):
            return password
        else:
            print("Password requirements:")
            print("- At least 10 characters")
            print("- At least one uppercase letter")
            print("- At least one lowercase letter")
            print("- At least one number")
            print("- At least one symbol")






Members = load_data()
current_user = None

design = "="
heading = "PASSWORD MANAGER"

print(design * 24)
print()
print(heading.center(23))
print()
print(design * 24)

welcome()

has_account = yes_no_input(
    "Do you have an account [Yes/No]: "
)

if has_account == "yes":
    current_user = login()

else:
    create_account = yes_no_input(
        "Do you want to create an account [Yes/No]: "
    )

    if create_account == "yes":
        account_creation()
        print("Login")
        current_user = login()

    else:
        print("Have a good day")


menu = {
    "1": "Add Password",
    "2": "View Password",
    "3": "Search Password",
    "4": "Delete Password",
    "5": "Update Password",
    "6": "Update Master Password",
    "7": "Delete Account",
    "8": "Logout"
}


if current_user:
    while True:
        for menu_number, menu_item in menu.items():
            print(menu_number, ":", menu_item)

        choice = input("Choose a number: ")

        if choice == "1":
            add_password(
                current_user[0],
                current_user[1]
            )

        elif choice == "2":
            view_password(
                current_user[0],
                current_user[1]
            )

        elif choice == "3":
            search_password(
                current_user[0],
                current_user[1]
            )

        elif choice == "4":
            delete_password(
                current_user[0]
            )

        elif choice == "5":
            update_password(
                current_user[0],
                current_user[1]
            )

        elif choice == "6":
            update_master_password(
                current_user[0]
            )

        elif choice == "7":
            delete_account(
                current_user[0]
            )

            if current_user[0] not in Members:
                break

        elif choice == "8":
            print("Have a good day")
            break

        else:
            print("Invalid input")


