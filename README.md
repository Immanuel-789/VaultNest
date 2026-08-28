# VaultNest

VaultNest is a Python-based password manager designed to securely store and manage account credentials.

## Features

* Create a user account with a master password
* Generate strong passwords
* Store website usernames and passwords
* View saved passwords
* Search for saved passwords
* Update saved passwords
* Delete saved passwords
* Update the master password
* Delete the user account
* Forgot-password recovery using an email OTP
* Forgot-username recovery using an email OTP
* Login attempt tracking
* Temporary account lockout after repeated failed login attempts
* Encrypted database storage

## Security

VaultNest uses several security mechanisms to protect stored information:

* Master passwords are processed using PBKDF2-HMAC-SHA256 with a unique salt.
* Password verification uses `hmac.compare_digest()`.
* Stored passwords are encrypted using Fernet symmetric encryption.
* The database file is encrypted using a separate Fernet encryption key.
* Database and email credentials are loaded through environment variables rather than being stored directly in the source code.
* Failed login attempts are tracked and accounts are temporarily locked after repeated failures.
* OTPs are generated using Python's `secrets` module.

## Requirements

VaultNest requires Python and the following external package:

```text
cryptography
```

The remaining modules used by the project are part of Python's standard library.

## Environment Variables

VaultNest requires environment variables for sensitive configuration.

The following variables must be configured before running the program:

```text
VAULTNEST_DB_KEY
SENDER_EMAIL
EMAIL_APP_PASSWORD
```

## Running VaultNest

1. Clone the repository.
2. Create and activate a Python virtual environment.
3. Install the required package:

```bash
pip install -r requirements.txt
```

4. Configure the required environment variables.
5. Run the Python program:

```bash
python "password manager.py"
```

## Database

VaultNest stores its user database in `Members.json`.

The database is encrypted before being written to disk. `Members.json` should not be uploaded to the repository.

## Project Structure

```text
VaultNest/
├── password manager.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Disclaimer

VaultNest is a personal/educational password-manager project created to explore password hashing, encryption, authentication, account recovery, and secure data storage in Python.

It should not be considered a production-grade password manager without further security review and testing.
