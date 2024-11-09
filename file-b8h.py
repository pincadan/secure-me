import os
import random
import string
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
PASSWORD_LENGTH = 32
SALT_LENGTH = 16
ITERATIONS = 100000

# Generate a random salt
def generate_salt():
    return os.urandom(SALT_LENGTH)

# Derive a key from a password and salt
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt the password
def encrypt_password(key, password):
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

# Decrypt the password
def decrypt_password(key, encrypted_password):
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

# Generate a strong password
def generate_password():
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=PASSWORD_LENGTH))

# Store encrypted passwords in a JSON file
def store_passwords(passwords):
    with open('passwords.json', 'w') as f:
        json.dump(passwords, f)

# Load encrypted passwords from the JSON file
def load_passwords():
    try:
        with open('passwords.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Add a new password
def add_password(name, passwords):
    salt = generate_salt()
    key = derive_key(password, salt)
    encrypted_password = encrypt_password(key, generate_password())
    passwords[name] = {
        'salt': base64.urlsafe_b64encode(salt).decode(),
        'encrypted_password': encrypted_password
    }
    store_passwords(passwords)

# Get a password
def get_password(name, passwords):
    if name in passwords:
        salt = base64.urlsafe_b64decode(passwords[name]['salt'].encode())
        encrypted_password = passwords[name]['encrypted_password']
        key = derive_key(password, salt)
        return decrypt_password(key, encrypted_password)
    else:
        return None

# Main program
def main():
    passwords = load_passwords()

    print('Welcome to SecureMe Password Manager!')
    print('Please authenticate to access your passwords.')
    password = input('Password: ')

    # Authenticate the user
    # (Placeholder for biometric authentication)
    if not authenticate(password):
        print('Authentication failed. Exiting...')
        return

    while True:
        print('\nPlease choose an option:')
        print('1. Add a new password')
        print('2. Get a password')
        print('3. Exit')

        choice = input('Enter your choice (1-3): ')

        if choice == '1':
            name = input('Enter the name of the account: ')
            add_password(name, passwords)
            print(f'Password for {name} added successfully.')
        elif choice == '2':
            name = input('Enter the name of the account: ')
            stored_password = get_password(name, passwords)
            if stored_password:
                print(f'Password for {name}: {stored_password}')
            else:
                print(f'No password found for {name}.')
        elif choice == '3':
            print('Exiting SecureMe...')
            break
        else:
            print('Invalid choice. Please try again.')

if __name__ == '__main__':
    main()