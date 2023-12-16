from cryptography.fernet import Fernet, InvalidToken



def generate_key():
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)


def encrypt_with_fernet():
