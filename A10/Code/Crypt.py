from cryptography.fernet import Fernet
import os

def key_path():
    
    # cwd = os.getcwd()
    file_path = os.path.realpath(__file__)
    dir_path = os.path.dirname(file_path)

    # print (cwd)
    # print (file_path)
    # print (dir_path)

    return dir_path



def generate_key():
    """
    Generates a key and save it into a file
    """
    dir_path = key_path()
    key = Fernet.generate_key()
    with open(dir_path + "/secret.key", "wb") as key_file:
        key_file.write(key)



def load_key():
    """
    Load the previously generated key
    """
    dir_path = key_path()
    return open(dir_path + "/secret.key", "rb").read()



def encrypt_message(message):
    """
    Encrypts a message
    """
    key = load_key()
    # key = "v30nE9iDBSlWlIzViAiqmgvIypz0v4qjGmiYHbNoXn8="
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)

    print(encrypted_message)

    # return encrypted_message



def decrypt_message(encrypted_message):
    """
    Decrypts an encrypted message
    """
    key = load_key()
    # key = "v30nE9iDBSlWlIzViAiqmgvIypz0v4qjGmiYHbNoXn8="
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)

    print(decrypted_message.decode())

    # return decrypted_message.decode()



if __name__ == "__main__":

    generate_key()

    # encrypt_message("encrypt this message")

    # decrypt_message(b'gAAAAABhTEeswE0qPMmAGrJrLyAyniPF_HYUIITozb7QIkHB21kqD1ibzE_8j4fpyzW6WwIvi3kHQqLZC37sWm0iLx1mDdtXU_W8Lr6tIeWpvhwpM3EPS-Q=')