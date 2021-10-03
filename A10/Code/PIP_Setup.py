import subprocess
import sys

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# pip install hashlib           #MD5, SHA-256
# pip install cryptography      #RSA, Fernet
# pip install pyDH              #DH
# pip install pycrypto          #AES, DES, RSA, SHA256