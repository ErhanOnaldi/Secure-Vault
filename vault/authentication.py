import os
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .utils import BACKEND

def create_key(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=BACKEND
    )
    key = kdf.derive(password.encode())
    return key, salt

def verify_key(password, salt, key):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=BACKEND
    )
    try:
        kdf.verify(password.encode(), key)
        return True
    except:
        return False
