import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .utils import BACKEND

def pad_data(data):
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length]) * padding_length

def unpad_data(data):
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    padded_data = pad_data(data)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext

def decrypt_data(iv, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    data = unpad_data(padded_data)
    return data
