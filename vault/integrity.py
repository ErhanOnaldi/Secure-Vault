from cryptography.hazmat.primitives import hashes
from .utils import BACKEND

def compute_hash(data):
    digest = hashes.Hash(hashes.SHA256(), backend=BACKEND)
    digest.update(data)
    return digest.finalize()

def verify_hash(data, stored_hash):
    return compute_hash(data) == stored_hash
