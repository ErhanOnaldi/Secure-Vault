import os
from cryptography.hazmat.backends import default_backend

# Ortak değişkenler
BACKEND = default_backend()
VAULT_FILE_PATH = os.path.join('data', 'vault.dat')
