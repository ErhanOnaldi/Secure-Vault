import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from vault_app.authentication import hash_password, derive_key

def save_vault(vault_path, vault_data, key):
    """
    Kasa verilerini diske şifreli olarak kaydeder.

    Args:
        vault_path (str): Kasayı kaydetmek için dosya yolu.
        vault_data (dict): Şifreli olarak saklanacak kasa verileri.
        key (bytes): Şifreleme anahtarı.
    """
    serialized_data = json.dumps(vault_data).encode('utf-8')
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # AES-GCM için 12 baytlık nonce
    encrypted_data = aesgcm.encrypt(nonce, serialized_data, None)
    
    with open(vault_path, 'wb') as vault_file:
        vault_file.write(nonce + encrypted_data)
    print(f"Kasa başarıyla kaydedildi: {vault_path}")


def create_vault(vault_path, password):
    """
    Yeni bir kasa oluşturur ve diske kaydeder.

    Args:
        vault_path (str): Kasayı kaydetmek için dosya yolu.
        password (str): Kullanıcı şifresi.

    Returns:
        dict: Yeni oluşturulan kasa verileri.
    """
    if os.path.exists(vault_path):
        raise FileExistsError("Belirtilen yol üzerinde zaten bir kasa var.")

    salt, hashed_password = hash_password(password)
    key = derive_key(password, salt)
    
    vault_data = {
        "salt": salt.hex(),
        "password_hash": hashed_password.hex(),
        "files": {}
    }
    
    save_vault(vault_path, vault_data, key)
    print("Kasa başarıyla oluşturuldu.")
    return vault_data

def load_vault(vault_path, password):
    """
    Şifreli kasayı yükler ve şifresini çözer.

    Args:
        vault_path (str): Kasanın saklandığı dosya yolu.
        password (str): Kasanın şifresini çözmek için kullanıcı şifresi.

    Returns:
        dict: Kasa verileri.
    """
    if not os.path.exists(vault_path):
        raise FileNotFoundError("Kasa dosyası bulunamadı.")
    
    with open(vault_path, 'rb') as vault_file:
        encrypted_data = vault_file.read()
    
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    with open(vault_path, 'rb') as vault_file:
        encrypted_data = vault_file.read()

    salt_hex = encrypted_data.get('salt')
    salt = bytes.fromhex(salt_hex)
    
    key = derive_key(password, salt)
    
    try:
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        vault_data = json.loads(decrypted_data.decode('utf-8'))
        
        return vault_data
    except Exception as e:
        raise ValueError("Kasa şifresi çözülmesi başarısız oldu.")

