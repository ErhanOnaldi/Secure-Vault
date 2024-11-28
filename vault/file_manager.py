import os
import pickle
from .encryption import encrypt_data, decrypt_data
from .integrity import compute_hash, verify_hash
from .utils import VAULT_FILE_PATH

def load_vault():
    if os.path.exists(VAULT_FILE_PATH):
        if os.path.getsize(VAULT_FILE_PATH) > 0:
            with open(VAULT_FILE_PATH, 'rb') as f:
                try:
                    vault_data = pickle.load(f)
                    return vault_data
                except EOFError:
                    print("Vault dosyası bozuk veya boş. Yeni bir vault oluşturulacak.")
                    return None
        else:
            print("Vault dosyası boş. Yeni bir vault oluşturulacak.")
            return None
    else:
        return None


def save_vault(vault_data):
    with open(VAULT_FILE_PATH, 'wb') as f:
        pickle.dump(vault_data, f)

def initialize_vault(key, salt):
    vault_data = {'files': {}, 'salt': salt}
    save_vault(vault_data)
    return vault_data

def add_file(vault_data, file_path, key):
    if not os.path.isfile(file_path):
        print("Dosya bulunamadı.")
        return vault_data

    with open(file_path, 'rb') as f:
        file_data = f.read()

    filename = os.path.basename(file_path)
    file_hash = compute_hash(file_data)
    iv, ciphertext = encrypt_data(file_data, key)

    vault_data['files'][filename] = {
        'iv': iv,
        'ciphertext': ciphertext,
        'hash': file_hash
    }

    print(f"{filename} dosyası vault'a eklendi.")
    return vault_data

def extract_file(vault_data, filename, output_directory, key):
    if filename not in vault_data['files']:
        print("Dosya vault içinde bulunamadı.")
        return

    file_info = vault_data['files'][filename]
    iv = file_info['iv']
    ciphertext = file_info['ciphertext']
    stored_hash = file_info['hash']

    decrypted_data = decrypt_data(iv, ciphertext, key)
    if not verify_hash(decrypted_data, stored_hash):
        print("Dosya bütünlüğü doğrulanamadı. Dosya bozulmuş olabilir.")
        return

    output_path = os.path.join(output_directory, filename)
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"{filename} dosyası {output_directory} dizinine çıkarıldı.")

def list_files(vault_data):
    if not vault_data['files']:
        print("Vault boş.")
    else:
        print("Vault içindeki dosyalar:")
        for filename in vault_data['files'].keys():
            print(f"- {filename}")

def remove_file(vault_data, filename):
    if filename in vault_data['files']:
        del vault_data['files'][filename]
        print(f"{filename} dosyası vault'tan silindi.")
    else:
        print("Dosya vault içinde bulunamadı.")
    return vault_data
