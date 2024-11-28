from vault.authentication import create_key, verify_key
from vault.file_manager import load_vault, save_vault, add_file, extract_file, list_files, remove_file, initialize_vault
from getpass import getpass
import os

def main():
    print("Secure File Vault Uygulamasına Hoş Geldiniz!")

    vault_data = load_vault()

    if not vault_data:
        print("Yeni bir vault oluşturuluyor.")
        password = getpass("Vault için bir şifre oluşturun: ")
        key, salt = create_key(password)
        vault_data = initialize_vault(key, salt)
        print("Vault oluşturuldu ve şifrelendi.")
    else:
        password = getpass("Vault şifresini girin: ")
        salt = vault_data['salt']
        key, _ = create_key(password, salt)
        # Burada verify_key fonksiyonunu kullanarak şifreyi doğrulayalım
        if not verify_key(password, salt, key):
            print("Şifre yanlış. Erişim reddedildi.")
            return
        print("Vault başarıyla açıldı.")

    while True:
        print("\nYapmak istediğiniz işlemi seçin:")
        print("1. Dosya Ekle")
        print("2. Dosya Çıkar")
        print("3. Dosyaları Listele")
        print("4. Dosya Sil")
        print("5. Vault'u Kilitle ve Çık")
        choice = input("Seçiminiz (1-5): ")

        if choice == '1':
            file_path = input("Eklenecek dosyanın yolunu girin: ")
            vault_data = add_file(vault_data, file_path, key)
            save_vault(vault_data)
        elif choice == '2':
            filename = input("Çıkarılacak dosyanın adını girin: ")
            output_directory = input("Dosyanın çıkarılacağı dizini girin: ")
            if not os.path.exists(output_directory):
                os.makedirs(output_directory)
            extract_file(vault_data, filename, output_directory, key)
        elif choice == '3':
            list_files(vault_data)
        elif choice == '4':
            filename = input("Silinecek dosyanın adını girin: ")
            vault_data = remove_file(vault_data, filename)
            save_vault(vault_data)
        elif choice == '5':
            print("Vault kilitleniyor. Güle güle!")
            break
        else:
            print("Geçersiz seçim. Lütfen tekrar deneyin.")

if __name__ == "__main__":
    main()
