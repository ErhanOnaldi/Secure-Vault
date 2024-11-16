import os
import hashlib
import hmac

def hash_password(password, salt=None):
    """
    Kullanıcı şifresini PBKDF2-HMAC-SHA256 kullanarak hashler.

    Args:
        password (str): Kullanıcının şifresi.
        salt (bytes, optional): Kullanıcıya özel salt. Yoksa yeni bir salt oluşturulur.

    Returns:
        tuple: (salt, hashed_password)
    """
    if not salt:
        salt = os.urandom(16)  # 16 baytlık yeni bir salt oluştur.
    
    password = password.encode('utf-8')  # Şifreyi UTF-8'e çevir.
    
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',          # HMAC-SHA256 algoritması
        password,          # Hashlenecek şifre
        salt,              # Kullanıcıya özel salt
        100000             # 100,000 iterasyon (güvenlik için standart)
    )
    return salt, hashed_password
def verify_password(stored_password, provided_password, salt):
    """
    Sağlanan şifreyi hashleyip saklanan hash ile karşılaştırır.

    Args:
        stored_password (bytes): Hashlenmiş ve saklanan şifre.
        provided_password (str): Kullanıcıdan alınan şifre.
        salt (bytes): Kullanıcıya özel salt.

    Returns:
        bool: Şifre doğruysa True, yanlışsa False.
    """
    _, hashed_password = hash_password(provided_password, salt)
    return hmac.compare_digest(stored_password, hashed_password)

if __name__ == "__main__":
    # Örnek şifre
    user_password = "SecurePassword123"
    
    # Şifreyi hashle ve salt oluştur
    salt, hashed = hash_password(user_password)
    print("Salt:", salt.hex())
    print("Hashed Password:", hashed.hex())
    
    # Şifreyi doğrula
    is_valid = verify_password(hashed, user_password, salt)
    print("Password is valid:", is_valid)
    
    # Yanlış şifre testi
    is_invalid = verify_password(hashed, "WrongPassword", salt)
    print("Password is valid (wrong test):", is_invalid)
