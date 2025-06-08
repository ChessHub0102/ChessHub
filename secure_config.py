import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Email credentials to encrypt
EMAIL_USERNAME = "chess.tournament.cop@gmail.com"
EMAIL_PASSWORD = "vrfg ufdw qogg pklv"
EMAIL_SENDER = "chess.tournament.cop@gmail.com"

# Secret key (should be stored securely, preferably in environment variable)
# If not available, use a default key (not best practice but for demonstration)
SECRET_FOR_ENCRYPTION = os.environ.get('ENCRYPTION_KEY', 'ChessT0urn@mentSecretK3y!2023')

def get_encryption_key(secret=None):
    """Generate an encryption key from a secret and salt"""
    if secret is None:
        secret = SECRET_FOR_ENCRYPTION
    
    # Use a static salt (in production, consider using a secure, persistent salt)
    salt = b'chess_tournament_salt_2023'
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    # Generate key from the secret
    key = base64.urlsafe_b64encode(kdf.derive(secret.encode()))
    return key

def encrypt_data(data, key=None):
    """Encrypt data using Fernet (AES)"""
    if key is None:
        key = get_encryption_key()
    
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, key=None):
    """Decrypt data using Fernet (AES)"""
    if key is None:
        key = get_encryption_key()
    
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()

# Encrypt the credentials
encrypted_username = encrypt_data(EMAIL_USERNAME)
encrypted_password = encrypt_data(EMAIL_PASSWORD)
encrypted_sender = encrypt_data(EMAIL_SENDER)

def get_mail_config():
    """Return decrypted mail configuration"""
    return {
        'MAIL_USERNAME': decrypt_data(encrypted_username),
        'MAIL_PASSWORD': decrypt_data(encrypted_password),
        'MAIL_DEFAULT_SENDER': decrypt_data(encrypted_sender)
    } 