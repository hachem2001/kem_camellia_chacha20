from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets
from KEM import DEBUG
from KEM import encrypt_hash

def encrypt(message: bytes, key: bytes, iv : bytes = None) -> bytes:
    """
        Calculates the (symmetric) encryption of message using key.
        For this project, we'll be using Camellia as the algorithm
        (Can be substituted with Chacha20 or AES)
    """
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()

    if iv == None:
        iv = secrets.token_bytes(16)
    else:
        assert(len(iv) == 16)

    cipher = Cipher(algorithm=algorithms.Camellia(key), mode=modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(padded_message) + encryptor.finalize()

    return ciphertext

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
        Calculates the (symmetric) encryption of message using key.
        For this project, we'll be using Camellia as the algorithm
        (Can be substituted with Chacha20 or AES)
    """
    iv = ciphertext[:16]
    cipher = Cipher(algorithm=algorithms.Camellia(key), mode=modes.CBC(iv), backend=default_backend())

    # Decrypting (for completeness)
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    # Removing padding from the decrypted message
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    return decrypted_message