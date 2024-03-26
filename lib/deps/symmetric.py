from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets
from deps.KEM import encrypt_hash
from deps.KEM import SYMMETRIC_ALGO
from sys import exit
def encrypt(message: bytes, key: bytes, iv : bytes = None) -> bytes:
    """
        Calculates the (symmetric) encryption of message using key.
        For this project, we'll be using Camellia as the algorithm
        (Can be substituted with Chacha20 or AES)
    """
    assert(SYMMETRIC_ALGO in ["Camellia", "AES", "ChaCha20"])
    ciphertext = None

    if SYMMETRIC_ALGO in ["Camellia", "AES"]:
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message) + padder.finalize()

        if iv == None:
            iv = secrets.token_bytes(16)
        else:
            assert(len(iv) == 16)
        algorithm = SYMMETRIC_ALGO == "Camellia" and algorithms.Camellia or algorithms.AES
        cipher = Cipher(algorithm=algorithm(key), mode=modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = iv + encryptor.update(padded_message) + encryptor.finalize()
    elif SYMMETRIC_ALGO in ["ChaCha20"]:
        algorithm = algorithms.ChaCha20
        cipher = Cipher(algorithm=algorithm(key, b'0'*16), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()

    else:
        exit(1)

    return ciphertext

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
        Calculates the (symmetric) encryption of message using key.
        For this project, we'll be using Camellia as the algorithm
        (Can be substituted with Chacha20 or AES)
    """
    assert(SYMMETRIC_ALGO in ["Camellia", "AES", "ChaCha20"])
    decrypted_message = None

    if SYMMETRIC_ALGO in ["Camellia", "AES"]:
        iv = ciphertext[:16]
        algorithm = SYMMETRIC_ALGO == "Camellia" and algorithms.Camellia or algorithms.AES
        cipher = Cipher(algorithm=algorithm(key), mode=modes.CBC(iv), backend=default_backend())

        # Decrypting (for completeness)
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(ciphertext[16:]) + decryptor.finalize()

        # Removing padding from the decrypted message
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    elif SYMMETRIC_ALGO in ["ChaCha20"]:
        algorithm = algorithms.ChaCha20
        cipher = Cipher(algorithm=algorithm(key, b'0'*16), mode=None, backend=default_backend())

        # Decrypting (for completeness)
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    else:
        exit(1)


    return decrypted_message