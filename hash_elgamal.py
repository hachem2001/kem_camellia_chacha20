from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

import symmetric
import KEM
from KEM import DEBUG

# PKE
def public_key_encrypt(message : bytes, public_bytes : bytes, randomness : bytes, iv : bytes = None) -> bytes:
    """
        PKE in hash_ElGamal style. Encrypt part
    """
    assert(len(public_bytes) == len(randomness))
    assert(len(public_bytes) == 32)


    # Calculate [randomness]public_key, (montgomery style).
    public_key_x25519 = x25519.X25519PublicKey.from_public_bytes(public_bytes)
    randomness_as_private_key = x25519.X25519PrivateKey.from_private_bytes(randomness)
    shared_secret = randomness_as_private_key.exchange(public_key_x25519)
    # Shared secret is set.


    randomness_corresponding_public_key = randomness_as_private_key.public_key() # Same thing as doing randomness[BP] x25519

    # Derive symmetric key from shared secret.
    symmetric_key = KEM.encrypt_hash(shared_secret)
    cipher_text = symmetric.encrypt(message, symmetric_key, iv)

    return (randomness_corresponding_public_key.public_bytes(encoding = Encoding.Raw, format=PublicFormat.Raw), cipher_text)

def private_key_decrypt(public_r : bytes, ciphertext : bytes, private_key_bytes : bytes) -> bytes:
    """
        PKE in hash_ElGamal style. Decrypt part
    """
    assert(len(public_r) == 32)
    #assert(len(ciphertext) == 96) DEPENDS ON SYMMETRIC ENCRYPTION ALGO.

    # Calculate [randomness]public_key, (montgomery style).
    # Calculate private key * public_r

    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    public_r_key = x25519.X25519PublicKey.from_public_bytes(public_r)
    shared_secret = private_key.exchange(public_r_key)
    
    symmetric_key = KEM.encrypt_hash(shared_secret)

    plaintext = symmetric.decrypt(ciphertext, symmetric_key)

    return plaintext
