import hashlib

## CONSTANTS

DEBUG = False
LS_bytes = 8 # Number of BYTES for the extra randomness parameter. Not in bits, BYTES.
SYMMETRIC_ALGO = "ChaCha20" # Three modes supported here : Camellia, AES and ChaCha20.

## HASHES

def G1(x):
    shake128_hasher = hashlib.shake_128(x)
    return shake128_hasher.digest(32)

def G2(x):
    shake128_hasher = hashlib.shake_128(x)
    return shake128_hasher.digest(64)

def F(x): # Must be 16-bytes.
    shake128_hasher = hashlib.shake_128(x)
    return shake128_hasher.digest(16)

def encrypt_hash(x):
    return G1(x)