import hashlib

## CONSTANTS

DEBUG = False
LS_bytes = 8 # Number of BYTES for the extra randomness parameter. Not in bits, BYTES.

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

'''
def decodeLittleEndian(b, bits):
    return sum([b[i] << 8*i for i in range((bits+7)/8)])

def decodeUCoordinate(u, bits):
    u_list = [ord(b) for b in u]
    # Ignore any unused bits.
    if bits % 8:
        u_list[-1] &= (1<<(bits%8))-1
    return decodeLittleEndian(u_list, bits)

def encodeUCoordinate(u, bits):
    u = u % p
    return ''.join([chr((u >> 8*i) & 0xff)
                    for i in range((bits+7)/8)])
'''