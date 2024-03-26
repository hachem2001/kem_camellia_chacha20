#!/usr/bin/env python

## IMPORTS

from string import hexdigits as string_hexdigits
from cryptography.hazmat.primitives.asymmetric import x25519
import sys, os

import KEM
import hash_elgamal
from KEM import DEBUG

## MAIN

def main():
    if len(sys.argv) != 3 :
        print("Usage : ./decaps.py <private-key-filename> <32-byte hex public key>")
        sys.exit(1)
    

    privatekey_filename = sys.argv[1]

    if not os.path.exists(privatekey_filename):
        print(f"Error : '{privatekey_filename} does not exists.")
        sys.exit(1)


    public_r_ciphertext = sys.argv[2]
    
    if len(public_r_ciphertext) < 64 and all(c in string_hexdigits for c in public_key):
        print(f"Error : '{public_r_ciphertext} is incorrect.") # Either too short or not hex
        sys.exit(1)



    ## All checks done : reconvert to proper formats
    public_r_bytes = bytes(bytearray.fromhex(public_r_ciphertext[:64]))
    public_r_key = x25519.X25519PublicKey.from_public_bytes(public_r_bytes)

    ciphertext_bytes = bytes(bytearray.fromhex(public_r_ciphertext[64:]))
    
    ## Read from private key file
    private_key = None
    public_key = None
    private_key_bytes = None
    extra_randomness = None
    public_key_bytes = None
    public_key_hash = None

    with open(privatekey_filename, 'rb') as file:
        # Calculate the private key
        byte_data = bytearray(file.read())

        # Remember format : 32 bytes for private key, followed by LS_bytes bytes for the extra randomness, followed by 32 bytes of public key and 32 bytes of public key hash, little endian for everything.

        private_key_bytes = bytes(byte_data[:32])
        extra_randomness = bytes(byte_data[32:32+KEM.LS_bytes])
        public_key_bytes = bytes(byte_data[32+KEM.LS_bytes:32+KEM.LS_bytes+32])
        public_key_hash = bytes(byte_data[64+KEM.LS_bytes:])


        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
        public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)

        if DEBUG:
            print("private", private_key_bytes.hex())
            print("s", extra_randomness.hex())
            print("public", public_key_bytes.hex())
            print("public_hash", public_key_hash.hex())



    message_Mp = hash_elgamal.private_key_decrypt(public_r_bytes, ciphertext_bytes, private_key_bytes)
    # Verified : the decrypted message is the right one.

    rp_kp = KEM.G2(public_key_hash + message_Mp)
    rp = rp_kp[:32]
    kp = rp_kp[32:]

    K0p = KEM.F(public_r_bytes + ciphertext_bytes + kp)
    K1p = KEM.F(public_r_bytes + ciphertext_bytes + extra_randomness)

    (public_r_p, ciphertext_p) = hash_elgamal.public_key_encrypt(message_Mp, public_key_bytes, rp, ciphertext_bytes[:16]) # Last is IV.


    Kp = None
    if (public_r_bytes == public_r_p) and (ciphertext_bytes == ciphertext_p):
        Kp = K0p
    else:
        Kp = K1p
    
    print(Kp.hex()) 

    if DEBUG:
        print("K0p", K0p.hex())
        print("K1p", K1p.hex())   

if __name__ == "__main__":
    main()