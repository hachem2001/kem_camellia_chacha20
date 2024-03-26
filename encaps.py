#!/usr/bin/env python

## IMPORTS

from cryptography.hazmat.primitives.asymmetric import x25519
import secrets
from string import hexdigits as string_hexdigits
import sys # For reading arguments, etc

import KEM
import hash_elgamal
from KEM import DEBUG

## MAIN

def main():
    if len(sys.argv) != 2 :
        print("Usage : ./encaps.py <32-byte hex public key>")
        sys.exit(1)
    
    public_key = sys.argv[1]
    
    if len(public_key) != 64 and all(c in string_hexdigits for c in public_key):
        print(f"Error : '{public_key} is not a valid public key.")
        sys.exit(1)


    ## All checks done : reconvert to proper formats
    public_bytes = bytes(bytearray.fromhex(public_key))
    public_key = x25519.X25519PublicKey.from_public_bytes(public_bytes)

    # Generate random message of size that we choose. Say 64 for simplicity
    message_M = b"abcd"*8 #secrets.token_bytes(32) # Tested : correct.

    r_k = KEM.G2( KEM.G1(public_bytes) + message_M)
    r = r_k[:32] # Randomess to be used in encapsulated encryption
    k = r_k[32:] # Randomizing hash of ciphertext.


    (public_r, cipher_text) = hash_elgamal.public_key_encrypt(message_M, public_bytes, r)
    K_hash = KEM.F( public_r + cipher_text + k)


    # Print out (public_r+ciphertext)
    print((public_r + cipher_text).hex()) # Print it out as hex. TODO : fixed size for both !
    #print(public_r.hex()) # This would be the symmetric key. TODO verify size of hash
    #print(cipher_text.hex()) # This would be the symmetric key. TODO verify size of hash
    print(K_hash.hex()) # This would be the symmetric key. TODO verify size of hash
    

if __name__ == "__main__":
    main()