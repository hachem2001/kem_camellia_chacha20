#!/usr/bin/env python

## IMPORTS

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import secrets # random is not secure enough
import sys, os # For reading arguments, etc
import deps.KEM as KEM
from deps.KEM import DEBUG

## MAIN

def main():
    if not (len(sys.argv) in [1, 2]) :
        print("Usage : ./keygen.py [publickey_filename]")
        sys.exit(1)
    
    privatekey_filename = "pk.key"
    if len(sys.argv) == 2:
        privatekey_filename = sys.argv[1]
    
    if os.path.exists(privatekey_filename):
        print(f"Error : '{privatekey_filename} exists.")
        sys.exit(1)

    # Generate key-pair. Write private key in file, print out public key.
    with open(privatekey_filename, 'wb') as file:
        
        # Calculate the private key
        private_key = x25519.X25519PrivateKey.generate()

        # Calculate the public key
        public_key = private_key.public_key()

        # Calculate PubKH

        # Extra randomness
        s = secrets.token_bytes(KEM.LS_bytes)

        # Raw byte representations
        private_bytes = private_key.private_bytes(encoding = Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
        public_bytes = public_key.public_bytes(encoding = Encoding.Raw, format=PublicFormat.Raw)

        public_key_hash = KEM.G1(public_bytes)

        # Print out public key
        print(public_bytes.hex())

        file.write(private_bytes)
        file.write(s)
        file.write(public_bytes)
        file.write(public_key_hash)

        if DEBUG:
            print("private", private_bytes.hex())
            print("s", s.hex())
            print("public", public_bytes.hex())
            print("public_hash", public_key_hash.hex())
    

if __name__ == "__main__":
    main()