OUERTANI Mohamed hichem

# Usage

- Made to work on common Linux (debian, fedora). Will not work on MacOS or Windows.
- Make sure keygen, encaps and decaps are executable (`chmod +x keygen encaps decaps`)

## Demo

```
$ ./keygen.py 
> 557538c0131e1bfa5051f99faf4f39c06d631ff11801abe69b16e002001b3844
$ ./encaps.py 557538c0131e1bfa5051f99faf4f39c06d631ff11801abe69b16e002001b3844
> af4384c742e640143152f8592edaf155f37c4f3571ca7f782e630a90d3254c77c8459e4fc0c0afab7a83a2078dcb9f7bc0e183a6b90f0c9f3a95cce5a4bab7f90533294462fd97700fa7c20ed5f9f2aa1d1cff408e0ac1152fee29a04f88febb
> 61a307e9753eef0843209cf9637e29fe
$ ./decaps.py pk.key af4384c742e640143152f8592edaf155f37c4f3571ca7f782e630a90d3254c77c8459e4fc0c0afab7a83a2078dcb9f7bc0e183a6b90f0c9f3a95cce5a4bab7f90533294462fd97700fa7c20ed5f9f2aa1d1cff408e0ac1152fee29a04f88febb
> 61a307e9753eef0843209cf9637e29fe

```

## Requirements

You may use a python virtual environment if you wish. Using bash it may look like so :
- `python -m venv .venv; source .venv/bin/activate; pip install -r requirements.txt`
- `./keygen sk.key`
- `...`
- `deactivate`

## Debug

Set DEBUG=True in lib/deps/KEM.py for debug messages.

# Useful Info

## Private key format

- 32 bytes for private key, followed by LS_bytes bytes for the extra randomness, followed by 32 bytes of public key and 32 bytes of public key hash, little endian for everything.

## Symmetric encryption protocol

- ChaCha20 is used here. Evidently, the symmetric encryption algorithm can be swapped with other ones (AES, Camellia, Blowfish, ...). To use Camellia for example, look at the comment in lib/deps/KEM.py. It is less trivial to make an example where the encapsulation is messed with using Camellia (decryption of message can fail to an error), hence ChaCha20 is used here.

- SHAKE128 is used for all hashes. The size of the output differs each time (32, 64 and 16 bytes)