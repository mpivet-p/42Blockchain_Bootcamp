#!/usr/bin/python

import os
import hashlib
import ecdsa
from Crypto.Hash import keccak

def get_private_key():
    random_number = os.urandom(2048)
    return (hashlib.sha256(random_number).digest())

def get_public_key(priv_key):
    key = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1).verifying_key
    return (key.to_string())

def get_address(pub_key):
    k = keccak.new(digest_bits=256)
    k.update(pub_key)
    hash_pub_key = k.hexdigest()
    return (hash_pub_key[24:])

if __name__ == "__main__":
    priv_key = get_private_key()
    pub_key = get_public_key(priv_key)
    address = get_address(pub_key)
    print("======== Private Key ========")
    print("0x" + priv_key.hex())
    print("======== Public Key ========")
    print("0x" + pub_key.hex())
    print("======== Address ========")
    print("0x" + address)
