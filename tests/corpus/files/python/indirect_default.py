import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA


def digest(data, alg="md5"):
    return hashlib.new(alg, data)


def legacy_key(bits=1024):
    return RSA.generate(bits)


def other_key(size=1024):
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


def main():
    digest(b"x")
    legacy_key()
    other_key()
