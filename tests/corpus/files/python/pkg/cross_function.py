import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA

from .consts import LEGACY_HASH


def make_hash(alg, data):
    return hashlib.new(alg, data)


def make_key(bits):
    return RSA.generate(bits)


class Signer:
    ALG = "md5"

    def digest(self, data):
        return hashlib.new(self.ALG, data)


def wrap(**kw):
    return rsa.generate_private_key(**kw)


def use():
    make_hash("sha1", b"")
    make_key(1024)
    wrap(public_exponent=65537, key_size=1024)
    return hashlib.new(LEGACY_HASH, b"")
