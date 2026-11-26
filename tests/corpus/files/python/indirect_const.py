import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, dh, ec
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA

HASH = "sha1"
BITS = 1024
KEY_SIZE = 1024
CURVE = ec.SECP256R1()
MODE = DES3.MODE_ECB
DH_BITS = 1024
BASE_ALG = "sha512"
ALG = BASE_ALG


def a(data):
    return hashlib.new(HASH, data)


def b():
    return RSA.generate(BITS)


def c(data):
    alg = "md5"
    return hashlib.new(alg, data)


def d():
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)


def e():
    return ec.generate_private_key(CURVE)


def f(k):
    return DES3.new(k, MODE)


def g():
    return dh.generate_parameters(generator=2, key_size=DH_BITS)


def h(data):
    return hashlib.new(ALG, data)
