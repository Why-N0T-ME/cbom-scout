import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, dh, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def build(k, iv):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )
    params = dh.generate_parameters(
        generator=2,
        key_size=1024,
    )
    cipher = Cipher(
        algorithms.AES(k),
        modes.CBC(iv),
    )
    eck = ec.generate_private_key(
        ec.SECP384R1()
    )
    h = hashlib.new(
        "sha1"
    )
    return key, params, cipher, eck, h
