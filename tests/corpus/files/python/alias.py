import hashlib as hl
from hashlib import md5, sha1 as s1
from cryptography.hazmat.primitives.asymmetric import rsa as r
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as G


def run(k):
    a = hl.sha512(b"").hexdigest()
    b = md5(b"").hexdigest()
    c = s1(b"").hexdigest()
    key = r.generate_private_key(public_exponent=65537, key_size=1024)
    g = G(k)
    return a, b, c, key, g
