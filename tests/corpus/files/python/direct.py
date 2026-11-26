import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from Crypto.Cipher import DES3, ARC4
from Crypto.PublicKey import RSA


def checksums(data):
    a = hashlib.md5(data).hexdigest()
    b = hashlib.sha1(data).hexdigest()
    c = hashlib.sha256(data).hexdigest()
    return a, b, c


def keys():
    k1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    k2 = ec.generate_private_key(ec.SECP256R1())
    k3 = RSA.generate(1024)
    return k1, k2, k3


def ciphers(k, iv):
    g = AESGCM(k)
    c = ChaCha20Poly1305(k)
    d = DES3.new(k, DES3.MODE_CBC, iv)
    r = ARC4.new(k)
    return g, c, d, r


def digest_obj():
    return hashes.SHA384()


def more(k, msg):
    import hmac
    from cryptography.hazmat.primitives.asymmetric import dsa
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    sig = ec.ECDSA(hashes.SHA256())
    xk = X25519PrivateKey.generate()
    dk = dsa.generate_private_key(key_size=1024)
    ccm = AESCCM(k)
    mac = hmac.new(k, msg, hashlib.sha512)
    return sig, xk, dk, ccm, mac
