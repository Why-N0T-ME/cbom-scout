"""데모: 결제 서비스 (의도적으로 오래된 암호를 섞어 둔 예제)."""
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def make_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_device_key():
    return ec.generate_private_key(ec.SECP256R1())


def legacy_checksum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()          # 취약: MD5


def card_token(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encrypt_legacy(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()   # 취약: ECB
    return enc.update(data) + enc.finalize()


def encrypt_record(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, data, None)
