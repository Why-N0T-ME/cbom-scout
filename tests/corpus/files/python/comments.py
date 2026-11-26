import hashlib
from Crypto.PublicKey import RSA

# hashlib.md5(data) 는 쓰지 말 것 — 아래 sha256 으로 교체함
# old = RSA.generate(1024)
value = 1  # 예전 코드: hashlib.sha1(b"")


def current(data):
    return hashlib.sha256(data).hexdigest()
