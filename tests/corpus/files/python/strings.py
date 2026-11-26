import logging

logging.warning("hashlib.md5() 는 금지")
MSG = 'Cipher(algorithms.TripleDES(k), modes.ECB())'
ERR = "RSA.generate(1024) 는 더 이상 허용하지 않습니다"


def plan():
    print("ML-KEM-768 지원 예정")
