import hashlib


def file_checksum(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def cache_key(key):
    return "cache:" + hashlib.md5(key.encode()).hexdigest()


aes_theme = "dark"
des = "description"
