import hashlib


def test_md5_vector():
    assert hashlib.md5(b"").hexdigest() == "d41d8cd98f00b204e9800998ecf8427e"


def test_sha1_vector():
    assert hashlib.sha1(b"").hexdigest() == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
