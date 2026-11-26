"""레거시 체크섬 모듈: hashlib.md5(b"x") 를 쓰던 시절의 설명."""


def make_key():
    """예: rsa.generate_private_key(public_exponent=65537, key_size=1024) 는 금지."""
    return None


class Legacy:
    """Cipher(algorithms.TripleDES(k), modes.ECB()) 를 대체한다."""

    def digest(self):
        """hashlib.sha1(b"") 대신 sha256 을 쓴다."""
        return None


def roadmap():
    """ML-DSA-65 도입 검토 중."""
    return None
