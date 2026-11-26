"""알고리즘 지식 베이스.

각 알고리즘이 어떤 암호 기본요소(primitive)인지, 양자 내성이 있는지,
NIST 기준으로 어떤 상태인지를 한곳에 모은다. 판정 기준을 코드가 아니라
데이터로 두는 것 자체가 '암호 민첩성' 원칙이다 — 기준이 바뀌면 이 표만 고친다.

status 값
  broken              고전 컴퓨터로도 안전하지 않음 (즉시 교체)
  quantum-vulnerable  Shor 알고리즘에 깨지는 공개키 (NIST IR 8547: 2030 이후 비권고, 2035 이후 금지)
  hybrid              고전 + PQC 하이브리드 (전환기 권장)
  pqc                 양자내성 알고리즘 (NIST 표준 또는 KpqC)
  pqc-draft           표준화 진행 중인 양자내성 알고리즘
  symmetric-ok        양자 환경에서도 충분한 대칭키·해시 (AES-256, SHA-384 등)
  symmetric-weak      당장은 허용되나 양자 여유가 작은 대칭키·해시 (AES-128, SHA-256 등)
  unknown             판정 불가
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

BROKEN = "broken"
QV = "quantum-vulnerable"
HYBRID = "hybrid"
PQC = "pqc"
PQC_DRAFT = "pqc-draft"
SYM_OK = "symmetric-ok"
SYM_WEAK = "symmetric-weak"
UNKNOWN = "unknown"

STATUS_LABEL_KO = {
    BROKEN: "즉시 교체 (취약)",
    QV: "양자 취약 공개키",
    HYBRID: "하이브리드 (전환기 권장)",
    PQC: "양자내성",
    PQC_DRAFT: "양자내성 (표준화 진행 중)",
    SYM_OK: "대칭키·해시 충분",
    SYM_WEAK: "대칭키·해시 상향 권장",
    UNKNOWN: "판정 불가",
}


@dataclass(frozen=True)
class AlgInfo:
    family: str                      # 정규화된 이름 (예: "RSA", "ML-KEM")
    primitive: str                   # CycloneDX primitive enum
    status: str
    nist_qsl: int = 0                # CycloneDX nistQuantumSecurityLevel (0 = 양자 취약)
    oid: Optional[str] = None
    note: str = ""
    functions: tuple = field(default_factory=tuple)


# 고정 파라미터 이름 → 정보.  가변 파라미터(키 길이 등)는 classify()에서 처리.
_CATALOG: dict[str, AlgInfo] = {
    # ---- 양자 취약 공개키 -------------------------------------------------
    "RSA": AlgInfo("RSA", "pke", QV, 0, "1.2.840.113549.1.1.1"),
    "DSA": AlgInfo("DSA", "signature", QV, 0, "1.2.840.10040.4.1"),
    "DH": AlgInfo("DH", "key-agree", QV, 0, "1.2.840.113549.1.3.1"),
    "ECDH": AlgInfo("ECDH", "key-agree", QV, 0, "1.3.132.1.12"),
    "ECDSA": AlgInfo("ECDSA", "signature", QV, 0, "1.2.840.10045.2.1"),
    "EC": AlgInfo("EC", "pke", QV, 0, "1.2.840.10045.2.1", "타원곡선 키"),
    "Ed25519": AlgInfo("Ed25519", "signature", QV, 0, "1.3.101.112"),
    "Ed448": AlgInfo("Ed448", "signature", QV, 0, "1.3.101.113"),
    "X25519": AlgInfo("X25519", "key-agree", QV, 0, "1.3.101.110"),
    "X448": AlgInfo("X448", "key-agree", QV, 0, "1.3.101.111"),
    # ---- 하이브리드 -------------------------------------------------------
    "X25519MLKEM768": AlgInfo("X25519MLKEM768", "kem", HYBRID, 3, None, "X25519 + ML-KEM-768 (TLS 하이브리드)"),
    "SecP256r1MLKEM768": AlgInfo("SecP256r1MLKEM768", "kem", HYBRID, 3, None, "P-256 + ML-KEM-768"),
    "SecP384r1MLKEM1024": AlgInfo("SecP384r1MLKEM1024", "kem", HYBRID, 5, None, "P-384 + ML-KEM-1024"),
    # ---- NIST PQC ---------------------------------------------------------
    "ML-KEM-512": AlgInfo("ML-KEM", "kem", PQC, 1, "2.16.840.1.101.3.4.4.1", "FIPS 203"),
    "ML-KEM-768": AlgInfo("ML-KEM", "kem", PQC, 3, "2.16.840.1.101.3.4.4.2", "FIPS 203 (기본 권장)"),
    "ML-KEM-1024": AlgInfo("ML-KEM", "kem", PQC, 5, "2.16.840.1.101.3.4.4.3", "FIPS 203"),
    "ML-KEM": AlgInfo("ML-KEM", "kem", PQC, 3, None, "FIPS 203"),
    "ML-DSA-44": AlgInfo("ML-DSA", "signature", PQC, 2, "2.16.840.1.101.3.4.3.17", "FIPS 204"),
    "ML-DSA-65": AlgInfo("ML-DSA", "signature", PQC, 3, "2.16.840.1.101.3.4.3.18", "FIPS 204"),
    "ML-DSA-87": AlgInfo("ML-DSA", "signature", PQC, 5, "2.16.840.1.101.3.4.3.19", "FIPS 204"),
    "ML-DSA": AlgInfo("ML-DSA", "signature", PQC, 3, None, "FIPS 204"),
    "SLH-DSA": AlgInfo("SLH-DSA", "signature", PQC, 1, None, "FIPS 205"),
    "LMS": AlgInfo("LMS", "signature", PQC, 3, None, "NIST SP 800-208 (상태 기반 해시 서명)"),
    "XMSS": AlgInfo("XMSS", "signature", PQC, 3, None, "NIST SP 800-208 (상태 기반 해시 서명)"),
    "FN-DSA": AlgInfo("FN-DSA", "signature", PQC_DRAFT, 1, None, "FIPS 206 초안 (Falcon)"),
    "HQC": AlgInfo("HQC", "kem", PQC_DRAFT, 1, None, "NIST 추가 선정 KEM (최종 표준 예정)"),
    # ---- KpqC (한국형 양자내성암호) --------------------------------------
    "SMAUG-T": AlgInfo("SMAUG-T", "kem", PQC, 1, None, "KpqC 최종 선정 KEM"),
    "NTRU+": AlgInfo("NTRU+", "kem", PQC, 1, None, "KpqC 최종 선정 KEM"),
    "HAETAE": AlgInfo("HAETAE", "signature", PQC, 2, None, "KpqC 최종 선정 서명"),
    "AIMer": AlgInfo("AIMer", "signature", PQC, 1, None, "KpqC 최종 선정 서명"),
    # ---- 대칭키 -----------------------------------------------------------
    "AES-128": AlgInfo("AES", "block-cipher", SYM_WEAK, 1, None, "양자 여유가 작음 → AES-256 권장"),
    "AES-192": AlgInfo("AES", "block-cipher", SYM_OK, 3),
    "AES-256": AlgInfo("AES", "block-cipher", SYM_OK, 5),
    "AES": AlgInfo("AES", "block-cipher", SYM_WEAK, 1, None, "키 길이 미확인 → AES-256 확인 필요"),
    "ChaCha20-Poly1305": AlgInfo("ChaCha20-Poly1305", "ae", SYM_OK, 5),
    "ChaCha20": AlgInfo("ChaCha20", "stream-cipher", SYM_OK, 5),
    "ARIA": AlgInfo("ARIA", "block-cipher", SYM_WEAK, 1, None, "키 길이 확인 필요 (256비트 권장)"),
    "SEED": AlgInfo("SEED", "block-cipher", SYM_WEAK, 1, None, "128비트 블록암호 → 상향 검토"),
    "LEA": AlgInfo("LEA", "block-cipher", SYM_WEAK, 1, None, "키 길이 확인 필요 (256비트 권장)"),
    "DES": AlgInfo("DES", "block-cipher", BROKEN, 0, None, "56비트 키 — 고전적으로도 취약"),
    "3DES": AlgInfo("3DES", "block-cipher", BROKEN, 0, None, "NIST 사용 금지 (SP 800-131A)"),
    "RC4": AlgInfo("RC4", "stream-cipher", BROKEN, 0, None, "고전적으로도 취약"),
    "Blowfish": AlgInfo("Blowfish", "block-cipher", BROKEN, 0, None, "64비트 블록 — 교체 권장"),
    # ---- 해시·MAC --------------------------------------------------------
    "MD5": AlgInfo("MD5", "hash", BROKEN, 0, None, "충돌 공격 가능 — 고전적으로도 취약"),
    "SHA-1": AlgInfo("SHA-1", "hash", BROKEN, 0, None, "충돌 공격 가능 — 서명·무결성 용도 금지"),
    "SHA-224": AlgInfo("SHA-224", "hash", SYM_WEAK, 1),
    "SHA-256": AlgInfo("SHA-256", "hash", SYM_WEAK, 2, None, "현재 허용, 장기적으로 SHA-384 이상 권장"),
    "SHA-384": AlgInfo("SHA-384", "hash", SYM_OK, 4),
    "SHA-512": AlgInfo("SHA-512", "hash", SYM_OK, 5),
    "SHA3-256": AlgInfo("SHA3-256", "hash", SYM_WEAK, 2),
    "SHA3-384": AlgInfo("SHA3-384", "hash", SYM_OK, 4),
    "SHA3-512": AlgInfo("SHA3-512", "hash", SYM_OK, 5),
    "SHAKE256": AlgInfo("SHAKE256", "xof", SYM_OK, 5),
    "HMAC": AlgInfo("HMAC", "mac", SYM_OK, 3),
}

_ALIASES = {
    "rsa": "RSA", "rsaencryption": "RSA", "rsa-oaep": "RSA", "rsa-pss": "RSA", "rsassa-pkcs1-v1_5": "RSA",
    "dsa": "DSA", "dh": "DH", "dhe": "DH", "diffiehellman": "DH", "ffdhe": "DH",
    "ecdh": "ECDH", "ecdhe": "ECDH", "ecdsa": "ECDSA", "ec": "EC",
    "ed25519": "Ed25519", "ed448": "Ed448", "x25519": "X25519", "x448": "X448",
    "x25519mlkem768": "X25519MLKEM768", "secp256r1mlkem768": "SecP256r1MLKEM768",
    "secp384r1mlkem1024": "SecP384r1MLKEM1024",
    "mlkem": "ML-KEM", "ml-kem": "ML-KEM", "kyber": "ML-KEM",
    "mlkem512": "ML-KEM-512", "mlkem768": "ML-KEM-768", "mlkem1024": "ML-KEM-1024",
    "mldsa": "ML-DSA", "ml-dsa": "ML-DSA", "dilithium": "ML-DSA",
    "mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87",
    "slhdsa": "SLH-DSA", "slh-dsa": "SLH-DSA", "sphincs+": "SLH-DSA", "sphincs": "SLH-DSA",
    "falcon": "FN-DSA", "fndsa": "FN-DSA", "fn-dsa": "FN-DSA", "hqc": "HQC",
    "lms": "LMS", "xmss": "XMSS",
    "smaug-t": "SMAUG-T", "smaugt": "SMAUG-T", "ntru+": "NTRU+", "ntruplus": "NTRU+",
    "haetae": "HAETAE", "aimer": "AIMer",
    "aes": "AES", "aes128": "AES-128", "aes192": "AES-192", "aes256": "AES-256",
    "chacha20-poly1305": "ChaCha20-Poly1305", "chacha20poly1305": "ChaCha20-Poly1305", "chacha20": "ChaCha20",
    "aria": "ARIA", "seed": "SEED", "lea": "LEA",
    "des": "DES", "3des": "3DES", "des3": "3DES", "desede": "3DES", "tripledes": "3DES", "des-ede3": "3DES",
    "rc4": "RC4", "arc4": "RC4", "arcfour": "RC4", "blowfish": "Blowfish",
    "md5": "MD5", "sha1": "SHA-1", "sha-1": "SHA-1",
    "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512",
    "sha-224": "SHA-224", "sha-256": "SHA-256", "sha-384": "SHA-384", "sha-512": "SHA-512",
    "sha3-256": "SHA3-256", "sha3-384": "SHA3-384", "sha3-512": "SHA3-512",
    "sha3_256": "SHA3-256", "sha3_384": "SHA3-384", "sha3_512": "SHA3-512", "shake256": "SHAKE256",
    "hmac": "HMAC",
}

# 곡선 이름 정규화
CURVES = {
    "secp256r1": "P-256", "prime256v1": "P-256", "p256": "P-256", "p-256": "P-256",
    "secp384r1": "P-384", "p384": "P-384", "p-384": "P-384",
    "secp521r1": "P-521", "p521": "P-521", "p-521": "P-521",
    "secp256k1": "secp256k1", "brainpoolp256r1": "brainpoolP256r1",
}


def normalize(name: str) -> Optional[str]:
    """알고리즘 이름을 카탈로그 키로 정규화. 모르면 None."""
    if not name:
        return None
    if name in _CATALOG:
        return name
    k = name.strip().lower()
    for cand in (k, k.replace("_", "-"), k.replace("-", "").replace("_", "")):
        if cand in _ALIASES:
            return _ALIASES[cand]
    return None


@dataclass
class Classified:
    key: str            # 자산 이름 (예: "RSA-2048", "AES-256-GCM")
    family: str
    primitive: str
    status: str
    nist_qsl: int
    parameter: Optional[str] = None
    curve: Optional[str] = None
    mode: Optional[str] = None
    oid: Optional[str] = None
    note: str = ""


def classify(name: str, size: Optional[int] = None, curve: Optional[str] = None,
             mode: Optional[str] = None) -> Classified:
    """이름 + 선택적 키 길이/곡선/모드 → 판정 결과."""
    base = normalize(name)
    if base is None:
        return Classified(name, name, "unknown", UNKNOWN, 0, note="카탈로그에 없는 알고리즘")

    # 키 길이가 붙은 AES
    if base == "AES" and size in (128, 192, 256):
        base = f"AES-{size}"
    info = _CATALOG[base]
    status, note = info.status, info.note
    parameter = None
    if size and info.family in ("RSA", "DSA", "DH"):
        parameter = str(size)
        if size < 2048:
            status, note = BROKEN, f"{size}비트 — 고전적으로도 취약 (최소 2048비트)"
    elif info.family == "AES" and size:
        parameter = str(size)

    curve_n = CURVES.get(curve.lower(), curve) if curve else None
    key = info.family if info.family not in ("AES",) else base
    if base.startswith(("ML-KEM-", "ML-DSA-")):
        key = base
    if parameter and info.family in ("RSA", "DSA", "DH"):
        key = f"{info.family}-{parameter}"
    if curve_n:
        key = f"{key}-{curve_n}"
    if mode:
        mode_u = mode.upper()
        key = f"{key}-{mode_u}"
        if mode_u == "ECB":
            status, note = BROKEN, "ECB 모드 — 패턴이 드러남, 사용 금지"
    return Classified(key=key, family=info.family, primitive=info.primitive, status=status,
                      nist_qsl=info.nist_qsl, parameter=parameter, curve=curve_n,
                      mode=mode.upper() if mode else None, oid=info.oid, note=note)


STATUS_ORDER = [BROKEN, QV, SYM_WEAK, UNKNOWN, PQC_DRAFT, HYBRID, SYM_OK, PQC]
