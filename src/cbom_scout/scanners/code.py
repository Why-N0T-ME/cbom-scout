"""소스코드·설정 파일 정적 스캐너.

언어별 암호 API 호출 패턴을 정규식으로 찾아 알고리즘·키 길이·곡선·모드를 뽑는다.
정확한 데이터 흐름 분석은 하지 않으므로 '어디에 무엇이 쓰이는지'를 빠르게
훑는 1차 인벤토리 용도다. 언어별 정밀 분석이 필요하면 CBOMkit(sonar-cryptography)
결과를 `cbom-scout merge` 로 합치면 된다.
"""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Optional

from ..inventory import Inventory

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build",
             "target", ".tox", ".mypy_cache", ".pytest_cache", "vendor", "third_party", ".idea"}
MAX_FILE_BYTES = 2_000_000

LANG_EXT = {
    "python": {".py"},
    "java": {".java", ".kt", ".kts", ".scala"},
    "go": {".go"},
    "js": {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"},
    "c": {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"},
    "csharp": {".cs"},
    "config": {".conf", ".cfg", ".cnf", ".ini", ".yaml", ".yml", ".toml", ".properties", ".xml"},
}
CONFIG_NAMES = {"sshd_config", "ssh_config", "nginx.conf", "httpd.conf", "ssl.conf", "openssl.cnf"}
ALL_CODE = set().union(*[v for k, v in LANG_EXT.items() if k != "config"])

MODES = {"ecb", "cbc", "gcm", "ccm", "ctr", "cfb", "ofb", "xts", "siv"}


@dataclass
class Hit:
    name: str
    function: Optional[str] = None
    size: Optional[int] = None
    curve: Optional[str] = None
    mode: Optional[str] = None


# ------------------------------------------------------------------ 이름 해석기
def pqc_name(s: str) -> str:
    t = s.lower()
    m = re.match(r"kyber-?(512|768|1024)", t)
    if m:
        return f"ML-KEM-{m.group(1)}"
    m = re.match(r"dilithium-?([235])", t)
    if m:
        return {"2": "ML-DSA-44", "3": "ML-DSA-65", "5": "ML-DSA-87"}[m.group(1)]
    if t.startswith("slh-dsa") or t.startswith("sphincs"):
        return "SLH-DSA"
    if t.startswith("falcon") or t.startswith("fn-dsa"):
        return "FN-DSA"
    if t.startswith("smaug"):
        return "SMAUG-T"
    if t.startswith("haetae"):
        return "HAETAE"
    if t.startswith("aimer"):
        return "AIMer"
    if t.startswith("ntru+") or t.startswith("ntruplus"):
        return "NTRU+"
    return s.upper() if t.startswith(("ml-kem", "ml-dsa")) else s


def parse_cipher_spec(spec: str, function: str = "encrypt") -> list[Hit]:
    """'AES/GCM/NoPadding', 'aes-256-gcm', 'aes_128_cbc', 'DESede/CBC/...' 등."""
    toks = [t for t in re.split(r"[/_\-\s]", spec.lower()) if t]
    if not toks:
        return []
    head = toks[0]
    mode = next((t for t in toks[1:] if t in MODES), None)
    size = next((int(t) for t in toks[1:] if t in ("128", "192", "256")), None)
    m = re.match(r"(aes|aria|lea)(128|192|256)$", head)
    if m:
        head, size = m.group(1), int(m.group(2))
    if head in ("aes", "aria", "lea", "seed"):
        return [Hit(head.upper(), function, size=size, mode=mode)]
    if head in ("desede", "tripledes", "3des", "des3") or (head == "des" and "ede3" in toks):
        return [Hit("3DES", function, mode=mode)]
    if head == "des":
        return [Hit("DES", function, mode=mode)]
    if head in ("rc4", "arc4", "arcfour"):
        return [Hit("RC4", function)]
    if head == "blowfish" or head == "bf":
        return [Hit("Blowfish", function, mode=mode)]
    if head == "chacha20":
        return [Hit("ChaCha20-Poly1305" if "poly1305" in toks else "ChaCha20", function)]
    if head == "rsa":
        return [Hit("RSA", function)]
    return []


def parse_sig_spec(spec: str) -> list[Hit]:
    """'SHA256withRSA', 'SHA384withECDSA', 'Ed25519', 'ML-DSA-65', 'RSASSA-PSS'."""
    m = re.match(r"(?i)(sha3?-?\d+|md5|sha1)with(rsa|ecdsa|dsa|rsaandmgf1)", spec)
    if m:
        h, a = m.group(1), m.group(2).lower()
        hname = h.upper().replace("SHA3", "SHA3-").replace("SHA", "SHA-").replace("SHA-3-", "SHA3-").replace("--", "-")
        alg = "RSA" if a.startswith("rsa") else a.upper()
        return [Hit(hname, "digest"), Hit(alg, "sign")]
    s = spec.lower()
    if s.startswith(("rsassa", "rsa")):
        return [Hit("RSA", "sign")]
    if s.startswith(("ml-dsa", "slh-dsa", "dilithium", "falcon", "sphincs", "haetae", "aimer")):
        return [Hit(pqc_name(spec), "sign")]
    if s in ("ed25519", "ed448", "ecdsa", "dsa"):
        return [Hit(spec, "sign")]
    return []


SSH_KEX = {
    "curve25519-sha256": ("X25519", None), "curve25519-sha256@libssh.org": ("X25519", None),
    "ecdh-sha2-nistp256": ("ECDH", "P-256"), "ecdh-sha2-nistp384": ("ECDH", "P-384"),
    "ecdh-sha2-nistp521": ("ECDH", "P-521"),
    "diffie-hellman-group1-sha1": ("DH", 1024), "diffie-hellman-group14-sha1": ("DH", 2048),
    "diffie-hellman-group14-sha256": ("DH", 2048), "diffie-hellman-group16-sha512": ("DH", 4096),
    "diffie-hellman-group18-sha512": ("DH", 8192), "diffie-hellman-group-exchange-sha256": ("DH", None),
    "mlkem768x25519-sha256": ("X25519MLKEM768", None),
    "sntrup761x25519-sha512": ("X25519MLKEM768", "sntrup"),  # 하이브리드 (NTRU Prime)
    "sntrup761x25519-sha512@openssh.com": ("X25519MLKEM768", "sntrup"),
}
SSH_HOSTKEY = {
    "ssh-rsa": ("RSA", "SHA-1"), "rsa-sha2-256": ("RSA", "SHA-256"), "rsa-sha2-512": ("RSA", "SHA-512"),
    "ssh-ed25519": ("Ed25519", None), "ssh-dss": ("DSA", "SHA-1"),
    "ecdsa-sha2-nistp256": ("ECDSA", "P-256"), "ecdsa-sha2-nistp384": ("ECDSA", "P-384"),
    "ecdsa-sha2-nistp521": ("ECDSA", "P-521"),
}


def _ssh_list(m: re.Match, *_):
    hits = []
    for item in m.group("list").split(","):
        item = item.strip().lstrip("+-^")
        if item in SSH_KEX:
            alg, extra = SSH_KEX[item]
            if extra == "sntrup":
                hits.append(Hit("sntrup761x25519", "keyderive"))
                continue
            if isinstance(extra, int):
                hits.append(Hit(alg, "keyderive", size=extra))
            else:
                hits.append(Hit(alg, "keyderive", curve=extra))
        elif item in SSH_HOSTKEY:
            alg, extra = SSH_HOSTKEY[item]
            if extra and extra.startswith("SHA"):
                hits += [Hit(alg, "sign"), Hit(extra, "digest")]
            else:
                hits.append(Hit(alg, "sign", curve=extra))
    return hits


def _lookahead(lines: list[str], idx: int, pattern: str, n: int = 6) -> Optional[str]:
    for ln in lines[idx: idx + n]:
        mm = re.search(pattern, ln)
        if mm:
            return mm.group(1)
    return None


Handler = Callable[[re.Match, list, int], list]


def _group(function: str, group: str = "alg", size_group: str | None = None,
           curve_group: str | None = None) -> Handler:
    def h(m, lines, idx):
        size = m.group(size_group) if size_group and m.group(size_group) else None
        curve = m.group(curve_group) if curve_group and m.group(curve_group) else None
        return [Hit(m.group(group), function, size=int(size) if size else None, curve=curve)]
    return h


def _java_keypair(m, lines, idx):
    alg = m.group("alg")
    size = _lookahead(lines, idx, r"\.initialize\(\s*(\d{3,5})")
    curve = _lookahead(lines, idx, r"ECGenParameterSpec\(\s*\"([\w-]+)\"")
    a = alg.upper()
    if a in ("EC",):
        alg = "EC"
    return [Hit(pqc_name(alg) if a.startswith(("ML-", "SLH")) else alg, "keygen",
                size=int(size) if size else None, curve=curve)]


def _java_cipher(m, lines, idx):
    spec = m.group("spec")
    hits = parse_cipher_spec(spec)
    # JCA 는 "AES" 처럼 모드를 생략하면 기본값 ECB/PKCS5Padding 을 쓴다
    if "/" not in spec:
        for h in hits:
            if h.name in ("AES", "DES", "3DES", "ARIA", "SEED", "LEA", "Blowfish") and not h.mode:
                h.mode = "ecb"
    return hits


def _js_keypair(m, lines, idx):
    alg = m.group("alg")
    size = _lookahead(lines, idx, r"modulusLength\s*:\s*(\d{3,5})")
    curve = _lookahead(lines, idx, r"namedCurve\s*:\s*['\"]([\w-]+)['\"]")
    return [Hit(alg, "keygen", size=int(size) if size else None, curve=curve)]


def _webcrypto(m, lines, idx):
    name = m.group("alg")
    if name.upper().startswith("AES"):
        length = _lookahead(lines, idx, r"length\s*:\s*(128|192|256)", 4)
        return [Hit("AES", "encrypt", size=int(length) if length else None, mode=name.split("-")[1])]
    size = _lookahead(lines, idx, r"modulusLength\s*:\s*(\d{3,5})", 4)
    curve = _lookahead(lines, idx, r"namedCurve\s*:\s*['\"]([\w-]+)['\"]", 4)
    fn = "sign" if name.upper() in ("RSASSA-PKCS1-V1_5", "RSA-PSS", "ECDSA", "ED25519") else "encrypt"
    if name.upper() in ("ECDH", "X25519"):
        fn = "keyderive"
    base = "RSA" if name.upper().startswith("RSA") else name
    return [Hit(base, fn, size=int(size) if size else None, curve=curve)]


def _go_hash(m, lines, idx):
    pkg, fn = m.group("pkg"), m.group("fn")
    if pkg == "sha512" and fn == "Sum384":
        return [Hit("SHA-384", "digest")]
    if pkg == "sha256" and fn == "Sum224":
        return [Hit("SHA-224", "digest")]
    return [Hit({"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}[pkg], "digest")]


def _go_tls_curve(m, lines, idx):
    c = m.group("alg")
    mapping = {"CurveP256": ("ECDH", "P-256"), "CurveP384": ("ECDH", "P-384"), "CurveP521": ("ECDH", "P-521"),
               "X25519": ("X25519", None), "X25519MLKEM768": ("X25519MLKEM768", None),
               "SecP256r1MLKEM768": ("SecP256r1MLKEM768", None), "SecP384r1MLKEM1024": ("SecP384r1MLKEM1024", None)}
    alg, curve = mapping[c]
    return [Hit(alg, "keyderive", curve=curve)]


def _c_evp_cipher(m, lines, idx):
    return parse_cipher_spec(m.group("spec"))


PQC_STR = (r"[\"'](?P<alg>ML-KEM-(?:512|768|1024)|ML-DSA-(?:44|65|87)|SLH-DSA[\w-]*|"
           r"X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024|Kyber-?\d+|Dilithium-?\d|Falcon-\d+|"
           r"SPHINCS\+[\w-]*|SMAUG-T\d*|HAETAE\d*|AIMer[\w-]*|NTRU\+[\w-]*|HQC-\d+)[\"']")

# (적용 대상 확장자 집합, 정규식, 처리기)
RULES: list[tuple[set, re.Pattern, Handler]] = []


def rule(exts: Iterable[str], pattern: str, handler: Handler, flags: int = 0) -> None:
    RULES.append((set(exts), re.compile(pattern, flags), handler))


PY, JAVA, GO, JS, C, CS, CFG = (LANG_EXT[k] for k in ("python", "java", "go", "js", "c", "csharp", "config"))

# ---- Python (cryptography, pycryptodome, hashlib) -------------------------------
rule(PY, r"rsa\.generate_private_key\((?:[^)]*key_size\s*=\s*(?P<size>\d+))?",
     lambda m, l, i: [Hit("RSA", "keygen", size=int(m.group("size")) if m.group("size") else None)])
rule(PY, r"\bRSA\.generate\(\s*(?P<size>\d+)", lambda m, l, i: [Hit("RSA", "keygen", size=int(m.group("size")))])
rule(PY, r"dsa\.generate_private_key\((?:[^)]*key_size\s*=\s*(?P<size>\d+))?",
     lambda m, l, i: [Hit("DSA", "keygen", size=int(m.group("size")) if m.group("size") else None)])
rule(PY, r"dh\.generate_parameters\((?:[^)]*key_size\s*=\s*(?P<size>\d+))?",
     lambda m, l, i: [Hit("DH", "keygen", size=int(m.group("size")) if m.group("size") else None)])
rule(PY, r"ec\.generate_private_key\(\s*ec\.(?P<curve>\w+)", lambda m, l, i: [Hit("EC", "keygen", curve=m.group("curve"))])
rule(PY, r"\bec\.ECDSA\(", lambda m, l, i: [Hit("ECDSA", "sign")])
rule(PY, r"\bec\.ECDH\(\)", lambda m, l, i: [Hit("ECDH", "keyderive")])
rule(PY, r"\b(?P<alg>Ed25519|Ed448|X25519|X448)Private(?:Key)?\b", _group("keygen"))
rule(PY, r"\bhashlib\.(?P<alg>md5|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_384|sha3_512)\b", _group("digest"))
rule(PY, r"\bhashlib\.new\(\s*['\"](?P<alg>[\w-]+)['\"]", _group("digest"))
rule(PY, r"\bhashes\.(?P<alg>MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3_256|SHA3_384|SHA3_512)\(", _group("digest"))
rule(PY, r"\balgorithms\.(?P<alg>AES|AES128|AES256|TripleDES|ARC4|Blowfish|ChaCha20)\(",
     lambda m, l, i: parse_cipher_spec(m.group("alg").replace("TripleDES", "3des")))
rule(PY, r"\bmodes\.ECB\(", lambda m, l, i: [Hit("AES", "encrypt", mode="ECB")])
rule(PY, r"\b(?P<alg>AESGCM|AESCCM|ChaCha20Poly1305)\(",
     lambda m, l, i: [Hit("ChaCha20-Poly1305", "encrypt")] if m.group("alg").startswith("ChaCha")
     else [Hit("AES", "encrypt", mode=m.group("alg")[3:])])
rule(PY, r"\b(?P<alg>DES3|DES|ARC4|Blowfish|AES)\.new\([^)]*?(?:MODE_(?P<mode>[A-Z]+))?\)",
     lambda m, l, i: parse_cipher_spec(m.group("alg").replace("DES3", "3des") + ("-" + m.group("mode") if m.group("mode") else "")))

# ---- Java / Kotlin (JCA) --------------------------------------------------------
rule(JAVA, r"KeyPairGenerator\.getInstance\(\s*\"(?P<alg>[\w-]+)\"", _java_keypair)
rule(JAVA, r"Cipher\.getInstance\(\s*\"(?P<spec>[^\"]+)\"", _java_cipher)
rule(JAVA, r"MessageDigest\.getInstance\(\s*\"(?P<alg>[\w-]+)\"", _group("digest"))
rule(JAVA, r"Signature\.getInstance\(\s*\"(?P<spec>[\w-]+)\"", lambda m, l, i: parse_sig_spec(m.group("spec")))
rule(JAVA, r"KeyAgreement\.getInstance\(\s*\"(?P<alg>[\w-]+)\"", _group("keyderive"))
rule(JAVA, r"\bKEM\.getInstance\(\s*\"(?P<alg>[\w-]+)\"", lambda m, l, i: [Hit(pqc_name(m.group("alg")), "encapsulate")])
rule(JAVA, r"Mac\.getInstance\(\s*\"Hmac(?P<alg>\w+)\"", lambda m, l, i: [Hit("HMAC", "tag"), Hit(m.group("alg"), "digest")])
rule(JAVA, r"KeyGenerator\.getInstance\(\s*\"(?P<spec>[\w-]+)\"", lambda m, l, i: parse_cipher_spec(m.group("spec"), "keygen"))

# ---- Go -------------------------------------------------------------------------
rule(GO, r"\brsa\.GenerateKey\([^,]+,\s*(?P<size>\d+)", lambda m, l, i: [Hit("RSA", "keygen", size=int(m.group("size")))])
rule(GO, r"\becdsa\.GenerateKey\(\s*elliptic\.(?P<curve>P\d+)\(", lambda m, l, i: [Hit("ECDSA", "keygen", curve=m.group("curve"))])
rule(GO, r"\becdh\.(?P<curve>P256|P384|P521)\(\)", lambda m, l, i: [Hit("ECDH", "keyderive", curve=m.group("curve"))])
rule(GO, r"\becdh\.X25519\(\)", lambda m, l, i: [Hit("X25519", "keyderive")])
rule(GO, r"\bed25519\.(?:GenerateKey|Sign|NewKeyFromSeed)\(", lambda m, l, i: [Hit("Ed25519", "sign")])
rule(GO, r"\b(?P<pkg>md5|sha1|sha256|sha512)\.(?P<fn>New|Sum|Sum224|Sum256|Sum384|Sum512)\(", _go_hash)
rule(GO, r"\baes\.NewCipher\(", lambda m, l, i: [Hit("AES", "encrypt")])
rule(GO, r"\bdes\.NewTripleDESCipher\(", lambda m, l, i: [Hit("3DES", "encrypt")])
rule(GO, r"\bdes\.NewCipher\(", lambda m, l, i: [Hit("DES", "encrypt")])
rule(GO, r"\brc4\.NewCipher\(", lambda m, l, i: [Hit("RC4", "encrypt")])
rule(GO, r"\bmlkem\.GenerateKey(?P<p>768|1024)\(", lambda m, l, i: [Hit(f"ML-KEM-{m.group('p')}", "keygen")])
rule(GO, r"\btls\.(?P<alg>X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024|X25519|CurveP256|CurveP384|CurveP521)\b", _go_tls_curve)

# ---- JavaScript / TypeScript (Node crypto, WebCrypto) ---------------------------
rule(JS, r"generateKeyPair(?:Sync)?\(\s*['\"](?P<alg>rsa|rsa-pss|dsa|ec|ed25519|ed448|x25519|x448|dh)['\"]", _js_keypair)
rule(JS, r"createHash\(\s*['\"](?P<alg>[\w-]+)['\"]", _group("digest"))
rule(JS, r"createHmac\(\s*['\"](?P<alg>[\w-]+)['\"]", lambda m, l, i: [Hit("HMAC", "tag"), Hit(m.group("alg"), "digest")])
rule(JS, r"create(?:De)?[Cc]ipheriv\(\s*['\"](?P<spec>[\w-]+)['\"]", lambda m, l, i: parse_cipher_spec(m.group("spec")))
rule(JS, r"name\s*:\s*['\"](?P<alg>RSA-OAEP|RSASSA-PKCS1-v1_5|RSA-PSS|ECDSA|ECDH|Ed25519|X25519|AES-GCM|AES-CBC|AES-CTR)['\"]", _webcrypto)

# ---- C / C++ (OpenSSL) ----------------------------------------------------------
rule(C, r"\bRSA_generate_key(?:_ex)?\(", lambda m, l, i: [Hit("RSA", "keygen")])
rule(C, r"\bEVP_PKEY_(?P<alg>RSA|EC|ED25519|ED448|X25519|X448|DH|DSA)\b", _group("keygen"))
rule(C, r"\bEVP_(?P<alg>md5|sha1|sha224|sha256|sha384|sha512)\(\)", _group("digest"))
rule(C, r"\bEVP_(?P<spec>aes_\d+_\w+|des_ede3_\w+|des_\w+|rc4|chacha20_poly1305|aria_\d+_\w+|seed_\w+)\(\)", _c_evp_cipher)
rule(C, r"\bEC_KEY_new_by_curve_name\(\s*NID_(?P<curve>\w+)", lambda m, l, i: [Hit("EC", "keygen", curve=m.group("curve"))])
rule(C, r"\bEVP_PKEY_CTX_new_from_name\([^,]*,\s*\"(?P<alg>[\w-]+)\"",
     lambda m, l, i: [Hit(pqc_name(m.group("alg")), "keygen")])

# ---- C# (.NET) ------------------------------------------------------------------
rule(CS, r"\b(?P<alg>RSA|ECDsa|ECDiffieHellman|DSA)\.Create\(", lambda m, l, i: [Hit(
    {"RSA": "RSA", "ECDsa": "ECDSA", "ECDiffieHellman": "ECDH", "DSA": "DSA"}[m.group("alg")], "keygen")])
rule(CS, r"\b(?P<alg>MD5|SHA1|SHA256|SHA384|SHA512)\.(?:Create|HashData)\(", _group("digest"))
rule(CS, r"\b(?P<alg>TripleDES|DES|Aes|AesGcm)\.Create\(|new\s+(?P<alg2>AesGcm)\(",
     lambda m, l, i: parse_cipher_spec(("3des" if (m.group("alg") or "") == "TripleDES" else (m.group("alg") or m.group("alg2") or "aes")).replace("AesGcm", "aes-gcm")))

# ---- 공통: PQC 알고리즘 문자열 (liboqs, BouncyCastle 등) ---------------------------
rule(ALL_CODE, PQC_STR, lambda m, l, i: [Hit(pqc_name(m.group("alg")), None)])

# ---- 설정 파일 --------------------------------------------------------------------
rule(CFG | {""}, r"^\s*(?:KexAlgorithms|HostKeyAlgorithms|PubkeyAcceptedAlgorithms|PubkeyAcceptedKeyTypes)\s+(?P<list>\S+)", _ssh_list)
rule(CFG | {""}, r"^\s*ssl_ecdh_curve\s+(?P<list>[^;]+);", lambda m, l, i: _tls_groups(m.group("list")))
rule({".cnf", ".conf", ""}, r"(?i)^\s*(?:Groups|Curves)\s*=\s*(?P<list>[\w:-]+)\s*$",
     lambda m, l, i: _tls_groups(m.group("list")))

# ---- 저장소 안의 비밀키 (모든 텍스트 파일) -----------------------------------------
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?P<kind>RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")


KNOWN_GROUPS = {
    "x25519": ("X25519", None), "x448": ("X448", None),
    "x25519mlkem768": ("X25519MLKEM768", None), "secp256r1mlkem768": ("SecP256r1MLKEM768", None),
    "secp384r1mlkem1024": ("SecP384r1MLKEM1024", None),
    "mlkem512": ("ML-KEM-512", None), "mlkem768": ("ML-KEM-768", None), "mlkem1024": ("ML-KEM-1024", None),
    "prime256v1": ("ECDH", "P-256"), "secp256r1": ("ECDH", "P-256"), "p-256": ("ECDH", "P-256"),
    "secp384r1": ("ECDH", "P-384"), "p-384": ("ECDH", "P-384"),
    "secp521r1": ("ECDH", "P-521"), "p-521": ("ECDH", "P-521"),
    "ffdhe2048": ("DH", 2048), "ffdhe3072": ("DH", 3072), "ffdhe4096": ("DH", 4096),
}


def _tls_groups(raw: str) -> list:
    """TLS 키 교환 그룹 목록. 알려진 그룹 이름만 인정해 오탐을 막는다."""
    hits = []
    for tok in re.split(r"[:\s,]+", raw.strip()):
        g = KNOWN_GROUPS.get(tok.lower())
        if not g:
            continue
        alg, extra = g
        if isinstance(extra, int):
            hits.append(Hit(alg, "keyderive", size=extra))
        else:
            hits.append(Hit(alg, "keyderive", curve=extra))
    return hits


# ---- TLS 버전 설정 (nginx ssl_protocols, Apache SSLProtocol) ------------------------
TLS_PROTOCOLS_RE = re.compile(r"(?i)^\s*(?:ssl_protocols|SSLProtocol)\s+(?P<list>[^;#\n]+)")
OLD_TLS = {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}


def _record_tls_config(inv: Inventory, raw: str, rel: str, line: int) -> None:
    items = [t for t in re.split(r"\s+", raw.strip()) if t]
    enabled = [t.lstrip("+") for t in items if not t.startswith("-")]
    if any(t.lower() == "all" for t in enabled):
        enabled = ["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    old = [t for t in enabled if t.lower() in OLD_TLS]
    has13 = any(t.lower() in ("tlsv1.3",) for t in enabled)
    if old:
        status, note = "broken", f"{', '.join(old)} 허용 — TLS 1.2 미만은 사용 금지"
    elif not has13:
        status, note = "quantum-vulnerable", "TLS 1.3 미허용 — PQC 하이브리드 키 교환은 TLS 1.3에서만 가능"
    else:
        status, note = "ok", "TLS 1.2 미만 차단, TLS 1.3 허용 (하이브리드 그룹 설정은 별도 확인)"
    versions = " ".join(enabled)
    inv.add_protocol(ptype="tls", version=versions, endpoint=f"{rel}:{line}", suites=[], alg_refs=[],
                     status=status, note=note, scanner="code")


# ------------------------------------------------------------------ 실행
def is_excluded(rel: str, patterns: Iterable[str]) -> bool:
    """rel(슬래시 구분 상대경로)이 제외 패턴에 걸리는지. 'tests/', '*.min.js', 'docs/**' 형태 지원."""
    rel = rel.lstrip("./")
    for pat in patterns or ():
        pat = pat.strip()
        if not pat or pat.startswith("#"):
            continue
        p = pat.lstrip("/")
        if p.endswith("/"):
            p = p + "**"
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("*").rstrip("/") + "/*"):
            return True
        if "/" not in p and any(fnmatch.fnmatch(part, p) for part in rel.split("/")):
            return True
    return False


def iter_files(root: str, excludes: Iterable[str] = (), rel_to: str | None = None) -> Iterator[str]:
    if os.path.isfile(root):
        yield root
        return
    rel_to = rel_to or root
    for d, dirs, files in os.walk(root):
        keep = []
        for x in sorted(dirs):
            if x in SKIP_DIRS or x.startswith(".git"):
                continue
            if is_excluded(os.path.relpath(os.path.join(d, x), rel_to).replace(os.sep, "/") + "/", excludes):
                continue
            keep.append(x)
        dirs[:] = keep
        for f in sorted(files):
            path = os.path.join(d, f)
            if not is_excluded(os.path.relpath(path, rel_to).replace(os.sep, "/"), excludes):
                yield path


def _ext_of(path: str) -> str:
    base = os.path.basename(path)
    if base in CONFIG_NAMES:
        return ""
    return os.path.splitext(base)[1].lower()


def scan_code(root: str, inv: Inventory, rel_to: str | None = None, excludes: Iterable[str] = ()) -> int:
    """root 아래 파일을 스캔해 inv 에 추가. 반환: 찾은 (파일, 줄, 알고리즘) 수."""
    rel_to = rel_to or (root if os.path.isdir(root) else os.path.dirname(root))
    count = 0
    for path in iter_files(root, excludes, rel_to):
        ext = _ext_of(path)
        base = os.path.basename(path)
        relevant = [r for r in RULES if ext in r[0] or (ext == "" and base in CONFIG_NAMES and "" in r[0])]
        check_pk = ext in ALL_CODE or ext in CFG or ext in {".txt", ".env", ".sh", ""}
        if not relevant and not check_pk:
            continue
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        if "\x00" in text[:1024]:
            continue
        lines = text.splitlines()
        rel = os.path.relpath(path, rel_to).replace(os.sep, "/")
        for idx, line in enumerate(lines):
            seen: set = set()
            for _exts, rx, handler in relevant:
                for m in rx.finditer(line):
                    for hit in handler(m, lines, idx) or []:
                        key = (hit.name.lower(), hit.size, hit.curve, hit.mode)
                        if key in seen:
                            continue
                        seen.add(key)
                        _record(inv, hit, rel, idx + 1, line.strip())
                        count += 1
            if ext in CFG or ext == "":
                tm = TLS_PROTOCOLS_RE.search(line)
                if tm:
                    _record_tls_config(inv, tm.group("list"), rel, idx + 1)
                    count += 1
            if check_pk:
                pm = PRIVATE_KEY_RE.search(line)
                if pm:
                    kind = (pm.group("kind") or "").strip() or "PKCS8"
                    alg = {"RSA": "RSA", "EC": "EC", "DSA": "DSA"}.get(kind)
                    alg_ref = inv.add_algorithm_by_name(alg, location=rel, line=idx + 1, scanner="code") if alg else None
                    inv.add_key_material(kind="private-key", alg_ref=alg_ref, size=None,
                                         ident=f"{rel}:{idx + 1}", location=rel, line=idx + 1,
                                         status="broken",
                                         note="저장소에 비밀키가 들어 있음 — 즉시 제거하고 키 교체",
                                         scanner="code")
                    count += 1
    return count


def _record(inv: Inventory, hit: Hit, rel: str, line: int, ctx: str) -> None:
    name = hit.name
    if name == "sntrup761x25519":
        from ..catalog import Classified, HYBRID
        c = Classified("sntrup761x25519", "sntrup761x25519", "kem", HYBRID, 1,
                       note="NTRU Prime + X25519 하이브리드 (NIST 표준은 아님, mlkem768x25519 권장)")
        inv.add_algorithm(c, location=rel, line=line, context=ctx, function="keyderive", scanner="code")
        return
    curve = hit.curve
    if name.upper() in ("EC",) and curve:
        name = "EC"
    inv.add_algorithm_by_name(name, size=hit.size, curve=curve, mode=hit.mode, location=rel, line=line,
                              context=ctx, function=hit.function, scanner="code")
