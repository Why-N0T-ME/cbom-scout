"""인증서·키 파일 스캐너.

.pem/.crt/.cer/.der/.key/.pub 와 SSH 공개키를 읽어 공개키 알고리즘·키 길이·
서명 알고리즘·유효기간을 CBOM 에 기록한다. 키 '값'은 절대 기록하지 않는다.
"""
from __future__ import annotations

import datetime as dt
import os
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519

from ..catalog import BROKEN, classify
from ..inventory import Inventory
from .code import SKIP_DIRS

CERT_EXT = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".cert"}
EXPIRY_WARN_DAYS = 30


def describe_public_key(key) -> tuple[str, Optional[int], Optional[str]]:
    """(알고리즘 이름, 키 길이, 곡선)"""
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.key_size, key.curve.name
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, None
    if isinstance(key, dh.DHPublicKey):
        return "DH", key.key_size, None
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456, None
    if isinstance(key, x25519.X25519PublicKey):
        return "X25519", 256, None
    if isinstance(key, x448.X448PublicKey):
        return "X448", 448, None
    name = type(key).__name__.replace("PublicKey", "")
    return name, None, None


def _sig_algorithm(cert: x509.Certificate) -> tuple[str, Optional[str]]:
    """인증서 서명 알고리즘 → (공개키 알고리즘, 해시)"""
    oid_name = cert.signature_algorithm_oid._name  # 예: sha256WithRSAEncryption, ecdsa-with-SHA384, ed25519
    h = None
    try:
        if cert.signature_hash_algorithm is not None:
            h = cert.signature_hash_algorithm.name  # sha256
    except Exception:  # 미지원 알고리즘(예: ML-DSA)
        pass
    low = oid_name.lower()
    if "rsa" in low:
        alg = "RSA"
    elif "ecdsa" in low:
        alg = "ECDSA"
    elif "dsa" in low and "ml-dsa" not in low:
        alg = "DSA"
    elif "ed25519" in low:
        alg = "Ed25519"
    elif "ed448" in low:
        alg = "Ed448"
    elif "ml-dsa" in low or "mldsa" in low:
        alg = "ML-DSA"
    else:
        alg = oid_name
    return alg, h


def _fmt(d: dt.datetime) -> str:
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_certificate(inv: Inventory, cert: x509.Certificate, location: str, scanner: str = "certs",
                       now: Optional[dt.datetime] = None) -> str:
    now = now or dt.datetime.now(dt.timezone.utc)
    fp = cert.fingerprint(hashes.SHA256()).hex()
    try:
        pub = cert.public_key()
        kname, ksize, kcurve = describe_public_key(pub)
    except Exception:
        kname, ksize, kcurve = "unknown", None, None
    key_alg_ref = inv.add_algorithm_by_name(kname, size=ksize if kname in ("RSA", "DSA", "DH") else None,
                                            curve=kcurve, location=location, function="verify", scanner=scanner)
    key_ref = inv.add_key_material(kind="public-key", alg_ref=key_alg_ref, size=ksize, ident=fp[:16],
                                   location=location, scanner=scanner)
    salg, shash = _sig_algorithm(cert)
    sig_ref = inv.add_algorithm_by_name(salg, location=location, function="sign", scanner=scanner)
    if shash:
        inv.add_algorithm_by_name(shash, location=location, function="digest", scanner=scanner)

    na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
    nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
    status, note = "", ""
    key_status = inv.components[key_alg_ref]
    from ..inventory import get_prop
    status = get_prop(key_status, "status") or ""
    if shash in ("md5", "sha1"):
        status, note = BROKEN, f"{shash.upper()} 서명 인증서"
    days_left = (na - now).days
    if days_left < 0:
        note = (note + "; " if note else "") + "만료된 인증서"
    elif days_left <= EXPIRY_WARN_DAYS:
        note = (note + "; " if note else "") + f"{days_left}일 후 만료"
    if not note and status == "quantum-vulnerable":
        note = f"{kname} 키 인증서 — PQC(ML-DSA) 인증서로 교체 계획 필요"
    return inv.add_certificate(fingerprint=fp, subject=cert.subject.rfc4514_string(),
                               issuer=cert.issuer.rfc4514_string(), not_before=_fmt(nb), not_after=_fmt(na),
                               sig_ref=sig_ref, key_ref=key_ref, location=location, status=status,
                               note=note, scanner=scanner)


def _record_private_key(inv: Inventory, key, rel: str) -> None:
    pub = key.public_key()
    kname, ksize, kcurve = describe_public_key(pub)
    alg_ref = inv.add_algorithm_by_name(kname, size=ksize if kname in ("RSA", "DSA", "DH") else None,
                                        curve=kcurve, location=rel, function="keygen", scanner="certs")
    inv.add_key_material(kind="private-key", alg_ref=alg_ref, size=ksize, ident=rel, location=rel,
                         status=BROKEN, note="평문 비밀키 파일 — 저장소·서버에서 제거하고 HSM/KMS로 이전",
                         scanner="certs")


def _record_public_key(inv: Inventory, key, rel: str) -> None:
    kname, ksize, kcurve = describe_public_key(key)
    alg_ref = inv.add_algorithm_by_name(kname, size=ksize if kname in ("RSA", "DSA", "DH") else None,
                                        curve=kcurve, location=rel, function="verify", scanner="certs")
    inv.add_key_material(kind="public-key", alg_ref=alg_ref, size=ksize, ident=rel, location=rel, scanner="certs")


def scan_file(path: str, rel: str, inv: Inventory) -> int:
    try:
        with open(path, "rb") as fh:
            data = fh.read(5_000_000)
    except OSError:
        return 0
    found = 0
    if b"-----BEGIN" in data:
        if b"CERTIFICATE-----" in data:
            try:
                for cert in x509.load_pem_x509_certificates(data):
                    record_certificate(inv, cert, rel)
                    found += 1
            except ValueError:
                pass
        if b"PRIVATE KEY-----" in data:
            if b"ENCRYPTED" in data:
                inv.add_key_material(kind="private-key", alg_ref=None, size=None, ident=rel, location=rel,
                                     note="암호화된 비밀키 (알고리즘 확인 불가)", scanner="certs")
                found += 1
            else:
                try:
                    _record_private_key(inv, serialization.load_pem_private_key(data, password=None), rel)
                    found += 1
                except (ValueError, TypeError, Exception):
                    pass
        if b"PUBLIC KEY-----" in data and b"PRIVATE" not in data:
            try:
                _record_public_key(inv, serialization.load_pem_public_key(data), rel)
                found += 1
            except Exception:
                pass
        return found
    if data.startswith((b"ssh-", b"ecdsa-sha2-")):
        for ln in data.splitlines():
            try:
                _record_public_key(inv, serialization.load_ssh_public_key(ln.strip()), rel)
                found += 1
            except Exception:
                continue
        return found
    if path.lower().endswith((".der", ".cer", ".crt")):
        try:
            record_certificate(inv, x509.load_der_x509_certificate(data), rel)
            found += 1
        except Exception:
            pass
    return found


def scan_certs(root: str, inv: Inventory, rel_to: str | None = None) -> int:
    rel_to = rel_to or (root if os.path.isdir(root) else os.path.dirname(root))
    total = 0
    paths = [root] if os.path.isfile(root) else None
    if paths is None:
        paths = []
        for d, dirs, files in os.walk(root):
            dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
            for f in sorted(files):
                if os.path.splitext(f)[1].lower() in CERT_EXT or f in ("authorized_keys", "known_hosts") \
                        or f.startswith("id_") and f.endswith(".pub"):
                    paths.append(os.path.join(d, f))
    for p in paths:
        total += scan_file(p, os.path.relpath(p, rel_to).replace(os.sep, "/"), inv)
    return total


def classify_key_status(name: str, size: Optional[int]) -> str:
    return classify(name, size=size).status
