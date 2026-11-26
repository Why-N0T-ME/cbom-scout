"""TLS 엔드포인트 스캐너.

1) 표준 라이브러리 ssl 로 접속해 협상된 TLS 버전·암호 스위트·서버 인증서를 수집한다.
2) 시스템에 OpenSSL 3.5 이상이 있으면 `openssl s_client -groups` 로
   하이브리드 PQC 키 교환(X25519MLKEM768 등) 협상 여부까지 확인한다.

인벤토리 목적이므로 인증서 검증은 하지 않는다(만료·자체서명 서버도 기록해야 하기 때문).
"""
from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509

from ..catalog import BROKEN, HYBRID, QV, classify
from ..inventory import Inventory, get_prop
from .certs import record_certificate

PQC_GROUPS = "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519:secp256r1:secp384r1"
OLD_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class TLSResult:
    host: str
    port: int
    ok: bool = False
    error: str = ""
    version: str = ""
    cipher: str = ""
    cipher_bits: int = 0
    cert_der: Optional[bytes] = None
    group: str = ""                 # 협상된 키 교환 그룹
    group_source: str = ""          # openssl / unavailable
    notes: list = field(default_factory=list)


def parse_target(t: str) -> tuple[str, int]:
    t = t.strip()
    t = re.sub(r"^https?://", "", t).split("/")[0]
    if t.startswith("["):  # IPv6
        host, _, port = t[1:].partition("]:")
        return host, int(port or 443)
    if t.count(":") == 1:
        host, port = t.split(":")
        return host, int(port)
    return t, 443


def openssl_supports_pqc(openssl: str = "openssl") -> bool:
    exe = shutil.which(openssl)
    if not exe:
        return False
    try:
        out = subprocess.run([exe, "list", "-kem-algorithms"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return False
    return "ML-KEM" in out.upper() or "MLKEM" in out.upper()


def parse_s_client(output: str) -> str:
    """openssl s_client 출력에서 협상된 키 교환 그룹을 뽑는다."""
    for pat in (r"Negotiated TLS1\.3 group:\s*(\S+)",
                r"Server Temp Key:\s*([\w-]+)",
                r"Negotiated group:\s*(\S+)"):
        m = re.search(pat, output)
        if m:
            g = m.group(1).rstrip(",")
            return {"ECDH": "", "DH": "DH"}.get(g, g) or _ecdh_curve(output)
    return ""


def _ecdh_curve(output: str) -> str:
    m = re.search(r"Server Temp Key:\s*ECDH,\s*(\S+?),", output)
    return m.group(1) if m else "ECDH"


def probe_group(host: str, port: int, timeout: float = 10.0, openssl: str = "openssl") -> str:
    exe = shutil.which(openssl)
    if not exe:
        return ""
    cmd = [exe, "s_client", "-connect", f"{host}:{port}", "-servername", host, "-groups", PQC_GROUPS, "-brief"]
    try:
        p = subprocess.run(cmd, input="Q\n", capture_output=True, text=True, timeout=timeout)
    except Exception:
        return ""
    return parse_s_client(p.stdout + "\n" + p.stderr)


def probe(host: str, port: int, timeout: float = 8.0, use_openssl: Optional[bool] = None) -> TLSResult:
    r = TLSResult(host, port)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ValueError, AttributeError):
        pass
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                r.version = ss.version() or ""
                c = ss.cipher()
                if c:
                    r.cipher, _, r.cipher_bits = c[0], c[1], c[2]
                r.cert_der = ss.getpeercert(binary_form=True)
                grp = getattr(ss, "group", None)  # Python 3.15+ 에서 제공 예정
                if callable(grp):
                    try:
                        r.group, r.group_source = grp() or "", "python-ssl"
                    except Exception:
                        pass
        r.ok = True
    except Exception as e:  # noqa: BLE001
        r.error = f"{type(e).__name__}: {e}"
        return r
    if not r.group:
        if use_openssl is None:
            use_openssl = openssl_supports_pqc()
        if use_openssl:
            r.group = probe_group(host, port)
            r.group_source = "openssl"
        else:
            r.group_source = "unavailable"
            r.notes.append("키 교환 그룹 확인 불가 (OpenSSL 3.5 이상 필요)")
    return r


def cipher_algorithms(cipher: str, version: str) -> list[tuple[str, dict]]:
    """암호 스위트 이름 → [(알고리즘, 옵션)]"""
    out: list[tuple[str, dict]] = []
    c = cipher.upper()
    if c.startswith("TLS_") and version == "TLSv1.3":
        m = re.match(r"TLS_(AES)_(128|256)_(GCM|CCM)\w*_(SHA\d+)", c)
        if m:
            out.append(("AES", {"size": int(m.group(2)), "mode": m.group(3)}))
            out.append((m.group(4), {}))
        elif "CHACHA20_POLY1305" in c:
            out += [("ChaCha20-Poly1305", {}), ("SHA256", {})]
        return out
    parts = c.replace("TLS_", "").replace("_WITH_", "-").replace("_", "-").split("-")
    joined = "-".join(parts)
    if "ECDHE" in parts:
        out.append(("ECDH", {}))
    elif "DHE" in parts or "EDH" in parts:
        out.append(("DH", {}))
    elif parts and parts[0] in ("AES128", "AES256", "AES", "DES", "RC4") or "RSA" in parts[:1]:
        out.append(("RSA", {}))  # RSA 키 전송
    if "ECDSA" in parts:
        out.append(("ECDSA", {}))
    elif "RSA" in parts:
        out.append(("RSA", {}))
    m = re.search(r"AES-?(128|256)", joined)
    if m:
        mode = "GCM" if "GCM" in parts else ("CBC" if "CBC" in parts or "SHA" in parts[-1:] else None)
        out.append(("AES", {"size": int(m.group(1)), "mode": mode}))
    if "CHACHA20" in parts:
        out.append(("ChaCha20-Poly1305", {}))
    if "3DES" in parts or "DES-CBC3" in joined:
        out.append(("3DES", {}))
    elif "DES" in parts:
        out.append(("DES", {}))
    if "RC4" in parts:
        out.append(("RC4", {}))
    if parts and re.match(r"SHA(\d+)?$", parts[-1]):
        out.append(("SHA-1" if parts[-1] == "SHA" else parts[-1], {}))
    return out


def group_algorithm(group: str) -> tuple[str, Optional[str]]:
    g = group.strip()
    gl = g.lower()
    if gl in ("x25519", "x448"):
        return gl.upper(), None
    if "mlkem" in gl:
        return g, None
    if gl in ("secp256r1", "prime256v1", "p-256"):
        return "ECDH", "P-256"
    if gl in ("secp384r1", "p-384"):
        return "ECDH", "P-384"
    if gl in ("secp521r1", "p-521"):
        return "ECDH", "P-521"
    if gl.startswith("ffdhe") or gl == "dh":
        return "DH", None
    return g, None


def record(inv: Inventory, r: TLSResult) -> Optional[str]:
    endpoint = f"{r.host}:{r.port}"
    if not r.ok:
        return None
    refs: list[str] = []
    suite_refs: list[str] = []
    for name, opt in cipher_algorithms(r.cipher, r.version):
        ref = inv.add_algorithm_by_name(name, size=opt.get("size"), mode=opt.get("mode"),
                                        location=endpoint, scanner="tls")
        suite_refs.append(ref)
    refs += suite_refs
    status, notes = "", list(r.notes)
    if r.group:
        alg, curve = group_algorithm(r.group)
        gref = inv.add_algorithm_by_name(alg, curve=curve, location=endpoint, function="keyderive", scanner="tls")
        refs.append(gref)
        status = get_prop(inv.components[gref], "status") or ""
    if r.cert_der:
        try:
            cert = x509.load_der_x509_certificate(r.cert_der)
            cref = record_certificate(inv, cert, endpoint, scanner="tls")
            refs.append(cref)
        except Exception:
            notes.append("서버 인증서 해석 실패")
    if r.version in OLD_VERSIONS:
        status = BROKEN
        notes.append(f"{r.version} 허용 — TLS 1.2 미만은 사용 금지")
    elif r.version == "TLSv1.2" and not status:
        status = QV
        notes.append("TLS 1.2 — PQC 하이브리드는 TLS 1.3에서만 사용 가능")
    if status == QV and r.group:
        notes.append("고전 키 교환 — X25519MLKEM768 하이브리드 활성화 권장")
    if status == HYBRID:
        notes.append("하이브리드 PQC 키 교환 사용 중")
    return inv.add_protocol(ptype="tls", version=r.version.replace("TLSv", "") if r.version else "",
                            endpoint=endpoint, suites=[(r.cipher, suite_refs)] if r.cipher else [],
                            alg_refs=refs, status=status, note="; ".join(notes), scanner="tls",
                            extra={"key-exchange-group": r.group or "unknown",
                                   "key-exchange-source": r.group_source})


def scan_tls(targets: list[str], inv: Inventory, timeout: float = 8.0,
             use_openssl: Optional[bool] = None) -> list[TLSResult]:
    if use_openssl is None:
        use_openssl = openssl_supports_pqc()
    results = []
    for t in targets:
        if not t.strip() or t.strip().startswith("#"):
            continue
        host, port = parse_target(t)
        res = probe(host, port, timeout=timeout, use_openssl=use_openssl)
        record(inv, res)
        results.append(res)
    return results
