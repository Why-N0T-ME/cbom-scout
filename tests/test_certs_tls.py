import datetime as dt
import os
import socket
import ssl
import threading

from cryptography.hazmat.primitives import serialization
from conftest import make_cert, pem_key

from cbom_scout.inventory import Inventory, get_prop
from cbom_scout.scanners import tls as tlsmod
from cbom_scout.scanners.certs import scan_certs


def _by_type(inv, t):
    return [c for c in inv.components.values() if c["cryptoProperties"]["assetType"] == t]


def test_cert_and_keys(tmp_path, ec_key):
    _, cert = make_cert(ec_key, cn="ec.local")
    (tmp_path / "ec.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key, _ = make_cert()
    (tmp_path / "server.key").write_bytes(pem_key(key))
    inv = Inventory()
    assert scan_certs(str(tmp_path), inv) >= 2
    certs = _by_type(inv, "certificate")
    assert certs[0]["cryptoProperties"]["certificateProperties"]["subjectName"] == "CN=ec.local"
    assert "crypto/algorithm/EC-P-384" in inv.components
    priv = [c for c in _by_type(inv, "related-crypto-material")
            if c["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] == "private-key"]
    assert priv and get_prop(priv[0], "status") == "broken"
    # 키 값은 절대 기록하지 않는다
    assert all("value" not in c["cryptoProperties"].get("relatedCryptoMaterialProperties", {})
               for c in inv.components.values())


def test_expired_cert_note(tmp_path):
    _, cert = make_cert(start=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc), days=30)
    (tmp_path / "old.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    inv = Inventory()
    scan_certs(str(tmp_path), inv)
    assert "만료" in get_prop(_by_type(inv, "certificate")[0], "note")


def test_ssh_public_key(tmp_path, ec_key):
    line = ec_key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    (tmp_path / "id_ecdsa.pub").write_bytes(line + b" user@host\n")
    inv = Inventory()
    scan_certs(str(tmp_path), inv)
    assert "crypto/algorithm/EC-P-384" in inv.components


# ------------------------------------------------------------------ TLS
def _serve_once(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        try:
            conn, _ = srv.accept()
            with ctx.wrap_socket(conn, server_side=True) as s:
                s.recv(1)
        except Exception:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return port, t


def test_tls_probe_local(tmp_path):
    key, cert = make_cert(cn="localhost")
    cf, kf = tmp_path / "c.pem", tmp_path / "k.pem"
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(pem_key(key))
    port, t = _serve_once(str(cf), str(kf))
    inv = Inventory()
    res = tlsmod.scan_tls([f"127.0.0.1:{port}"], inv, timeout=5, use_openssl=False)
    t.join(5)
    assert res[0].ok, res[0].error
    assert res[0].version == "TLSv1.3"
    proto = _by_type(inv, "protocol")[0]
    assert proto["cryptoProperties"]["protocolProperties"]["version"] == "1.3"
    assert get_prop(proto, "key-exchange-source") == "unavailable"
    assert _by_type(inv, "certificate")
    assert any(n.startswith("crypto/algorithm/AES") or "ChaCha" in n for n in inv.components)


def test_parse_s_client_outputs():
    hybrid = "Protocol version: TLSv1.3\nNegotiated TLS1.3 group: X25519MLKEM768\n"
    classic = "Peer signature type: rsa_pss_rsae_sha256\nServer Temp Key: X25519, 253 bits\n"
    ecdh = "Server Temp Key: ECDH, prime256v1, 256 bits\n"
    assert tlsmod.parse_s_client(hybrid) == "X25519MLKEM768"
    assert tlsmod.parse_s_client(classic) == "X25519"
    assert tlsmod.parse_s_client(ecdh) == "prime256v1"


def test_record_hybrid_group_status():
    inv = Inventory()
    r = tlsmod.TLSResult("example.org", 443, ok=True, version="TLSv1.3",
                         cipher="TLS_AES_256_GCM_SHA384", group="X25519MLKEM768", group_source="openssl")
    ref = tlsmod.record(inv, r)
    assert get_prop(inv.components[ref], "status") == "hybrid"
    assert "crypto/algorithm/AES-256-GCM" in inv.components


def test_cipher_suite_parsing():
    algs = [a for a, _ in tlsmod.cipher_algorithms("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2")]
    assert algs[:2] == ["ECDH", "RSA"] and "AES" in algs and "SHA256" in algs
    assert tlsmod.parse_target("https://example.com/path") == ("example.com", 443)
    assert tlsmod.parse_target("[::1]:8443") == ("::1", 8443)
