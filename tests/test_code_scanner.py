import os

from conftest import DEMO

from cbom_scout.inventory import Inventory, get_prop
from cbom_scout.scanners.code import parse_cipher_spec, parse_sig_spec, scan_code


def names(inv):
    return {c["name"] for c in inv.components.values()}


def scan_snippet(tmp_path, filename, text):
    p = tmp_path / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    inv = Inventory()
    scan_code(str(tmp_path), inv)
    return inv


def test_demo_app_findings():
    inv = Inventory()
    scan_code(DEMO, inv)
    n = names(inv)
    for expected in ("RSA-2048", "RSA-1024", "EC-P-256", "MD5", "SHA-1", "AES-ECB", "3DES-CBC",
                     "ECDSA-P-384", "ML-KEM-768", "ML-KEM", "X25519MLKEM768", "RSA-3072", "AES-256-GCM",
                     "DH-2048", "Ed25519", "X25519"):
        assert expected in n, expected
    md5 = inv.components["crypto/algorithm/MD5"]
    occ = md5["evidence"]["occurrences"][0]
    assert occ["location"] == "src/payment.py" and occ["line"] == 18
    assert get_prop(md5, "status") == "broken"


def test_python_variants(tmp_path):
    inv = scan_snippet(tmp_path, "a.py", "import hashlib\nh = hashlib.new('sha512')\n"
                                         "from Crypto.Cipher import DES3\nc = DES3.new(k, DES3.MODE_CBC)\n")
    n = names(inv)
    assert "SHA-512" in n and "3DES-CBC" in n


def test_java_lookahead_curve(tmp_path):
    src = ('KeyPairGenerator g = KeyPairGenerator.getInstance("EC");\n'
           'g.initialize(new ECGenParameterSpec("secp384r1"));\n'
           'Mac m = Mac.getInstance("HmacSHA384");\n')
    n = names(scan_snippet(tmp_path, "A.java", src))
    assert "EC-P-384" in n and "HMAC" in n and "SHA-384" in n


def test_js_webcrypto(tmp_path):
    src = ('await crypto.subtle.generateKey({ name: "RSA-PSS",\n  modulusLength: 4096 }, true, ["sign"]);\n'
           'await crypto.subtle.generateKey({ name: "AES-GCM", length: 128 }, true, ["encrypt"]);\n')
    n = names(scan_snippet(tmp_path, "a.js", src))
    assert "RSA-4096" in n and "AES-128-GCM" in n


def test_c_openssl(tmp_path):
    src = "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, k, iv);\nEVP_DigestInit(md, EVP_sha1());\n" \
          'EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);\n'
    n = names(scan_snippet(tmp_path, "x.c", src))
    assert {"AES-128-CBC", "SHA-1", "ML-KEM-768"} <= n


def test_private_key_in_repo(tmp_path):
    inv = scan_snippet(tmp_path, "config/.env", "KEY=\"-----BEGIN RSA PRIVATE KEY-----\"\n")
    keys = [c for c in inv.components.values()
            if c["cryptoProperties"]["assetType"] == "related-crypto-material"]
    assert keys and get_prop(keys[0], "status") == "broken"


def test_tls_config_old_versions(tmp_path):
    inv = scan_snippet(tmp_path, "nginx.conf", "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n")
    protos = [c for c in inv.components.values() if c["cryptoProperties"]["assetType"] == "protocol"]
    assert protos and get_prop(protos[0], "status") == "broken"


def test_skips_vendor_dirs(tmp_path):
    inv = scan_snippet(tmp_path, "node_modules/lib/x.js", "createHash('md5')\n")
    assert not inv.components


def test_spec_parsers():
    assert [(h.name, h.size, h.mode) for h in parse_cipher_spec("aes-256-gcm")] == [("AES", 256, "gcm")]
    assert parse_cipher_spec("DESede/CBC/PKCS5Padding")[0].name == "3DES"
    assert parse_cipher_spec("chacha20-poly1305")[0].name == "ChaCha20-Poly1305"
    assert [h.name for h in parse_sig_spec("SHA256withRSA")] == ["SHA-256", "RSA"]
    assert parse_sig_spec("ML-DSA-65")[0].name == "ML-DSA-65"


def test_json_and_unrelated_groups_not_flagged(tmp_path):
    (tmp_path / "data.json").write_text('{"ctx": "hashlib.md5(x)", "Groups": "admins"}', encoding="utf-8")
    (tmp_path / "app.yaml").write_text("Groups = admins:users\n", encoding="utf-8")
    inv = Inventory()
    scan_code(str(tmp_path), inv)
    assert not inv.components


def test_openssl_cnf_groups(tmp_path):
    n = names(scan_snippet(tmp_path, "openssl.cnf", "Groups = X25519MLKEM768:X25519:secp384r1\n"))
    assert {"X25519MLKEM768", "X25519", "ECDH-P-384"} <= n


def test_java_default_ecb(tmp_path):
    inv = scan_snippet(tmp_path, "C.java", 'Cipher c = Cipher.getInstance("AES");\n')
    assert "AES-ECB" in names(inv)
    assert get_prop(inv.components["crypto/algorithm/AES-ECB"], "status") == "broken"


def test_good_tls_config_is_ok(tmp_path):
    inv = scan_snippet(tmp_path, "nginx.conf", "ssl_protocols TLSv1.2 TLSv1.3;\n")
    proto = [c for c in inv.components.values() if c["cryptoProperties"]["assetType"] == "protocol"][0]
    assert get_prop(proto, "status") == "ok"


def test_excludes(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "a.py").write_text("import hashlib\nhashlib.md5(b'')\n", encoding="utf-8")
    (tmp_path / "tests" / "t.py").write_text("import hashlib\nhashlib.sha1(b'')\n", encoding="utf-8")
    (tmp_path / "src" / "x.min.js").write_text("createHash('md5')\n", encoding="utf-8")
    inv = Inventory()
    scan_code(str(tmp_path), inv, excludes=["tests/", "*.min.js"])
    assert names(inv) == {"MD5"}
    locs = {o["location"] for o in inv.components["crypto/algorithm/MD5"]["evidence"]["occurrences"]}
    assert locs == {"src/a.py"}
