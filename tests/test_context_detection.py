"""문맥 인식 탐지 (docs/specs/context-aware-detection.md 1a) 개발자 테스트."""
import json
import os
import sys

import pytest

from cbom_scout.cli import main


def scan(tmp_path, files, *extra, monkeypatch=None, capsys=None):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            p.write_bytes(text)
        else:
            p.write_text(text, encoding="utf-8", newline="")
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        code = main(["scan", ".", "-o", "out.json", "--markdown", "r.md", "--html", "r.html",
                     "--fail-on", "never", "--no-github-summary", *extra])
    finally:
        os.chdir(cwd)
    bom = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    return code, bom


def comp(bom, name):
    for c in bom["components"]:
        if c["name"] == name:
            return c
    return None


def names(bom, asset_type="algorithm"):
    return {c["name"] for c in bom["components"]
            if c.get("cryptoProperties", {}).get("assetType") == asset_type}


def occs(c):
    return {(o["location"], o.get("line")) for o in c["evidence"]["occurrences"]}


def methods(c):
    el = [x for x in c["evidence"]["identity"] if x["field"] == "name"]
    assert len(el) == 1
    return {m["technique"]: m["confidence"] for m in el[0]["methods"]}, el[0]["confidence"]


def prop(c, k):
    for p in c.get("properties", []):
        if p["name"] == "cbom-scout:" + k:
            return p["value"]
    return None


AST, SRC = "ast-fingerprint", "source-code-analysis"


# ------------------------------------------------------------------ Python 오탐
def test_python_comment_ignored(tmp_path):
    _, bom = scan(tmp_path, {"app/a.py": 'import hashlib\n# hashlib.md5(data) 는 쓰지 말 것\n'
                                         'x = 1  # 예: hashlib.sha1(b"")\nh = hashlib.sha256(b"")\n'})
    assert comp(bom, "MD5") is None and comp(bom, "SHA-1") is None
    c = comp(bom, "SHA-256")
    assert occs(c) == {("app/a.py", 4)}
    assert methods(c) == ({AST: 0.9}, 0.9)


def test_python_docstring_ignored(tmp_path):
    _, bom = scan(tmp_path, {"app/doc.py": '"""모듈 설명: hashlib.md5(b"x") 예제"""\ndef f():\n'
                  '    """>>> rsa.generate_private_key(public_exponent=65537, key_size=1024)"""\n    return 1\n'
                  'class C:\n    """Cipher(algorithms.TripleDES(k), modes.ECB())"""\n'})
    assert names(bom) == set()


def test_python_string_literal_ignored(tmp_path):
    _, bom = scan(tmp_path, {"app/s.py": 'import logging\nlogging.warning("hashlib.md5() 는 금지")\n'
                                         "MSG = 'Cipher(algorithms.TripleDES(k), modes.ECB())'\n"})
    assert not names(bom) & {"MD5", "3DES", "3DES-ECB", "AES-ECB"}


def test_python_pqc_string(tmp_path):
    _, bom = scan(tmp_path, {"app/p.py": 'print("ML-KEM-768 지원 예정")\n',
                             "app/q.py": '"""ML-DSA-65 도입 검토"""\n# "SLH-DSA-SHA2-128s"\n'})
    c = comp(bom, "ML-KEM-768")
    assert occs(c) == {("app/p.py", 1)}
    assert methods(c) == ({AST: 0.3}, 0.3)
    assert all("symbol" not in o for o in c["evidence"]["occurrences"])
    assert not any(n.startswith(("ML-DSA-65", "SLH-DSA")) for n in names(bom))


# ------------------------------------------------------------------ Python 미탐
def test_python_import_alias(tmp_path):
    _, bom = scan(tmp_path, {"a.py": "import hashlib as hl\nfrom hashlib import md5, sha1 as s1\n"
                                     'hl.sha512(b"")\nmd5(b"")\ns1(b"")\n'})
    for name, line, sym in (("SHA-512", 3, "hashlib.sha512"), ("MD5", 4, "hashlib.md5"), ("SHA-1", 5, "hashlib.sha1")):
        c = comp(bom, name)
        assert c["evidence"]["occurrences"] == [{"location": "a.py", "line": line, "symbol": sym}]
        assert methods(c)[0] == {AST: 0.9}


def test_python_module_alias_and_multiline(tmp_path):
    _, bom = scan(tmp_path, {
        "k.py": "from cryptography.hazmat.primitives.asymmetric import rsa as r\n"
                "k = r.generate_private_key(public_exponent=65537, key_size=1024)\n",
        "m.py": "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(\n"
                "    public_exponent=65537,\n    key_size=1024,\n)\n"})
    c = comp(bom, "RSA-1024")
    assert occs(c) == {("k.py", 2), ("m.py", 2)}
    assert prop(c, "status") == "broken"
    assert comp(bom, "RSA") is None


def test_regex_engine_keeps_old_multiline_behaviour(tmp_path):
    _, bom = scan(tmp_path, {"m.py": "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                                     "key = rsa.generate_private_key(\n    public_exponent=65537,\n"
                                     "    key_size=1024,\n)\n"}, "--engine", "regex")
    assert comp(bom, "RSA") is not None and comp(bom, "RSA-1024") is None
    assert methods(comp(bom, "RSA")) == ({SRC: 0.6}, 0.6)


def test_python_constants(tmp_path):
    _, bom = scan(tmp_path, {"c.py": 'import hashlib\nHASH_ALG = "sha1"\nKEY_BITS = 1024\ndef f(d):\n'
                                     "    return hashlib.new(HASH_ALG, d)\nfrom Crypto.PublicKey import RSA\n"
                                     "k = RSA.generate(KEY_BITS)\n"})
    sha1 = comp(bom, "SHA-1")
    assert sha1["evidence"]["occurrences"] == [{"location": "c.py", "line": 5, "symbol": "hashlib.new"}]
    assert methods(sha1)[1] == 0.9
    assert occs(comp(bom, "RSA-1024")) == {("c.py", 7)}


def test_python_ambiguous_and_default(tmp_path):
    _, bom = scan(tmp_path, {"d.py": 'import hashlib\ndef digest(data, alg="md5"):\n    return hashlib.new(alg, data)\n'
                                     'MODE = "sha256"\nif cond:\n    MODE = "sha1"\nhashlib.new(MODE, b"")\n'})
    assert occs(comp(bom, "MD5")) == {("d.py", 3)}
    assert occs(comp(bom, "SHA-256")) == {("d.py", 7)}
    assert occs(comp(bom, "SHA-1")) == {("d.py", 7)}
    for n in ("MD5", "SHA-256", "SHA-1"):
        assert methods(comp(bom, n)) == ({AST: 0.6}, 0.6)


def test_python_unresolvable(tmp_path, capsys):
    code, bom = scan(tmp_path, {"u.py": 'import hashlib\nhashlib.new(user_input, b"")\n'
                                        'hashlib.new(get_alg(), b"")\nhashlib.new(f"sha{n}", b"")\n'})
    assert code == 0 and names(bom) == set()
    assert "Traceback" not in capsys.readouterr().err


def test_python_cipher_combination(tmp_path):
    _, bom = scan(tmp_path, {"e.py": "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
                                     "c1 = Cipher(algorithms.TripleDES(k), modes.ECB())\n"
                                     "c2 = Cipher(algorithms.AES(k), modes.CBC(iv))\n"})
    assert occs(comp(bom, "3DES-ECB")) == {("e.py", 2)}
    assert prop(comp(bom, "3DES-ECB"), "status") == "broken"
    assert occs(comp(bom, "AES-CBC")) == {("e.py", 3)}
    assert not names(bom) & {"AES-ECB", "AES", "3DES"}


ALL_PY = ('hashlib.md5(b"")\nhashlib.new(\'sha512\')\nhashes.SHA384()\n'
          "rsa.generate_private_key(public_exponent=65537, key_size=2048)\nRSA.generate(3072)\n"
          "dsa.generate_private_key(key_size=1024)\ndh.generate_parameters(generator=2, key_size=2048)\n"
          "ec.generate_private_key(ec.SECP384R1())\nec.ECDSA(hashes.SHA256())\nEd25519PrivateKey.generate()\n"
          "AESGCM(k)\nChaCha20Poly1305(k)\nDES3.new(k, DES3.MODE_CBC)\nARC4.new(k)\n")


def test_python_parity_with_regex(tmp_path):
    _, auto = scan(tmp_path / "a", {"all.py": ALL_PY})
    _, rx = scan(tmp_path / "b", {"all.py": ALL_PY}, "--engine", "regex")
    assert names(auto) == names(rx)
    assert len(names(auto)) >= 14


def test_kb_is_data():
    import cbom_scout
    root = os.path.dirname(cbom_scout.__file__)
    kb = json.load(open(os.path.join(root, "data", "python_api.json"), encoding="utf-8"))["apis"]
    for k in ("hashlib.md5", "hashlib.new", "hashes.SHA384", "rsa.generate_private_key", "RSA.generate",
              "dsa.generate_private_key", "dh.generate_parameters", "ec.generate_private_key", "ec.ECDSA",
              "Ed25519PrivateKey", "AESGCM", "ChaCha20Poly1305", "DES3.new", "ARC4.new"):
        assert k in kb
    for d, _, files in os.walk(root):
        for f in files:
            if f.endswith(".py"):
                text = open(os.path.join(d, f), encoding="utf-8").read()
                if "import ast" in text or "from ast" in text:
                    for word in ("generate_private_key", "generate_parameters", "ChaCha20Poly1305"):
                        assert word not in text, (f, word)


# ------------------------------------------------------------------ Python 대체·인코딩
def test_python_syntax_error_fallback(tmp_path, capsys):
    files = {"legacy.py": 'print "hello"\nimport hashlib\n# hashlib.sha1(x)\nhashlib.md5(x)\n',
             "ok.py": 'import hashlib\nhashlib.sha384(b"")\n'}
    _, bom = scan(tmp_path, files, "-v")
    assert occs(comp(bom, "MD5")) == {("legacy.py", 4)}
    assert methods(comp(bom, "MD5")) == ({SRC: 0.6}, 0.6)
    assert comp(bom, "SHA-1") is None
    assert methods(comp(bom, "SHA-384"))[0] == {AST: 0.9}
    err = capsys.readouterr().err
    assert any("구문 분석 실패" in ln and "legacy.py" in ln for ln in err.splitlines())
    scan(tmp_path, {})
    assert "구문 분석 실패" not in capsys.readouterr().err


def test_python_bom_file(tmp_path):
    _, bom = scan(tmp_path, {"bom.py": b"\xef\xbb\xbfimport hashlib\nhashlib.md5(b'')\n"})
    assert occs(comp(bom, "MD5")) == {("bom.py", 2)}
    assert methods(comp(bom, "MD5"))[0] == {AST: 0.9}


def test_python_new_syntax(tmp_path, capsys):
    code, bom = scan(tmp_path, {"new.py": 'import hashlib\ntype Alias = int\nhashlib.md5(b"")\n'})
    assert code == 0 and occs(comp(bom, "MD5")) == {("new.py", 3)}
    expected = AST if sys.version_info >= (3, 12) else SRC
    assert expected in methods(comp(bom, "MD5"))[0]
    assert "Traceback" not in capsys.readouterr().err


# ------------------------------------------------------------------ 그 밖의 언어
def test_java_comments(tmp_path):
    _, bom = scan(tmp_path, {"A.java": 'import javax.crypto.Cipher;\npublic class A {\n'
                  '  // Cipher c = Cipher.getInstance("DES");\n  /* MessageDigest.getInstance("MD5");\n'
                  '     Signature.getInstance("SHA1withRSA"); */\n  /** Cipher.getInstance("RC4") */\n'
                  '  Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); // 예전: Cipher.getInstance("DESede")\n}\n'})
    assert names(bom) == {"AES-GCM"}
    c = comp(bom, "AES-GCM")
    assert c["evidence"]["occurrences"] == [{"location": "A.java", "line": 7, "symbol": "Cipher.getInstance"}]
    assert methods(c) == ({SRC: 0.9}, 0.9)


def test_java_strings_and_text_block(tmp_path):
    _, bom = scan(tmp_path, {"B.java": 'class B {\n  String doc = "Cipher.getInstance(\\"DES\\") 금지";\n'
                  '  String tb = """\n    MessageDigest.getInstance("MD5")\n    """;\n'
                  '  String u = "http://x"; MessageDigest md = MessageDigest.getInstance("SHA-256");\n}\n'})
    assert names(bom) == {"SHA-256"}
    assert occs(comp(bom, "SHA-256")) == {("B.java", 6)}


def test_java_lookahead_skips_comments(tmp_path):
    _, bom = scan(tmp_path, {"K.java": 'class K { void k() throws Exception {\n'
                  '  KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\n  // g.initialize(1024);\n'
                  '  g.initialize(3072);\n}}\n'})
    assert comp(bom, "RSA-3072") is not None and comp(bom, "RSA-1024") is None


def test_go_js_c_cs(tmp_path):
    _, bom = scan(tmp_path, {
        "g.go": 'package main\nimport ("crypto/sha1"; "crypto/sha256")\n// sha1.Sum(x)\nvar s = `md5.New()`\n'
                "func f(b []byte) { _ = sha256.Sum256(b) }\n",
        "w.ts": 'import { createHash, createCipheriv } from "crypto";\n// createHash(\'md5\')\n'
                "/* createCipheriv('des-ede3-cbc', k, iv) */\nconst s = \"createHash('sha1')\";\n"
                "const t = `createHash('sha1')`;\nexport const h = createHash('sha512');\n",
        "x.c": "#include <openssl/evp.h>\n/* EVP_md5() */ EVP_DigestInit(ctx, EVP_sha256());\n",
        "y.cs": '// MD5.Create()\nvar s = @"SHA1.Create() ""q""";\nvar h = SHA256.Create();\n'})
    assert names(bom) == {"SHA-256", "SHA-512"}
    assert occs(comp(bom, "SHA-512")) == {("w.ts", 6)}
    assert occs(comp(bom, "SHA-256")) == {("g.go", 5), ("x.c", 2), ("y.cs", 3)}


def test_other_language_pqc_string(tmp_path):
    _, bom = scan(tmp_path, {"P.java": 'class P { void p() { log.info("ML-KEM-768 준비 중"); } }\n// "ML-DSA-65"\n'})
    assert methods(comp(bom, "ML-KEM-768")) == ({SRC: 0.3}, 0.3)
    assert comp(bom, "ML-DSA-65") is None


def test_unclosed_comment_and_string(tmp_path, capsys):
    code, bom = scan(tmp_path, {"o1.js": "/* 열린 주석\ncreateHash('md5')\n",
                                "o2.js": "const s = \"abc\ncreateHash('md5')\n"})
    assert code == 0 and occs(comp(bom, "MD5")) == {("o2.js", 2)}
    assert "Traceback" not in capsys.readouterr().err


def test_private_key_still_detected_in_comments(tmp_path):
    _, bom = scan(tmp_path, {"s.java": "// -----BEGIN RSA PRIVATE KEY-----\n",
                             "s.py": '"""\n-----BEGIN EC PRIVATE KEY-----\n"""\n'})
    keys = [c for c in bom["components"]
            if c["cryptoProperties"].get("relatedCryptoMaterialProperties", {}).get("type") == "private-key"]
    locs = {o["location"] for c in keys for o in c["evidence"]["occurrences"]}
    assert locs == {"s.java", "s.py"}
    assert all(prop(c, "status") == "broken" for c in keys)


def test_config_unchanged(tmp_path):
    _, bom = scan(tmp_path, {"sshd_config": "# KexAlgorithms diffie-hellman-group1-sha1\nKexAlgorithms curve25519-sha256\n",
                             "nginx.conf": "ssl_protocols TLSv1.2 TLSv1.3; # TLSv1\n"})
    assert comp(bom, "DH-1024") is None
    assert methods(comp(bom, "X25519")) == ({SRC: 0.9}, 0.9)
    proto = [c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "protocol"]
    assert [prop(c, "status") for c in proto] == ["ok"]


# ------------------------------------------------------------------ 표준 필드·정책
def test_identity_merges_methods(tmp_path):
    _, bom = scan(tmp_path, {"p.py": 'print("ML-KEM-768")\n',
                             "B.java": 'class B { void b() throws Exception { KEM k = KEM.getInstance("ML-KEM-768"); } }\n'})
    c = comp(bom, "ML-KEM-768")
    assert c["evidence"]["identity"] == [{"field": "name", "confidence": 0.9, "concludedValue": "ML-KEM-768",
                                          "methods": [{"technique": AST, "confidence": 0.3},
                                                      {"technique": SRC, "confidence": 0.9}]}]
    for x in bom["components"]:
        for p in x.get("properties", []):
            assert not any(w in p["name"] for w in ("confidence", "detection", "technique"))


def test_secret_constant_not_recorded(tmp_path, capsys):
    _, bom = scan(tmp_path, {"z.py": 'import hashlib\nSECRET_KEY = "s3cr3t-Pa55w0rd-XYZ"\nALG = "sha1"\n'
                                     "hashlib.new(ALG, SECRET_KEY.encode())\n"}, "-v")
    out = capsys.readouterr()
    for f in ("out.json", "r.md", "r.html"):
        assert "s3cr3t-Pa55w0rd-XYZ" not in (tmp_path / f).read_text(encoding="utf-8")
    assert "s3cr3t-Pa55w0rd-XYZ" not in out.out + out.err
    assert occs(comp(bom, "SHA-1")) == {("z.py", 4)}


def _policy(tmp_path, value):
    import cbom_scout
    src = os.path.join(os.path.dirname(cbom_scout.__file__), "policies", "nist-ir8547.json")
    pol = json.load(open(src, encoding="utf-8"))
    pol["min_confidence"] = value
    (tmp_path / "p.json").write_text(json.dumps(pol), encoding="utf-8")


def test_min_confidence(tmp_path, capsys):
    files = {"d.py": 'import hashlib\ndef digest(data, alg="md5"):\n    return hashlib.new(alg, data)\n'
                     'MODE = "sha256"\nif cond:\n    MODE = "sha1"\nhashlib.new(MODE, b"")\n'}
    scan(tmp_path, files)
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert main(["scan", ".", "-o", "out.json", "--markdown", "r.md", "--no-github-summary"]) == 1
        _policy(tmp_path, 0.7)
        assert main(["scan", ".", "-o", "out.json", "--markdown", "r.md", "--no-github-summary",
                     "--policy", "p.json"]) == 0
        bom = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        assert prop(comp(bom, "MD5"), "policy-action") == "info"
        assert prop(comp(bom, "SHA-1"), "policy-action") == "info"
        md5_row = [ln for ln in (tmp_path / "r.md").read_text(encoding="utf-8").splitlines() if "**MD5**" in ln]
        assert md5_row and "(탐지 신뢰도 낮음 — 판정 보류)" in md5_row[0]
        _policy(tmp_path, 0.5)
        assert main(["scan", ".", "-o", "out.json", "--no-github-summary", "--policy", "p.json"]) == 1
        for bad in ("high", 1.5):
            _policy(tmp_path, bad)
            assert main(["scan", ".", "-o", "out.json", "--no-github-summary", "--policy", "p.json"]) == 2
            err = capsys.readouterr().err
            assert "min_confidence" in err and "Traceback" not in err
    finally:
        os.chdir(cwd)


# ------------------------------------------------------------------ 범위
SCOPE_TREE = {"src/app.py": 'import hashlib\nhashlib.md5(b"")\n',
              "tests/test_app.py": 'import hashlib\nhashlib.md5(b"")\nhashlib.sha1(b"")\n',
              "examples/demo.py": 'import hashlib\nhashlib.sha384(b"")\n',
              "pkg/util_test.go": 'package pkg\nimport "crypto/sha512"\nvar _ = sha512.Sum512(nil)\n'}


def test_scope_property(tmp_path):
    _, bom = scan(tmp_path, SCOPE_TREE)
    assert prop(comp(bom, "MD5"), "scope") == "production,test"
    assert prop(comp(bom, "SHA-1"), "scope") == "test"
    assert prop(comp(bom, "SHA-384"), "scope") == "example"
    assert prop(comp(bom, "SHA-512"), "scope") == "test"


def test_scope_patterns(tmp_path):
    _, bom = scan(tmp_path, {"a/conftest.py": 'import hashlib\nhashlib.md5(b"")',
                             "a/FooTest.java": 'class FooTest { Object m = MessageDigest.getInstance("SHA-1"); }',
                             "a/x.spec.ts": "createHash('sha384')",
                             "Tests/Bar.cs": "var h = SHA512.Create();",
                             "Samples/s.go": 'package s\nimport "crypto/sha256"\nvar _ = sha256.Sum256(nil)'})
    for n in ("MD5", "SHA-1", "SHA-384", "SHA-512"):
        assert prop(comp(bom, n), "scope") == "test", n
    assert prop(comp(bom, "SHA-256"), "scope") == "example"


def test_scope_relative_to_scan_root(tmp_path):
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cwd = os.getcwd()
    os.chdir(repo)
    try:
        out = str(tmp_path / "demo.json")
        main(["scan", "examples/demo-app", "-o", out, "--fail-on", "never", "--no-github-summary"])
    finally:
        os.chdir(cwd)
    bom = json.loads(open(out, encoding="utf-8").read())
    src = [c for c in bom["components"]
           if any(o["location"].startswith("examples/demo-app/src/") for o in c.get("evidence", {}).get("occurrences", []))]
    assert src and all(prop(c, "scope") == "production" for c in src)


def test_report_marks(tmp_path):
    files = dict(SCOPE_TREE)
    files["src/p.py"] = 'print("ML-KEM-768")\n'
    scan(tmp_path, files)
    md = (tmp_path / "r.md").read_text(encoding="utf-8").splitlines()
    assert any("**SHA-1** (테스트·예제 전용)" in ln for ln in md)
    assert not any("**MD5**" in ln and "(테스트·예제 전용)" in ln for ln in md)
    i = next(i for i, ln in enumerate(md) if ln.startswith("정책 결과:"))
    nxt = next(ln for ln in md[i + 1:] if ln.strip())
    assert nxt == "탐지 참고: 테스트·예제 경로에서만 발견 3개 · 신뢰도 낮음 1개"
    assert any(ln.startswith("- ML-KEM-768") and "(신뢰도 낮음)" in ln for ln in md)
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert "(테스트·예제 전용)" in html and "탐지 참고:" in html


def test_no_detection_note_when_clean(tmp_path):
    scan(tmp_path, {"app/a.py": 'import hashlib\nh = hashlib.sha256(b"")\n'})
    assert "탐지 참고:" not in (tmp_path / "r.md").read_text(encoding="utf-8")


def test_scope_does_not_change_exit_or_annotations(tmp_path, monkeypatch, capsys):
    scan(tmp_path, SCOPE_TREE)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        capsys.readouterr()
        assert main(["scan", ".", "-o", "out.json", "--no-github-summary"]) == 1
    finally:
        os.chdir(cwd)
    assert any(ln.startswith("::error file=tests/test_app.py,line=3,title=cbom-scout SHA-1::")
               for ln in capsys.readouterr().out.splitlines())


# ------------------------------------------------------------------ 하위 호환
def test_deterministic_output(tmp_path):
    scan(tmp_path, SCOPE_TREE)
    a = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    scan(tmp_path, {})
    b = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    for x in (a, b):
        x.pop("serialNumber")
        x["metadata"].pop("timestamp")
    assert json.dumps(a, sort_keys=False) == json.dumps(b, sort_keys=False)


@pytest.mark.parametrize("files", [
    {"c.py": 'import hashlib\nHASH_ALG = "sha1"\nKEY_BITS = 1024\ndef f(d):\n    return hashlib.new(HASH_ALG, d)\n'
             "from Crypto.PublicKey import RSA\nk = RSA.generate(KEY_BITS)\n"},
    {"A.java": 'class A {\n  /* MessageDigest.getInstance("MD5");\n     x */\n'
               '  Object c = Cipher.getInstance("AES/GCM/NoPadding");\n}\n'},
])
def test_crlf_same_as_lf(tmp_path, files):
    _, lf = scan(tmp_path / "lf", files)
    _, crlf = scan(tmp_path / "crlf", {k: v.replace("\n", "\r\n") for k, v in files.items()})

    def key(bom):
        return sorted((c["name"], sorted(occs(c)), prop(c, "scope"), json.dumps(c["evidence"].get("identity")))
                      for c in bom["components"])
    assert key(lf) == key(crlf)


def test_outputs_pass_schema(tmp_path, cdx_validator):
    trees = [SCOPE_TREE, {"all.py": ALL_PY},
             {"p.py": 'print("ML-KEM-768")\n', "sshd_config": "KexAlgorithms curve25519-sha256\n",
              "nginx.conf": "ssl_protocols TLSv1.2 TLSv1.3;\n", "s.java": "// -----BEGIN RSA PRIVATE KEY-----\n"}]
    for i, t in enumerate(trees):
        _, bom = scan(tmp_path / str(i), t)
        errors = list(cdx_validator.iter_errors(bom))
        assert not errors, [e.message for e in errors[:5]]


def test_certs_only_components_have_no_identity(tmp_path):
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = str(tmp_path / "out.json")
    main(["scan", os.path.join(repo, "examples", "demo-app", "certs"), "-o", out, "--fail-on", "never",
          "--no-github-summary"])
    bom = json.loads(open(out, encoding="utf-8").read())
    certs_only = [c for c in bom["components"] if prop(c, "scanners") == "certs"]
    assert certs_only and all("identity" not in c.get("evidence", {}) for c in certs_only)


def test_baseline_report_marks(tmp_path):
    files = dict(SCOPE_TREE)
    files["src/p.py"] = 'print("ML-KEM-768")\n'
    scan(tmp_path, files)
    os.replace(tmp_path / "out.json", tmp_path / "base.json")
    (tmp_path / "tests/test_app.py").write_text(SCOPE_TREE["tests/test_app.py"] + 'hashlib.sha224(b"")\n',
                                                encoding="utf-8")
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        main(["scan", ".", "--baseline", "base.json", "--markdown", "r2.md", "--fail-on", "never",
              "--no-github-summary"])
    finally:
        os.chdir(cwd)
    md = (tmp_path / "r2.md").read_text(encoding="utf-8")
    new = md.split("## 신규 위반 (기준선 대비)")[1].split("## 기존 위반")[0]
    assert any("SHA-224" in ln and "(테스트·예제 전용)" in ln for ln in new.splitlines())


def test_old_baseline_comment_false_positive_resolved(tmp_path, capsys):
    files = {"app/a.py": "import hashlib\n# hashlib.md5(x)\nhashlib.sha1(b\"\")\n"}
    scan(tmp_path, files, "--engine", "regex")
    old = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    for c in old["components"]:          # 이전 버전 CBOM 처럼 새 필드를 지운다
        c.get("evidence", {}).pop("identity", None)
        for o in c.get("evidence", {}).get("occurrences", []):
            o.pop("symbol", None)
        c["properties"] = [p for p in c.get("properties", []) if p["name"] != "cbom-scout:scope"]
    assert comp(old, "MD5") is not None
    (tmp_path / "old.json").write_text(json.dumps(old), encoding="utf-8")
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        capsys.readouterr()
        assert main(["scan", ".", "--baseline", "old.json", "--markdown", "r.md", "--no-github-summary",
                     "-o", "x.json"]) == 0
        err = capsys.readouterr().err
        assert "신규 실패 0" in err and "해결 1건" in err
        main(["scan", ".", "-o", "new.json", "--fail-on", "never", "--no-github-summary"])
        capsys.readouterr()
        main(["scan", ".", "--baseline", "new.json", "-o", "y.json", "--no-github-summary"])
        err = capsys.readouterr().err
        assert "신규 실패 0 / 신규 경고 0 / 신규 참고 0" in err and "해결 0건" in err
    finally:
        os.chdir(cwd)
