"""기준선 비교 단위·CLI 테스트. 오탐(줄 이동을 신규로 보는 것)과 미탐을 함께 본다."""
import json
import os

import pytest
from conftest import ROOT

from cbom_scout.baseline import BaselineError, asset_key, load_baseline, location_path, units_of
from cbom_scout.cli import main

MD5 = "import hashlib\nhashlib.md5(b'')\n"
RSA = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
       "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
KEY = ("-----BEGIN RSA PRIVATE KEY-----\n"
       "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
       "-----END RSA PRIVATE KEY-----\n")


@pytest.fixture
def ws(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    (tmp_path / "app").mkdir()
    return tmp_path


def write(p, text):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def base(*extra):
    assert main(["scan", "app", "-o", "base.json", "--fail-on", "never", *extra]) == 0


def run(*extra):
    return main(["scan", "app", "-o", "cur.json", "--baseline", "base.json", *extra])


def read(p):
    return open(p, encoding="utf-8").read()


# ------------------------------------------------------------------ 식별 규칙
def comp(at, name="x", occs=(), props=None, **cp):
    c = {"type": "cryptographic-asset", "bom-ref": "r", "name": name,
         "cryptoProperties": {"assetType": at, **cp}, "evidence": {"occurrences": list(occs)}}
    if props:
        c["properties"] = [{"name": f"cbom-scout:{k}", "value": v} for k, v in props.items()]
    return c


def test_location_path_rules():
    alg = comp("algorithm", "MD5")
    assert location_path(alg, {"location": "./app/a.py", "line": 3}) == "app/a.py"
    assert location_path(alg, {"location": "app\\a.py"}) == "app/a.py"
    cfg = comp("protocol", props={"scanners": "code"})
    assert location_path(cfg, {"location": "app/nginx.conf:12"}) == "app/nginx.conf"
    ep = comp("protocol", props={"scanners": "tls"})
    assert location_path(ep, {"location": "api.example.com:443"}) == "api.example.com:443"
    foreign_ep = comp("protocol")
    assert location_path(foreign_ep, {"location": "api.example.com:8443"}) == "api.example.com:8443"
    assert location_path(alg, {"location": "App/a.py"}) == "App/a.py"   # 대소문자 구분


def test_asset_key_ignores_line_in_name():
    k1 = comp("related-crypto-material", "private-key:app/s.txt:1", relatedCryptoMaterialProperties={"type": "private-key"})
    k2 = comp("related-crypto-material", "private-key:app/s.txt:9", relatedCryptoMaterialProperties={"type": "private-key"})
    assert asset_key(k1) == asset_key(k2)
    assert asset_key(comp("algorithm", "md5")) == asset_key(comp("algorithm", "MD5"))
    assert units_of(comp("algorithm", "MD5")) == {(("algorithm", "md5"), ""): []}


@pytest.mark.parametrize("content", ["{not json", "{}", "[]", '{"bomFormat":"SPDX"}',
                                     '{"bomFormat":"CycloneDX","components":{}}'])
def test_load_baseline_rejects(tmp_path, content):
    p = tmp_path / "b.json"
    p.write_text(content, encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(str(p))


def test_load_baseline_missing_components(tmp_path):
    p = tmp_path / "b.json"
    p.write_text('{"bomFormat":"CycloneDX","specVersion":"1.4"}', encoding="utf-8")
    assert load_baseline(str(p))["components"] == []


# ------------------------------------------------------------------ CLI 흐름
def test_unchanged_passes_and_without_baseline_fails(ws):
    write(ws / "app/a.py", MD5)
    base()
    assert run() == 0
    assert main(["scan", "app", "-o", "x.json"]) == 1


def test_line_shift_is_not_new(ws):
    write(ws / "app/a.py", MD5)
    base()
    write(ws / "app/a.py", "# 주석\n\n\n" + MD5 + "hashlib.md5(b'x')\n")
    assert run() == 0


def test_new_file_fails_and_report_sections(ws, capsys):
    write(ws / "app/a.py", MD5)
    base()
    write(ws / "app/b.py", MD5)
    assert run("--markdown", "r.md", "--html", "r.html") == 1
    md = read("r.md")
    new_part, old_part = md.split("## 기존 위반")
    assert "## 신규 위반 (기준선 대비)" in new_part and "app/b.py" in new_part and "app/a.py" not in new_part
    assert "app/a.py" in old_part and "<details>" in old_part
    assert "기준선 대비 판정" in md
    html = read("r.html")
    assert "badge new'>신규</span></td><td><span class='badge fail'>실패</span></td><td><b>MD5" in html
    err = capsys.readouterr().err
    assert "기준선 대비: 신규 실패 1 / 신규 경고 0 / 신규 참고 0 · 기존 1건 · 해결 0건 → 실패" in err


def test_github_annotations_only_new(ws, monkeypatch, capsys):
    write(ws / "app/a.py", MD5)
    base()
    write(ws / "app/b.py", MD5)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    run()
    out = capsys.readouterr().out
    assert "::error file=app/b.py,line=2" in out
    assert "file=app/a.py" not in out


def test_new_algorithm_in_existing_file_and_cbom_prop(ws, capsys, cdx_validator):
    write(ws / "app/a.py", MD5)
    base()
    write(ws / "app/a.py", MD5 + "hashlib.sha1(b'')\nhashlib.sha384(b'')\n")
    assert run("-v") == 1
    err = capsys.readouterr().err
    assert any("[신규]" in ln and "SHA-1" in ln for ln in err.splitlines())
    assert any("[기존]" in ln and "MD5" in ln for ln in err.splitlines())
    bom = json.loads(read("cur.json"))
    props = {c["name"]: {p["name"]: p["value"] for p in c.get("properties", [])} for c in bom["components"]}
    assert props["SHA-1"]["cbom-scout:baseline"] == "new"
    assert props["MD5"]["cbom-scout:baseline"] == "existing"
    assert "cbom-scout:baseline" not in props["SHA-384"]
    assert not list(cdx_validator.iter_errors(bom))


def test_existing_never_fails_even_when_policy_stricter(ws):
    write(ws / "app/a.py", RSA)
    base()
    assert run("--policy", "strict") == 0
    assert run("--fail-on", "info") == 0


def test_new_warn_respects_fail_on(ws):
    pol = ws / "pwarn.json"
    pol.write_text(json.dumps({"name": "t", "status": {"broken": {"action": "fail"},
                                                         "quantum-vulnerable": {"action": "warn"}},
                               "default": {"action": "info"}}), encoding="utf-8")
    write(ws / "app/a.py", MD5)
    base("--policy", "pwarn.json")
    write(ws / "app/a.py", MD5 + RSA)
    assert run("--policy", "pwarn.json") == 0
    assert run("--policy", "pwarn.json", "--fail-on", "warn") == 1


def test_resolved_and_moved(ws, capsys):
    write(ws / "app/a.py", MD5)
    base()
    write(ws / "app/a.py", "import hashlib\nhashlib.sha384(b'')\n")
    assert run("--markdown", "r.md") == 0
    assert "해결 1건" in capsys.readouterr().err
    assert "## 해결된 위반 (1건)" in read("r.md") and "`app/a.py`" in read("r.md")
    os.remove(ws / "app/a.py")
    write(ws / "app/c.py", MD5)
    assert run() == 1     # 파일 이동은 신규 (알려진 한계)


def test_private_key_and_tls_config_line_shift(ws, capsys):
    write(ws / "app/secret.txt", KEY)
    write(ws / "app/nginx.conf", "ssl_protocols TLSv1 TLSv1.2;\n")
    base()
    write(ws / "app/secret.txt", "\n\n" + KEY)
    write(ws / "app/nginx.conf", "# 설정\n" * 5 + "ssl_protocols TLSv1 TLSv1.2;\n")
    assert run() == 0
    write(ws / "app/secret2.txt", KEY)
    assert run("-v", "--markdown", "r.md", "--html", "r.html") == 1
    err = capsys.readouterr().err
    for text in (err, read("cur.json"), read("r.md"), read("r.html")):
        assert "MIIBOgIBAAJBAKj34" not in text
    assert "app/secret2.txt" in read("r.md").split("## 기존 위반")[0]


@pytest.mark.parametrize("arg,content", [("nope.json", None), ("app", None),
                                         ("bad.json", "{not json"), ("bad.json", '{"bomFormat":"SPDX"}')])
def test_baseline_errors_exit_2_without_outputs(ws, capsys, arg, content):
    write(ws / "app/a.py", MD5)
    if content is not None:
        write(ws / arg, content)
    code = main(["scan", "app", "-o", "cur.json", "--markdown", "r.md", "--baseline", arg])
    assert code == 2
    err = capsys.readouterr().err
    assert "기준선" in err and arg in err and "Traceback" not in err
    assert not os.path.exists("cur.json") and not os.path.exists("r.md")


def test_empty_and_foreign_baseline(ws):
    write(ws / "app/a.py", MD5)
    write(ws / "base.json", '{"bomFormat":"CycloneDX","specVersion":"1.6"}')
    assert run() == 1
    foreign = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "cryptographic-asset", "bom-ref": "foreign/md5", "name": "md5",
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
         "evidence": {"occurrences": [{"location": "app\\a.py"}]}}]}
    write(ws / "base.json", json.dumps(foreign))
    assert run() == 0
    foreign["components"][0]["evidence"]["occurrences"][0]["location"] = "App/a.py"
    write(ws / "base.json", json.dumps(foreign))
    assert run() == 1


def test_no_overlap_warning(ws, capsys):
    write(ws / "app/a.py", MD5)
    base()
    capsys.readouterr()
    write(ws / "base.json", read("base.json").replace("app/a.py", "other/root/a.py"))
    assert run() == 1
    assert "겹치지 않습니다" in capsys.readouterr().err
    write(ws / "base.json", '{"bomFormat":"CycloneDX","components":[]}')
    run()
    assert "겹치지 않습니다" not in capsys.readouterr().err


def test_tls_endpoint_port_distinguished(ws):
    ep = {"type": "cryptographic-asset", "bom-ref": "crypto/protocol/tls/api.example.com-443",
          "name": "TLS api.example.com:443",
          "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "1.0"}},
          "evidence": {"occurrences": [{"location": "api.example.com:443"}]},
          "properties": [{"name": "cbom-scout:status", "value": "broken"},
                         {"name": "cbom-scout:scanners", "value": "tls"}]}
    ep2 = json.loads(json.dumps(ep).replace(":443", ":8443").replace("-443", "-8443"))
    write(ws / "base.json", json.dumps({"bomFormat": "CycloneDX", "components": [ep]}))
    write(ws / "cur1.json", json.dumps({"bomFormat": "CycloneDX", "components": [ep]}))
    write(ws / "cur2.json", json.dumps({"bomFormat": "CycloneDX", "components": [ep, ep2]}))
    assert main(["check", "cur1.json", "--baseline", "base.json"]) == 0
    assert main(["check", "cur2.json", "--baseline", "base.json", "--markdown", "r.md"]) == 1
    new_part = read("r.md").split("## 기존 위반")[0]
    assert "api.example.com:8443" in new_part and "api.example.com:443`" not in new_part


def test_demo_self_baseline_passes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    d, d2 = str(tmp_path / "d.json"), str(tmp_path / "d2.json")
    assert main(["scan", "examples/demo-app", "-o", d, "--fail-on", "never"]) == 0
    assert main(["scan", "examples/demo-app", "-o", d2, "--baseline", d]) == 0
    assert "신규 실패 0 / 신규 경고 0 / 신규 참고 0" in capsys.readouterr().err


def test_without_baseline_output_unchanged(ws, capsys):
    write(ws / "app/a.py", MD5)
    assert main(["scan", "app", "-o", "x.json", "--markdown", "r.md"]) == 1
    assert "기준선" not in capsys.readouterr().err
    assert "기준선" not in read("r.md") and "신규 위반" not in read("r.md")
    assert "cbom-scout:baseline" not in read("x.json")


def test_merge_rejects_baseline(ws):
    with pytest.raises(SystemExit) as e:
        main(["merge", "a.json", "-o", "m.json", "--baseline", "b.json"])
    assert e.value.code == 2
