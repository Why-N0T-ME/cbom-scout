"""기준선(baseline) 비교 인수 테스트 — docs/specs/baseline.md 완료 기준(AC-1~AC-36).

실제 CLI 를 하위 프로세스로 돌려 종료 코드·stderr·stdout·출력 파일을 확인한다.
"""
import json
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEMO = os.path.join(ROOT, "examples", "demo-app")
SCHEMAS = os.path.join(ROOT, "tests", "schemas")

F0 = "import hashlib\nhashlib.md5(b'')\n"
R = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
     "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
KEY_BODY = "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu"
KEY = f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----\n"
P_WARN = {"name": "t-warn", "status": {"broken": {"action": "fail"}, "quantum-vulnerable": {"action": "warn"}},
          "default": {"action": "info"}}
SUMMARY_RE = re.compile(r"^기준선 대비: 신규 실패 (\d+) / 신규 경고 (\d+) / 신규 참고 (\d+) · 기존 (\d+)건 · "
                        r"해결 (\d+)건 → (실패|경고|참고|통과)$")


class Run:
    def __init__(self, p):
        self.code, self.out, self.err = p.returncode, p.stdout, p.stderr

    def __repr__(self):
        return f"<code={self.code}\nstdout={self.out}\nstderr={self.err}>"


@pytest.fixture
def T(tmp_path):
    (tmp_path / "app").mkdir()
    return tmp_path


def cli(T, *args, env=None):
    e = {k: v for k, v in os.environ.items() if k not in ("GITHUB_STEP_SUMMARY", "GITHUB_ACTIONS")}
    e["PYTHONIOENCODING"] = "utf-8"
    e.update(env or {})
    p = subprocess.run([sys.executable, "-m", "cbom_scout.cli", *args], cwd=str(T), env=e,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return Run(p)


def w(T, rel, text):
    p = T / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def rd(T, rel):
    return (T / rel).read_text(encoding="utf-8")


def mkbase(T, *extra, out="base.json"):
    r = cli(T, "scan", "app", "-o", out, "--fail-on", "never", *extra)
    assert r.code == 0, r
    return r


def C(T, *extra, env=None):
    return cli(T, "scan", "app", "-o", "cur.json", "--baseline", "base.json", *extra, env=env)


def section(md, title_prefix):
    """'## title_prefix' 로 시작하는 절의 본문 (다음 '## ' 전까지)."""
    lines = md.splitlines()
    out, on = [], False
    for ln in lines:
        if ln.startswith("## "):
            on = ln.startswith("## " + title_prefix)
            continue
        if on:
            out.append(ln)
    return "\n".join(out)


def new_sec(md):
    return section(md, "신규 위반")


def old_sec(md):
    return section(md, "기존 위반")


def res_sec(md):
    return section(md, "해결")


def summary(r):
    lines = r.err.splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("cbom-scout: 자산"):
            assert i + 1 < len(lines), r
            m = SUMMARY_RE.match(lines[i + 1])
            assert m, f"요약 줄 형식 불일치: {lines[i + 1]!r}"
            return m.groups()
    raise AssertionError(f"요약 줄 없음: {r}")


def comp_by_name(bom, name):
    return [c for c in bom["components"] if c.get("name") == name]


def prop(c, name):
    for p in c.get("properties", []):
        if p["name"] == name:
            return p["value"]
    return None


def foreign_base(T, location):
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "cryptographic-asset", "bom-ref": "foreign/md5", "name": "md5",
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
         "evidence": {"occurrences": [{"location": location}]}}]}
    (T / "base.json").write_text(json.dumps(bom), encoding="utf-8")


def tls_comp(port):
    return {"type": "cryptographic-asset", "bom-ref": f"crypto/protocol/tls/api.example.com-{port}",
            "name": f"TLS api.example.com:{port}",
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "1.0"}},
            "evidence": {"occurrences": [{"location": f"api.example.com:{port}"}]},
            "properties": [{"name": "cbom-scout:status", "value": "broken"},
                           {"name": "cbom-scout:scanners", "value": "tls"}]}


def cdx(comps):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": comps}


# ================================================================== 정상 경로
def test_ac1_no_change_passes(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    assert C(T).code == 0
    r = cli(T, "scan", "app", "-o", "cur.json")
    assert r.code == 1, r


def test_ac2_line_shift_is_not_new(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/a.py", "# 주석\n\n\n" + F0)
    r = C(T)
    assert r.code == 0, r


def test_ac3_new_file_fails(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/b.py", F0)
    r = C(T, "--markdown", "r.md")
    assert r.code == 1, r
    md = rd(T, "r.md")
    assert "app/b.py" in new_sec(md) and "app/a.py" not in new_sec(md)
    assert "app/a.py" in old_sec(md)


def test_ac4_new_algorithm_in_existing_file(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/a.py", F0 + "hashlib.sha1(b'')\n")
    r = C(T, "--markdown", "r.md")
    assert r.code == 1, r
    md = rd(T, "r.md")
    assert "SHA-1" in new_sec(md) and "MD5" not in new_sec(md)
    assert "MD5" in old_sec(md)


def test_ac5_new_violation_follows_fail_on(T):
    w(T, "pwarn.json", json.dumps(P_WARN))
    w(T, "app/a.py", F0)
    mkbase(T, "--policy", "pwarn.json")
    w(T, "app/a.py", F0 + R)
    r = C(T, "--policy", "pwarn.json", "--markdown", "r.md")
    assert r.code == 0, r
    ns = new_sec(rd(T, "r.md"))
    row = [ln for ln in ns.splitlines() if "RSA-2048" in ln]
    assert row and "경고" in row[0], ns
    assert C(T, "--policy", "pwarn.json", "--fail-on", "warn").code == 1


def test_ac6_existing_never_fails(T):
    w(T, "pwarn.json", json.dumps(P_WARN))
    w(T, "app/a.py", F0 + R)
    mkbase(T, "--policy", "pwarn.json")
    assert C(T, "--policy", "pwarn.json", "--fail-on", "warn").code == 0
    assert C(T, "--policy", "pwarn.json", "--fail-on", "info").code == 0


def test_ac7_resolved(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/a.py", "import hashlib\nhashlib.sha384(b'')\n")
    r = C(T, "--markdown", "r.md")
    assert r.code == 0, r
    assert "해결 1건" in r.err
    rs = res_sec(rd(T, "r.md"))
    assert "MD5" in rs and "app/a.py" in rs


def test_ac8_check_command(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    assert cli(T, "scan", "app", "-o", "cur0.json", "--fail-on", "never").code == 0
    assert cli(T, "check", "cur0.json", "--baseline", "base.json").code == 0
    w(T, "app/b.py", F0)
    assert cli(T, "scan", "app", "-o", "cur0.json", "--fail-on", "never").code == 0
    assert cli(T, "check", "cur0.json", "--baseline", "base.json").code == 1


def test_ac9_self_compare_demo(T):
    assert cli(T, "scan", DEMO, "-o", "d.json", "--fail-on", "never").code == 0
    types = {(c.get("cryptoProperties") or {}).get("assetType") for c in json.loads(rd(T, "d.json"))["components"]}
    assert {"certificate", "related-crypto-material", "protocol", "algorithm"} <= types, types
    r = cli(T, "scan", DEMO, "-o", "d2.json", "--baseline", "d.json")
    assert r.code == 0, r
    g = summary(r)
    assert g[:3] == ("0", "0", "0"), g


def test_ac10_fail_on_never(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/b.py", F0)
    assert C(T, "--fail-on", "never").code == 0


# ================================================================== 줄 번호 견고성
def test_ac11_secret_key_line_shift(T):
    w(T, "app/secret.txt", KEY)
    mkbase(T)
    w(T, "app/secret.txt", "\n\n" + KEY)
    r = C(T)
    assert r.code == 0, r


def test_ac12_secret_key_new_file(T):
    w(T, "app/secret.txt", KEY)
    mkbase(T)
    w(T, "app/secret2.txt", KEY)
    r = C(T, "--markdown", "r.md")
    assert r.code == 1, r
    assert "app/secret2.txt" in new_sec(rd(T, "r.md"))


def test_ac13_no_key_material_anywhere(T):
    w(T, "app/secret.txt", KEY)
    mkbase(T)
    assert KEY_BODY not in rd(T, "base.json")
    w(T, "app/secret.txt", "\n\n" + KEY)
    outs = []
    r = C(T, "--markdown", "r.md", "--html", "r.html", "-v", env={"GITHUB_ACTIONS": "true"})
    outs += [r.out, r.err, rd(T, "cur.json"), rd(T, "r.md"), rd(T, "r.html")]
    w(T, "app/secret2.txt", KEY)
    summ = T / "summary.md"
    r = C(T, "--markdown", "r.md", "--html", "r.html", "-v",
          env={"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": str(summ)})
    assert r.code == 1, r
    outs += [r.out, r.err, rd(T, "cur.json"), rd(T, "r.md"), rd(T, "r.html"), summ.read_text(encoding="utf-8")]
    for o in outs:
        assert KEY_BODY not in o
        assert "MIIBOgIBAAJBAKj34" not in o


def test_ac14_tls_config_line_shift(T):
    w(T, "app/nginx.conf", "ssl_protocols TLSv1 TLSv1.2;\n")
    mkbase(T)
    b = json.loads(rd(T, "base.json"))
    assert any((c.get("cryptoProperties") or {}).get("assetType") == "protocol" for c in b["components"]), b
    w(T, "app/nginx.conf", "# 설정\n" * 5 + "ssl_protocols TLSv1 TLSv1.2;\n")
    r = C(T)
    assert r.code == 0, r


def test_ac15_tls_endpoint_port(T):
    (T / "base.json").write_text(json.dumps(cdx([tls_comp(443)])), encoding="utf-8")
    (T / "cur.json").write_text(json.dumps(cdx([tls_comp(443), tls_comp(8443)])), encoding="utf-8")
    r = cli(T, "check", "cur.json", "--baseline", "base.json", "--markdown", "r.md")
    assert r.code == 1, r
    ns = new_sec(rd(T, "r.md"))
    assert "api.example.com:8443" in ns
    assert "api.example.com:443`" not in ns and "api.example.com:443 " not in ns
    (T / "cur.json").write_text(json.dumps(cdx([tls_comp(443)])), encoding="utf-8")
    r = cli(T, "check", "cur.json", "--baseline", "base.json")
    assert r.code == 0, r


# ================================================================== 기준선 오류
def assert_baseline_error(T, r, path_shown):
    assert r.code == 2, r
    assert "기준선" in r.err, r
    assert path_shown in r.err, r
    assert "Traceback" not in r.err, r
    for f in ("cur.json", "r.md", "r.html"):
        assert not (T / f).exists(), f


def C_err(T, baseline):
    return cli(T, "scan", "app", "-o", "cur.json", "--markdown", "r.md", "--html", "r.html", "--baseline", baseline)


def test_ac16_missing_baseline(T):
    w(T, "app/a.py", F0)
    assert_baseline_error(T, C_err(T, "nope.json"), "nope.json")


def test_ac16_check_missing_baseline(T):
    w(T, "app/a.py", F0)
    mkbase(T, out="cur0.json")
    r = cli(T, "check", "cur0.json", "--baseline", "nope.json", "-o", "cur.json", "--markdown", "r.md")
    assert_baseline_error(T, r, "nope.json")


def test_ac17_directory_baseline(T):
    w(T, "app/a.py", F0)
    assert_baseline_error(T, C_err(T, "app"), "app")


def test_ac18_broken_json(T):
    w(T, "app/a.py", F0)
    w(T, "bad.json", "{not json")
    assert_baseline_error(T, C_err(T, "bad.json"), "bad.json")


@pytest.mark.parametrize("content", ["{}", "[]", '{"bomFormat":"SPDX"}'])
def test_ac19_not_cyclonedx(T, content):
    w(T, "app/a.py", F0)
    w(T, "bad.json", content)
    assert_baseline_error(T, C_err(T, "bad.json"), "bad.json")


@pytest.mark.parametrize("content", ['{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}',
                                     '{"bomFormat":"CycloneDX","specVersion":"1.6"}'])
def test_ac20_empty_baseline(T, content):
    w(T, "app/a.py", F0)
    w(T, "base.json", content)
    r = C(T, "--markdown", "r.md")
    assert r.code == 1, r
    assert "MD5" in new_sec(rd(T, "r.md"))


@pytest.mark.parametrize("spec", ["1.4", "1.5"])
def test_ac20_spec_version_not_checked(T, spec):
    w(T, "app/a.py", F0)
    w(T, "base.json", json.dumps({"bomFormat": "CycloneDX", "specVersion": spec, "components": []}))
    assert C(T).code == 1


def test_ac21_foreign_baseline(T):
    w(T, "app/a.py", F0)
    foreign_base(T, "app/a.py")
    r = C(T)
    assert r.code == 0, r


@pytest.mark.parametrize("loc,code", [("app\\a.py", 0), ("./app/a.py", 0), ("App/a.py", 1)])
def test_ac22_location_normalization(T, loc, code):
    w(T, "app/a.py", F0)
    foreign_base(T, loc)
    r = C(T)
    assert r.code == code, r


def test_ac23_no_overlap_warning(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    b = json.loads(rd(T, "base.json"))
    for c in b["components"]:
        for o in (c.get("evidence") or {}).get("occurrences", []):
            o["location"] = "other/root/a.py"
    w(T, "base.json", json.dumps(b))
    r = C(T)
    assert r.code == 1, r
    assert "겹치지 않습니다" in r.err


def test_ac23_no_warning_when_empty(T):
    w(T, "app/a.py", F0)
    w(T, "base.json", '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}')
    r = C(T)
    assert "겹치지 않습니다" not in r.err, r
    # 현재 위반이 비어 있는 경우
    w(T, "app/a.py", "import hashlib\nhashlib.sha384(b'')\n")
    foreign_base(T, "other/root/a.py")
    r = C(T)
    assert "겹치지 않습니다" not in r.err, r


# ================================================================== 결정에 따른 동작
def test_ac24_same_file_more_occurrences(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/a.py", F0 + "hashlib.md5(b'x')\n")
    assert C(T).code == 0


def test_ac25_stricter_policy_existing(T):
    w(T, "app/a.py", F0 + R)
    mkbase(T)
    r = C(T, "--policy", "strict", "--markdown", "r.md")
    assert r.code == 0, r
    os_ = old_sec(rd(T, "r.md"))
    row = [ln for ln in os_.splitlines() if "RSA-2048" in ln]
    assert row and "실패" in row[0], os_


def test_ac26_rename_is_new(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    os.rename(T / "app" / "a.py", T / "app" / "c.py")
    r = C(T, "--markdown", "r.md")
    assert r.code == 1, r
    md = rd(T, "r.md")
    assert "app/c.py" in new_sec(md)
    assert "app/a.py" in res_sec(md)


# ================================================================== 출력
def test_ac27_console_summary(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/a.py", F0 + "hashlib.sha1(b'')\n")
    r = C(T)
    assert summary(r) == ("1", "0", "0", "1", "0", "실패")


def test_ac28_verbose_tags(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/a.py", F0 + "hashlib.sha1(b'')\n")
    r = C(T, "-v")
    lines = r.err.splitlines()
    assert any("[신규]" in ln and "SHA-1" in ln for ln in lines), r
    assert any("[기존]" in ln and "MD5" in ln for ln in lines), r
    assert not any("[신규]" in ln and "MD5" in ln for ln in lines), r


def test_ac29_github_annotations_new_only(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/b.py", F0)
    r = C(T, env={"GITHUB_ACTIONS": "true"})
    assert "::error file=app/b.py,line=2" in r.out, r
    bad = [ln for ln in r.out.splitlines()
           if (ln.startswith("::error") or ln.startswith("::warning")) and "file=app/a.py" in ln]
    assert not bad, bad


def test_ac30_markdown_structure(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/b.py", F0)
    summ = T / "summary.md"
    r = C(T, "--markdown", "r.md", env={"GITHUB_STEP_SUMMARY": str(summ)})
    md = rd(T, "r.md")
    verdict = [ln for ln in md.splitlines() if "판정" in ln][0]
    assert "기준선 대비" in verdict and "실패" in verdict, verdict
    i_new, i_old = md.find("## 신규 위반 (기준선 대비)"), md.find("## 기존 위반")
    assert 0 <= i_new < i_old, md
    o = old_sec(md)
    assert "<details>" in o and "</details>" in o
    d0, d1 = o.find("<details>"), o.find("</details>")
    assert d0 < o.find("app/a.py") < d1
    assert md in summ.read_text(encoding="utf-8")
    # 신규 0건
    (T / "app" / "b.py").unlink()
    r = C(T, "--markdown", "r.md")
    assert r.code == 0
    assert "기준선 대비 새로 생긴 위반이 없습니다" in new_sec(rd(T, "r.md"))


def test_ac31_html(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/b.py", F0)
    C(T, "--html", "r.html")
    h = rd(T, "r.html")
    rows = re.findall(r"<tr.*?</tr>", h, re.S)
    assert any("신규" in x and "app/b.py" in x and "app/a.py" not in x for x in rows), rows
    assert any("기존" in x and "app/a.py" in x and "app/b.py" not in x for x in rows), rows


def _validator():
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    reg = referencing.Registry()
    for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
        with open(os.path.join(SCHEMAS, name), encoding="utf-8") as fh:
            res = referencing.Resource.from_contents(json.load(fh))
        reg = reg.with_resource(f"http://cyclonedx.org/schema/{name}", res).with_resource(name, res)
    with open(os.path.join(SCHEMAS, "bom-1.6.schema.json"), encoding="utf-8") as fh:
        return jsonschema.Draft7Validator(json.load(fh), registry=reg)


def test_ac32_cbom_property_and_schema(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/a.py", F0 + "hashlib.sha1(b'')\nhashlib.sha384(b'')\n")
    w(T, "app/b.py", F0)  # MD5 가 기존(a.py)+신규(b.py) 위치를 모두 가짐
    C(T)
    bom = json.loads(rd(T, "cur.json"))
    assert prop(comp_by_name(bom, "SHA-1")[0], "cbom-scout:baseline") == "new"
    assert prop(comp_by_name(bom, "MD5")[0], "cbom-scout:baseline") == "new"
    for c in bom["components"]:
        if prop(c, "cbom-scout:policy-action") == "pass":
            assert prop(c, "cbom-scout:baseline") is None, c["name"]
    errs = list(_validator().iter_errors(bom))
    assert not errs, errs[:3]


def test_ac32_existing_value(T):
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/a.py", F0 + "hashlib.sha1(b'')\n")
    C(T)
    bom = json.loads(rd(T, "cur.json"))
    assert prop(comp_by_name(bom, "SHA-1")[0], "cbom-scout:baseline") == "new"
    assert prop(comp_by_name(bom, "MD5")[0], "cbom-scout:baseline") == "existing"
    assert not list(_validator().iter_errors(bom))


# ================================================================== 하위 호환
def test_ac33_no_baseline_unchanged(T):
    r = cli(T, "scan", DEMO, "-o", "x.json", "--markdown", "r.md")
    assert r.code == 1, r
    assert "기준선" not in r.err
    md = rd(T, "r.md")
    assert "기준선" not in md and "신규 위반" not in md
    assert "cbom-scout:baseline" not in rd(T, "x.json")


def test_ac34_merge_rejects_baseline(T):
    w(T, "a.json", json.dumps(cdx([])))
    r = cli(T, "merge", "a.json", "-o", "m.json", "--baseline", "b.json")
    assert r.code == 2, r


def test_ac35_help_and_readme(T):
    for cmd in ("scan", "check"):
        r = cli(T, cmd, "--help")
        assert r.code == 0
        assert "--baseline" in r.out
        idx = r.out.find("--baseline")
        assert re.search(r"[가-힣]", r.out[idx:idx + 300]), r.out[idx:idx + 300]
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    assert "--baseline" in readme
    assert "신규" in readme and "기준선" in readme
    exit_lines = [ln for ln in readme.splitlines() if "2" in ln and "기준선" in ln]
    assert exit_lines, "README 종료 코드 2 설명에 기준선 오류 없음"


def test_ac36_action_input():
    a = open(os.path.join(ROOT, "action.yml"), encoding="utf-8").read()
    m = re.search(r"^  baseline:\r?\n((?:    .*\r?\n)+)", a, re.M)
    assert m, "action.yml 에 baseline 입력 없음"
    assert re.search(r'^    default: ""\s*$', m.group(1), re.M), m.group(1)
    assert "IN_BASELINE: ${{ inputs.baseline }}" in a
    assert re.search(r'if \[ -n "\$IN_BASELINE" \]; then args\+=\(--baseline "\$IN_BASELINE"\); fi', a)
    assert a.count("--baseline") == 1


# ================================================================== 추가 점검 (명세 외)
def test_extra_windows_backslash_and_korean_baseline_path(tmp_path):
    T = tmp_path / "한글 폴더"
    (T / "app").mkdir(parents=True)
    w(T, "app/a.py", F0)
    (T / "기준").mkdir()
    assert cli(T, "scan", "app", "-o", os.path.join("기준", "기준선.json"), "--fail-on", "never").code == 0
    r = cli(T, "scan", "app", "-o", "cur.json", "--baseline", "기준\\기준선.json" if os.name == "nt"
            else "기준/기준선.json")
    assert r.code == 0, r
    w(T, "app/b.py", F0)
    r = cli(T, "scan", "app", "-o", "cur.json", "--baseline", str(T / "기준" / "기준선.json"),
            env={"GITHUB_ACTIONS": "true"})
    assert r.code == 1, r
    assert "::error file=app/b.py,line=2" in r.out, r


def test_extra_korean_missing_baseline_path(T):
    w(T, "app/a.py", F0)
    assert_baseline_error(T, C_err(T, "없는\\기준선.json"), "기준선.json")


def test_extra_scan_target_backslash(T):
    w(T, "app/sub/a.py", F0)
    assert cli(T, "scan", "app", "-o", "base.json", "--fail-on", "never").code == 0
    target = "app\\sub" if os.name == "nt" else "app/sub"
    # 다른 대상 경로로 스캔해도 위치는 '/' 구분 상대경로
    r = cli(T, "scan", target, "-o", "cur.json", "--baseline", "base.json")
    bom = json.loads(rd(T, "cur.json"))
    locs = [o["location"] for c in bom["components"] for o in (c.get("evidence") or {}).get("occurrences", [])]
    assert all("\\" not in l for l in locs), locs


@pytest.mark.parametrize("content", [
    '{"bomFormat":"CycloneDX","components":[{"type":"cryptographic-asset","name":"md5","evidence":"x"}]}',
    '{"bomFormat":"CycloneDX","components":[{"type":"cryptographic-asset","name":"md5","cryptoProperties":"x"}]}',
    '{"bomFormat":"CycloneDX","components":[{"type":"cryptographic-asset","name":5,'
    '"cryptoProperties":{"assetType":"algorithm"}}]}',
    '{"bomFormat":"CycloneDX","components":[{"type":"cryptographic-asset","name":"md5",'
    '"evidence":{"occurrences":[{"location":null}]}}]}',
    '{"bomFormat":"CycloneDX","components":[1, "x", null]}',
])
def test_extra_malformed_components_no_traceback(T, content):
    """CycloneDX 이지만 구성요소 형식이 이상한 기준선 — 트레이스백 없이 0/1/2 중 하나로 끝나야 한다."""
    w(T, "app/a.py", F0)
    w(T, "base.json", content)
    r = C(T)
    assert "Traceback" not in r.err, r
    assert r.code in (0, 1, 2), r


def test_extra_utf8_bom_baseline(T):
    """Windows 편집기(메모장 등)가 UTF-8 BOM 을 붙인 기준선."""
    w(T, "app/a.py", F0)
    mkbase(T)
    data = rd(T, "base.json")
    (T / "base.json").write_bytes(b"\xef\xbb\xbf" + data.encode("utf-8"))
    r = C(T)
    assert "Traceback" not in r.err, r
    assert r.code in (0, 2), r


def test_extra_cur_output_reused_as_baseline(T):
    """--baseline 으로 만든 cur.json 을 다음 기준선으로 써도 된다."""
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/b.py", F0)
    C(T)
    os.replace(T / "cur.json", T / "base.json")
    assert C(T).code == 0


def test_extra_check_stale_baseline_prop(T):
    """기준선 결과가 들어간 CBOM 을 check 로 다시 평가할 때 기존 baseline 속성이 남지 않아야 한다 (AC-33/32 취지)."""
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/b.py", F0)
    C(T)
    r = cli(T, "check", "cur.json", "-o", "re.json", "--fail-on", "never")
    assert r.code == 0
    assert "cbom-scout:baseline" not in rd(T, "re.json")


def test_extra_baseline_same_as_output(T):
    """-o 와 --baseline 이 같은 파일이어도 기준선을 먼저 읽어 비교한다."""
    w(T, "app/a.py", F0)
    mkbase(T)
    r = cli(T, "scan", "app", "-o", "base.json", "--baseline", "base.json")
    assert r.code == 0, r


def test_ac32_check_pass_component_has_no_baseline_prop(T):
    """AC-32: pass 구성요소에는 cbom-scout:baseline 속성이 없다 — check 입력 CBOM 에 남은 이전 값 포함."""
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/b.py", F0)
    C(T)
    w(T, "pass.json", json.dumps({"name": "allpass", "status": {}, "default": {"action": "pass"}}))
    r = cli(T, "check", "cur.json", "--baseline", "base.json", "--policy", "pass.json", "-o", "re.json")
    assert r.code == 0, r
    bom = json.loads(rd(T, "re.json"))
    for c in bom["components"]:
        if prop(c, "cbom-scout:policy-action") == "pass":
            assert prop(c, "cbom-scout:baseline") is None, c["name"]


# ------------------------------------------------------------------ 2회차 추가 점검
def _foreign(occ_loc="app/a.py", name="md5", **extra):
    c = {"type": "cryptographic-asset", "name": name,
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
         "evidence": {"occurrences": [{"location": occ_loc}]}}
    c.update(extra)
    return c


def test_r2_foreign_baseline_without_bom_ref(T):
    """AC-21 취지: 다른 도구가 만든 기준선. CycloneDX 1.6 에서 bom-ref 는 선택 필드이므로 없어도 맞춰야 한다."""
    w(T, "app/a.py", F0)
    w(T, "base.json", json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [_foreign()]}))
    r = C(T)
    assert "Traceback" not in r.err, r
    assert r.code == 0, r


def test_r2_foreign_baseline_without_bom_ref_resolved(T):
    """bom-ref 없는 기준선 구성요소가 현재 없으면 해결로 보고, 트레이스백이 없어야 한다."""
    w(T, "app/a.py", F0)
    w(T, "base.json", json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                                  "components": [_foreign(), _foreign("app/z.py", "sha1")]}))
    r = C(T)
    assert "Traceback" not in r.err, r
    assert r.code == 0, r
    assert "해결 1건" in r.err, r


@pytest.mark.parametrize("props", [
    [{"name": "cbom-scout:scanners", "value": 5}],
    [{"name": "cbom-scout:status", "value": ["broken"]}],
])
def test_r2_malformed_property_value_no_traceback(T, props):
    """D3 와 같은 계열: properties 의 value 가 문자열이 아닌 기준선 — 트레이스백 없이 끝나야 한다 (오류면 2)."""
    w(T, "app/a.py", F0)
    c = _foreign("app/a.py:2", **{"bom-ref": "x", "properties": props})
    w(T, "base.json", json.dumps({"bomFormat": "CycloneDX", "components": [c]}))
    r = C(T)
    assert "Traceback" not in r.err, r
    assert r.code in (0, 2), r
    if r.code == 2:
        assert "기준선" in r.err and not (T / "cur.json").exists()


def test_r2_duplicate_bom_ref_resolved_count(T):
    """bom-ref 가 중복된 기준선(스키마상 잘못된 입력). 해결 건수가 부풀려지지 않거나 오류 2 여야 한다."""
    w(T, "app/a.py", F0)
    w(T, "base.json", json.dumps({"bomFormat": "CycloneDX", "components": [
        _foreign(**{"bom-ref": "x"}), _foreign("app/z.py", "sha1", **{"bom-ref": "x"})]}))
    r = C(T)
    assert "Traceback" not in r.err, r
    if r.code != 2:
        assert r.code == 0, r
        assert "해결 1건" in r.err, r


def test_r2_check_rerun_output_schema_valid(T):
    """D1 수정 경로: check --baseline 재평가 출력도 CycloneDX 1.6 스키마를 통과한다."""
    w(T, "app/a.py", F0)
    mkbase(T)
    w(T, "app/b.py", F0)
    C(T)
    w(T, "pass.json", json.dumps({"name": "allpass", "status": {}, "default": {"action": "pass"}}))
    r = cli(T, "check", "cur.json", "--baseline", "base.json", "--policy", "pass.json", "-o", "re.json")
    assert r.code == 0, r
    bom = json.loads(rd(T, "re.json"))
    assert all(prop(c, "cbom-scout:baseline") is None for c in bom["components"])
    _validator().validate(bom)


# ================================================================== 3회차: D4~D6 수정 경로 회귀
def test_r3_property_without_name(T):
    """properties 항목에 name 이 없어도(값만 있음) 트레이스백 없이 정상 비교한다."""
    w(T, "app/a.py", F0)
    w(T, "base.json", json.dumps({"bomFormat": "CycloneDX", "components": [
        _foreign(**{"properties": [{"value": "x"}]})]}))
    r = C(T)
    assert "Traceback" not in r.err, r
    assert r.code == 0, r


def test_r3_compare_error_leaves_no_outputs(T):
    """재평가 단계(compare)에서 기준선 오류가 나도 공통 오류 기대: 2, '기준선'+경로, 출력 파일·STEP_SUMMARY 없음."""
    w(T, "app/a.py", F0)
    c = _foreign("app/z.py", "RSA-2048")
    c["cryptoProperties"]["algorithmProperties"] = {"parameterSetIdentifier": "²"}
    w(T, "base.json", json.dumps({"bomFormat": "CycloneDX", "components": [c]}))
    summ = T / "summary.md"
    r = C(T, "--markdown", "r.md", "--html", "r.html", env={"GITHUB_STEP_SUMMARY": str(summ)})
    assert "Traceback" not in r.err, r
    assert r.code in (0, 2), r
    if r.code == 2:
        assert "기준선" in r.err and "base.json" in r.err, r
        for f in ("cur.json", "r.md", "r.html"):
            assert not (T / f).exists(), f
        assert not summ.exists() or summ.read_text(encoding="utf-8") == ""


def test_r3_resolved_without_bom_ref_no_internal_ref_leak(T):
    """bom-ref 없는 기준선의 해결 항목: 리포트에 원래 이름·위치가 나오고 내부 임시 ref(baseline/N)가 새지 않는다."""
    w(T, "app/a.py", F0)
    w(T, "base.json", json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                                  "components": [_foreign(), _foreign("app/z.py", "sha1")]}))
    r = C(T, "--markdown", "r.md", "--html", "r.html", "-v")
    assert r.code == 0, r
    md, html = rd(T, "r.md"), rd(T, "r.html")
    rs = res_sec(md)
    assert "sha1" in rs and "app/z.py" in rs, md
    assert "md5" not in rs.lower(), md
    for text in (md, html, r.err, rd(T, "cur.json")):
        assert "baseline/0" not in text and "baseline/1" not in text
    _validator().validate(json.loads(rd(T, "cur.json")))


@pytest.mark.parametrize("content", ["null", "5", "", '"CycloneDX"', "true"])
def test_r3_non_object_json_baseline(T, content):
    """최상위가 객체가 아닌 JSON·빈 파일 → AC-16~19 공통 기대."""
    w(T, "app/a.py", F0)
    w(T, "base.json", content)
    r = C(T)
    assert r.code == 2, r
    assert "기준선" in r.err and "base.json" in r.err and "Traceback" not in r.err, r
    assert not (T / "cur.json").exists()


def test_r3_non_utf8_baseline(T):
    """UTF-8 이 아닌(CP949) 기준선 → 트레이스백 없이 2."""
    w(T, "app/a.py", F0)
    (T / "base.json").write_bytes('{"bomFormat":"CycloneDX","metadata":{"x":"한글"},"components":[]}'.encode("cp949"))
    r = C(T)
    assert r.code == 2, r
    assert "기준선" in r.err and "Traceback" not in r.err, r
    assert not (T / "cur.json").exists()


def test_r3_duplicate_unit_in_two_baseline_components(T):
    """같은 발견 단위(MD5@app/z.py)가 기준선 두 구성요소에 있어도 해결은 1건."""
    w(T, "app/a.py", F0)
    w(T, "base.json", json.dumps({"bomFormat": "CycloneDX", "components": [
        _foreign(), _foreign("app/z.py", "MD5", **{"bom-ref": "p"}), _foreign("app/z.py", "md5", **{"bom-ref": "q"})]}))
    r = C(T)
    assert r.code == 0, r
    assert summary(r)[3:] == ("1", "1", "통과"), r
