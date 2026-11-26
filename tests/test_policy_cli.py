import datetime as dt
import json

from conftest import DEMO

from cbom_scout.cbom import inventory_from_boms, to_cbom
from cbom_scout.cli import main
from cbom_scout.inventory import Inventory, get_prop
from cbom_scout.policy import evaluate, load_policy, should_fail
from cbom_scout.scanners.certs import scan_certs
from cbom_scout.scanners.code import scan_code


def demo_bom():
    inv = Inventory()
    scan_code(DEMO, inv)
    scan_certs(DEMO, inv)
    return to_cbom(inv, subject="demo")


def test_cbom_schema_valid(cdx_validator):
    bom = demo_bom()
    errors = list(cdx_validator.iter_errors(bom))
    assert not errors, [e.message for e in errors[:5]]
    assert bom["specVersion"] == "1.6" and bom["bomFormat"] == "CycloneDX"


def test_fail_after_escalation():
    policy = load_policy()
    bom = demo_bom()
    before = evaluate(bom, policy, today=dt.date(2026, 11, 1))
    qv_before = {f.action for f in before.findings if f.status == "quantum-vulnerable"}
    assert qv_before == {"warn"}
    after = evaluate(demo_bom(), policy, today=dt.date(2031, 1, 1))
    qv_after = {f.action for f in after.findings if f.status == "quantum-vulnerable"}
    assert qv_after == {"fail"}


def test_strict_and_overrides():
    policy = load_policy()
    policy["overrides"] = [{"name": "MD5", "action": "info", "message": "레거시 체크섬 예외 승인"}]
    res = evaluate(demo_bom(), policy, today=dt.date(2026, 11, 1))
    md5 = next(f for f in res.findings if f.name == "MD5")
    assert md5.action == "info"
    assert should_fail(res, "fail")          # 다른 broken 항목 존재
    assert not should_fail(res, "never")


def test_foreign_cbom_reclassified():
    foreign = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "cryptographic-asset", "bom-ref": "x/rsa", "name": "RSA-2048",
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "pke"}}},
        {"type": "cryptographic-asset", "bom-ref": "x/mlkem", "name": "ML-KEM-768",
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "kem"}}}]}
    bom = to_cbom(inventory_from_boms([foreign]))
    res = evaluate(bom, load_policy(), today=dt.date(2026, 11, 1))
    st = {f.name: f.status for f in res.findings}
    assert st == {"RSA-2048": "quantum-vulnerable", "ML-KEM-768": "pqc"}


def test_cli_scan_and_merge(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    out, md, html = tmp_path / "c.json", tmp_path / "r.md", tmp_path / "r.html"
    rc = main(["scan", DEMO, "-o", str(out), "--markdown", str(md), "--html", str(html)])
    assert rc == 1                                   # 데모에는 broken 항목이 있다
    assert main(["scan", DEMO, "-o", str(out), "--fail-on", "never"]) == 0
    bom = json.loads(out.read_text(encoding="utf-8"))
    assert any(get_prop(c, "policy-action") == "fail" for c in bom["components"])
    assert "암호자산 리포트" in md.read_text(encoding="utf-8")
    assert "<table>" in html.read_text(encoding="utf-8")
    merged = tmp_path / "m.json"
    assert main(["merge", str(out), str(out), "-o", str(merged)]) == 0
    assert len(json.loads(merged.read_text())["components"]) == len(bom["components"])
    assert main(["check", str(merged), "--policy", "strict", "--fail-on", "warn"]) == 1


def test_github_summary(tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    main(["scan", DEMO, "-o", str(tmp_path / "c.json"), "--fail-on", "never"])
    assert "판정" in summary.read_text(encoding="utf-8")
