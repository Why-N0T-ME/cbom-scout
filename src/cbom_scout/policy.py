"""정책 평가.

정책은 JSON 파일이다. 상태(status)별로 조치(pass/info/warn/fail)를 정하고,
`fail_after` 날짜를 주면 그 날 이후 자동으로 fail 로 올라간다.
알고리즘 판정 기준을 코드가 아니라 정책 파일로 두면, 기준이 바뀔 때
배포 없이 교체할 수 있다 — 이것이 암호 민첩성의 실제 모습이다.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from dataclasses import dataclass, field
from typing import Optional

from .catalog import classify
from .inventory import get_prop, set_prop

ACTIONS = ["pass", "info", "warn", "fail"]
DEFAULT_POLICY_PATH = os.path.join(os.path.dirname(__file__), "policies", "nist-ir8547.json")


@dataclass
class Finding:
    ref: str
    name: str
    status: str
    action: str
    message: str
    locations: list = field(default_factory=list)


@dataclass
class Result:
    policy: str
    findings: list
    counts: dict

    def worst(self) -> str:
        return worst_of(f.action for f in self.findings)


def worst_of(actions) -> str:
    """조치 목록 중 가장 높은 것. 비어 있으면 pass."""
    worst = "pass"
    for a in actions:
        if ACTIONS.index(a) > ACTIONS.index(worst):
            worst = a
    return worst


def load_policy(path: Optional[str] = None) -> dict:
    with open(path or DEFAULT_POLICY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _status_of(comp: dict) -> str:
    st = get_prop(comp, "status")
    if st:
        return st
    # 다른 도구가 만든 CBOM: 이름으로 다시 판정
    cp = comp.get("cryptoProperties", {})
    if cp.get("assetType") == "algorithm":
        ap = cp.get("algorithmProperties", {})
        size = ap.get("parameterSetIdentifier")
        c = classify(comp.get("name", "").split("-")[0] if comp.get("name", "").upper().startswith(("RSA-", "DSA-", "DH-"))
                     else comp.get("name", ""), size=int(size) if str(size or "").isdigit() else None,
                     mode=ap.get("mode"))
        set_prop(comp, "status", c.status)
        return c.status
    return "unknown"


def evaluate(bom: dict, policy: dict, today: Optional[dt.date] = None) -> Result:
    today = today or dt.date.today()
    rules = policy.get("status", {})
    findings, counts = [], {a: 0 for a in ACTIONS}
    for comp in bom.get("components", []):
        if comp.get("type") != "cryptographic-asset":
            continue
        st = _status_of(comp)
        rule = rules.get(st, policy.get("default", {"action": "info"}))
        action = rule.get("action", "info")
        fa = rule.get("fail_after")
        msg = rule.get("message", "")
        if fa and today >= dt.date.fromisoformat(fa):
            action = "fail"
            msg = (msg + f" (정책상 {fa}부터 금지)").strip()
        for over in policy.get("overrides", []):
            if over.get("name") and over["name"].lower() == comp.get("name", "").lower():
                action, msg = over.get("action", action), over.get("message", msg)
        note = get_prop(comp, "note")
        if note:
            msg = f"{msg} — {note}" if msg else note
        locs = [o.get("location", "") + (f":{o['line']}" if o.get("line") else "")
                for o in comp.get("evidence", {}).get("occurrences", [])]
        set_prop(comp, "policy-action", action)
        counts[action] += 1
        findings.append(Finding(comp["bom-ref"], comp.get("name", ""), st, action, msg, locs))
    findings.sort(key=lambda f: (-ACTIONS.index(f.action), f.name))
    return Result(policy.get("name", "policy"), findings, counts)


def should_fail(result: Result, fail_on: str) -> bool:
    return fails_at(result.worst(), fail_on)


def fails_at(action: str, fail_on: str) -> bool:
    """action 이 --fail-on 수준 이상인지. 기준선 비교에서는 신규 위반의 최고 조치에 쓴다."""
    if fail_on == "never":
        return False
    return ACTIONS.index(action) >= ACTIONS.index(fail_on)
