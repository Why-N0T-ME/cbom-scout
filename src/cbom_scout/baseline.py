"""기준선(baseline) 비교.

기준 CBOM(예: main 브랜치 스캔 결과) 대비 현재 위반을 신규·기존·해결됨으로 나눈다.
PR CI 에서 이미 알고 있는 레거시 부채가 아니라 **새로 들어온** 취약 암호만 실패로 처리하기 위한 것이다.

- 비교 단위(발견 단위)는 (자산 식별자, 위치 경로) 쌍이다. 줄 번호는 보지 않는다.
- 어떤 상태가 위반인지는 이 모듈이 정하지 않는다. 정책 평가 결과(action)를 그대로 쓴다.
- 기준선 쪽의 policy-action·status 값은 비교에 쓰지 않는다 (정책이 엄격해져도 기존은 기존).
- 키·비밀 값(additionalContext 등)은 읽지도 출력하지도 않는다. 위치와 이름만 다룬다.
"""
from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass, field
from .inventory import PROP_PREFIX, get_prop, set_prop
from .policy import ACTIONS, Result, evaluate, worst_of

BASELINE_PROP = "baseline"
_LINE_SUFFIX = re.compile(r"^(?P<path>.+?):(?P<line>\d+)$")


class BaselineError(Exception):
    """기준선 파일을 쓸 수 없을 때. 메시지는 사용자에게 그대로 보여 준다."""


def load_baseline(path: str) -> dict:
    """기준선 파일을 읽고 CycloneDX 인지 확인한다. 문제가 있으면 BaselineError."""
    if not os.path.exists(path):
        raise BaselineError(f"기준선 파일을 찾을 수 없습니다: {path}")
    if not os.path.isfile(path):
        raise BaselineError(f"기준선 경로가 파일이 아닙니다: {path}")
    try:
        # utf-8-sig: PowerShell 등이 붙이는 BOM 도 허용
        with open(path, encoding="utf-8-sig") as fh:
            bom = json.load(fh)
    except (OSError, UnicodeDecodeError) as e:
        raise BaselineError(f"기준선 파일을 읽을 수 없습니다: {path} ({e.__class__.__name__})") from None
    except json.JSONDecodeError as e:
        raise BaselineError(f"기준선 파일이 올바른 JSON 이 아닙니다: {path} ({e.lineno}행 {e.colno}열)") from None
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        raise BaselineError(f"기준선 파일이 CycloneDX CBOM 이 아닙니다 (bomFormat 이 'CycloneDX' 여야 함): {path}")
    comps = bom.get("components")
    if comps is None:
        bom["components"] = []
    elif not isinstance(comps, list):
        raise BaselineError(f"기준선 파일의 components 가 목록이 아닙니다: {path}")
    for i, comp in enumerate(bom["components"]):
        problem = _component_problem(comp)
        if problem:
            raise BaselineError(f"기준선 파일의 components[{i}] 형식이 올바르지 않습니다 ({problem}): {path}")
    return bom


def _component_problem(comp) -> str:
    """비교·재평가에 쓰는 필드의 형식만 확인한다. 문제가 없으면 ''. 값(키 등)은 메시지에 넣지 않는다."""
    if not isinstance(comp, dict):
        return "객체가 아님"
    if comp.get("type") != "cryptographic-asset":
        return ""           # 비교 대상이 아니므로 형식을 따지지 않는다
    for k in ("name", "bom-ref"):
        if k in comp and not isinstance(comp[k], str):
            return f"{k} 가 문자열이 아님"
    cp = comp.get("cryptoProperties", {})
    if not isinstance(cp, dict):
        return "cryptoProperties 가 객체가 아님"
    if "assetType" in cp and not isinstance(cp["assetType"], str):
        return "cryptoProperties.assetType 이 문자열이 아님"
    for k in ("algorithmProperties", "relatedCryptoMaterialProperties", "protocolProperties"):
        if k in cp and not isinstance(cp[k], dict):
            return f"cryptoProperties.{k} 가 객체가 아님"
    ap = cp.get("algorithmProperties", {})
    if "mode" in ap and not isinstance(ap["mode"], str):
        return "algorithmProperties.mode 가 문자열이 아님"
    for k, sub in (("relatedCryptoMaterialProperties", "type"), ("protocolProperties", "type")):
        if sub in cp.get(k, {}) and not isinstance(cp[k][sub], str):
            return f"cryptoProperties.{k}.{sub} 가 문자열이 아님"
    ev = comp.get("evidence", {})
    if not isinstance(ev, dict):
        return "evidence 가 객체가 아님"
    occs = ev.get("occurrences", [])
    if not isinstance(occs, list):
        return "evidence.occurrences 가 목록이 아님"
    for o in occs:
        if not isinstance(o, dict):
            return "occurrence 가 객체가 아님"
        if "location" in o and not isinstance(o["location"], str):
            return "occurrence.location 이 문자열이 아님"
        if "line" in o and (isinstance(o["line"], bool) or not isinstance(o["line"], int)):
            return "occurrence.line 이 정수가 아님"
    props = comp.get("properties", [])
    if not isinstance(props, list) or not all(isinstance(p, dict) for p in props):
        return "properties 가 객체 목록이 아님"
    for p in props:
        for k in ("name", "value"):
            if k in p and not isinstance(p[k], str):
                return f"properties[].{k} 가 문자열이 아님"
    return ""


def clear_marks(bom: dict) -> None:
    """입력 CBOM 에 남아 있던 이전 비교 결과(cbom-scout:baseline)를 지운다. 이번 평가 결과만 남긴다."""
    name = PROP_PREFIX + BASELINE_PROP
    for comp in bom.get("components", []):
        props = comp.get("properties")
        if isinstance(props, list):
            kept = [p for p in props if not (isinstance(p, dict) and p.get("name") == name)]
            if len(kept) != len(props):
                if kept:
                    comp["properties"] = kept
                else:
                    del comp["properties"]


# ------------------------------------------------------------------ 식별 규칙
def asset_key(comp: dict) -> tuple:
    """자산 유형별 식별자. bom-ref 나 name 에 줄 번호가 들어가는 경우를 피한다."""
    cp = comp.get("cryptoProperties") or {}
    at = cp.get("assetType") or ""
    name = comp.get("name") or ""
    if at == "algorithm":
        return (at, name.lower())
    if at == "related-crypto-material":
        kind = (cp.get("relatedCryptoMaterialProperties") or {}).get("type")
        return (at, kind or name)
    if at == "protocol":
        ptype = (cp.get("protocolProperties") or {}).get("type")
        return (at, ptype or name)
    return (at, name)


def _is_endpoint(comp: dict, prefix: str) -> bool:
    """위치가 `host:port` (TLS 엔드포인트)인지. 이때 `:숫자` 는 줄 번호가 아니라 포트다."""
    scanners = get_prop(comp, "scanners")
    if scanners is not None:
        return "tls" in scanners.split(",")
    # 다른 도구가 만든 CBOM: 경로 구분자가 없으면 호스트로 본다
    return "/" not in prefix and "\\" not in prefix


def location_path(comp: dict, occ: dict) -> str:
    """occurrence 의 위치에서 줄 번호를 뺀 정규화 경로. 대소문자는 구분한다."""
    loc = str(occ.get("location") or "").replace("\\", "/")
    while loc.startswith("./"):
        loc = loc[2:]
    if "line" not in occ:
        m = _LINE_SUFFIX.match(loc)
        if m and not _is_endpoint(comp, m.group("path")):
            loc = m.group("path")
    return loc


def _display(occ: dict) -> str:
    loc = str(occ.get("location") or "")
    return loc + (f":{occ['line']}" if occ.get("line") else "")


def units_of(comp: dict) -> dict:
    """구성요소의 발견 단위 → 그 위치의 표시 문자열 목록. occurrence 가 없으면 경로는 ''."""
    key = asset_key(comp)
    out: dict = {}
    occs = (comp.get("evidence") or {}).get("occurrences") or []
    for occ in occs:
        if not isinstance(occ, dict):
            continue
        out.setdefault((key, location_path(comp, occ)), []).append(_display(occ))
    if not out:
        out[(key, "")] = []
    return out


# ------------------------------------------------------------------ 비교
@dataclass
class Entry:
    """한 구성요소의 한 분류(신규·기존·해결)에 속한 위치들."""
    ref: str
    name: str
    status: str
    action: str
    message: str
    asset_type: str
    paths: list = field(default_factory=list)
    locations: list = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.paths)


@dataclass
class Diff:
    new: list
    existing: list
    resolved: list
    no_overlap: bool = False

    def new_counts(self) -> dict:
        c = {a: 0 for a in ACTIONS}
        for e in self.new:
            c[e.action] += e.count
        return c

    @property
    def existing_count(self) -> int:
        return sum(e.count for e in self.existing)

    @property
    def resolved_count(self) -> int:
        return sum(e.count for e in self.resolved)

    def worst(self) -> str:
        return worst_of(e.action for e in self.new)


def _entry(f, comp: dict, units: list) -> Entry:
    locs = [d for _, ds in units for d in ds]
    return Entry(f.ref, f.name, f.status, f.action, f.message,
                 (comp.get("cryptoProperties") or {}).get("assetType", ""),
                 [p for (_, p), _ in units], locs)


def compare(bom: dict, result: Result, baseline: dict, policy: dict, today=None) -> Diff:
    """현재 평가 결과를 기준선과 비교한다. 위반 구성요소에 cbom-scout:baseline 속성을 단다."""
    comps = {c.get("bom-ref"): c for c in bom.get("components", [])}
    base_comps = [c for c in baseline.get("components", [])
                  if isinstance(c, dict) and c.get("type") == "cryptographic-asset"]
    base_units: dict = {}
    for c in base_comps:
        base_units.update(units_of(c))

    new, existing = [], []
    cur_units: set = set()
    viol_paths: set = set()
    for comp in comps.values():
        if comp.get("type") == "cryptographic-asset":
            cur_units.update(units_of(comp))
    for f in result.findings:
        if f.action == "pass":
            continue
        comp = comps.get(f.ref, {})
        n, e = [], []
        for u, ds in units_of(comp).items():
            (e if u in base_units else n).append((u, ds))
            viol_paths.add(u[1])
        if n:
            new.append(_entry(f, comp, n))
        if e:
            existing.append(_entry(f, comp, e))
        set_prop(comp, BASELINE_PROP, "new" if n else "existing")

    # 해결됨: 기준선을 현재 정책으로 평가해 위반인 단위 중 현재 스캔에 없는 것
    resolved = []
    if base_comps:
        # bom-ref 는 CycloneDX 에서 선택 필드이고 중복될 수도 있다. 재평가용 사본에는 고유 ref 를 붙인다.
        bb = {"components": copy.deepcopy(base_comps)}
        for i, c in enumerate(bb["components"]):
            c["bom-ref"] = f"baseline/{i}"
        try:
            bres = evaluate(bb, policy, today=today)
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise BaselineError(f"기준선 구성요소를 평가할 수 없습니다 ({e.__class__.__name__})") from None
        bmap = {c["bom-ref"]: c for c in bb["components"]}
        seen: set = set()     # 같은 발견 단위가 여러 구성요소에 있어도 한 번만 센다
        for f in bres.findings:
            if f.action == "pass":
                continue
            comp = bmap[f.ref]
            gone = [(u, ds) for u, ds in units_of(comp).items() if u not in cur_units and u not in seen]
            seen.update(u for u, _ in gone)
            if gone:
                resolved.append(_entry(f, comp, gone))

    base_paths = {p for (_, p) in base_units if p}
    cur_paths = {p for (_, p) in cur_units if p}
    viol_paths.discard("")
    no_overlap = bool(base_paths and viol_paths and not (base_paths & cur_paths))
    return Diff(new, existing, resolved, no_overlap)


def summary_line(diff: Diff, label: dict) -> str:
    c = diff.new_counts()
    return (f"기준선 대비: 신규 실패 {c['fail']} / 신규 경고 {c['warn']} / 신규 참고 {c['info']} · "
            f"기존 {diff.existing_count}건 · 해결 {diff.resolved_count}건 → {label[diff.worst()]}")


NO_OVERLAP_WARNING = ("경고: 기준선과 현재 스캔의 위치가 하나도 겹치지 않습니다. "
                      "기준선을 같은 작업 디렉터리 기준으로 만들었는지 확인하세요.")
