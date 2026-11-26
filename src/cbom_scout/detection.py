"""탐지 근거(신뢰도·탐지 방식)와 테스트·예제 범위 판정.

기준값은 data/detection.json 에 있다. 신뢰도·방식은 CycloneDX 1.6 표준 필드
`evidence.identity[].confidence`, `methods[].technique`/`confidence` 로 기록한다.
"""
from __future__ import annotations

import fnmatch
import json
import os
from typing import Optional

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "detection.json")
with open(_DATA_PATH, encoding="utf-8") as _fh:
    _DATA = json.load(_fh)

#: 상황 이름 → (technique, confidence)
CONFIDENCE: dict = {k: (v["technique"], float(v["confidence"])) for k, v in _DATA["confidence"].items()}
LOW_CONFIDENCE_BELOW: float = float(_DATA["low_confidence_below"])

_SCOPE = _DATA["scope"]
_TEST_DIRS = {d.lower() for d in _SCOPE["test_dirs"]}
_EXAMPLE_DIRS = {d.lower() for d in _SCOPE["example_dirs"]}
_TEST_FILES = list(_SCOPE["test_files"])

SCOPES = ("example", "production", "test")


def detection(kind: str) -> tuple:
    """상황 이름(예: 'ast-direct') → (technique, confidence)."""
    return CONFIDENCE[kind]


def classify_scope(rel_path: str) -> str:
    """스캔 루트 기준 '/' 구분 상대경로 → 'test' / 'example' / 'production'."""
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts:
        return "production"
    dirs, name = [p.lower() for p in parts[:-1]], parts[-1]
    if any(d in _TEST_DIRS for d in dirs) or any(fnmatch.fnmatchcase(name, pat) for pat in _TEST_FILES):
        return "test"
    if any(d in _EXAMPLE_DIRS for d in dirs):
        return "example"
    return "production"


def scope_fn_for(root: str, rel_to: str):
    """위치(rel_to 기준 상대경로) → 범위. 범위는 스캔 루트(root) 기준으로 판정한다."""
    base = os.path.abspath(root if os.path.isdir(root) else os.path.dirname(root))
    rel_base = os.path.abspath(rel_to)

    def fn(location: str) -> Optional[str]:
        ap = os.path.normpath(os.path.join(rel_base, location.replace("/", os.sep)))
        rp = os.path.relpath(ap, base)
        if rp.startswith(".."):
            rp = location
        return classify_scope(rp.replace(os.sep, "/"))
    return fn


def name_confidence(comp: dict) -> Optional[float]:
    """구성요소의 이름 식별 신뢰도 (evidence.identity 중 field == 'name'). 없으면 None."""
    ident = (comp.get("evidence") or {}).get("identity")
    if isinstance(ident, dict):
        ident = [ident]
    if not isinstance(ident, list):
        return None
    for el in ident:
        if isinstance(el, dict) and el.get("field") == "name":
            c = el.get("confidence")
            if isinstance(c, (int, float)) and not isinstance(c, bool):
                return float(c)
    return None


def scopes_of(comp: dict) -> set:
    from .inventory import get_prop
    raw = get_prop(comp, "scope") or ""
    return {s for s in raw.split(",") if s}


def is_test_only(comp: dict) -> bool:
    s = scopes_of(comp)
    return bool(s) and "production" not in s


def is_low_confidence(comp: dict) -> bool:
    c = name_confidence(comp)
    return c is not None and c < LOW_CONFIDENCE_BELOW
