"""스캐너들이 찾은 결과를 모아 CycloneDX 1.6 CBOM 구성요소(component)로 만든다."""
from __future__ import annotations

import re
from typing import Callable, Iterable, Optional

from .catalog import Classified, STATUS_LABEL_KO, classify

PROP_PREFIX = "cbom-scout:"


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]+", "-", text).strip("-")


def get_prop(component: dict, name: str) -> Optional[str]:
    for p in component.get("properties", []):
        if p.get("name") == PROP_PREFIX + name:
            return p.get("value")
    return None


def set_prop(component: dict, name: str, value: str) -> None:
    props = component.setdefault("properties", [])
    for p in props:
        if p.get("name") == PROP_PREFIX + name:
            p["value"] = value
            return
    props.append({"name": PROP_PREFIX + name, "value": value})


class Inventory:
    """bom-ref 를 키로 하는 구성요소 모음. 같은 자산은 occurrence 만 늘어난다."""

    def __init__(self) -> None:
        self.components: dict[str, dict] = {}
        self.dependencies: dict[str, set] = {}
        #: 위치 → 범위(test/example/production). 스캐너가 스캔하는 동안만 설정한다.
        self.scope_fn: Optional[Callable[[str], Optional[str]]] = None
        self._occ_idx: dict = {}     # bom-ref → (occurrences 목록, {(location, line): occurrence})

    # ------------------------------------------------------------ 공통
    def _occ(self, comp: dict, location: Optional[str], line: Optional[int],
             symbol: Optional[str] = None) -> None:
        # 소스 줄 원문(additionalContext)은 기록하지 않는다 — 같은 줄의 하드코딩 키가 CBOM 에 새기 때문.
        if not location:
            return
        occ: dict = {"location": location}
        if line:
            occ["line"] = int(line)
        if symbol:
            occ["symbol"] = symbol
        self._add_occ(comp, occ)
        if self.scope_fn is not None:
            scope = self.scope_fn(re.sub(r":\d+$", "", location))
            if scope and scope not in (get_prop(comp, "scope") or "").split(","):
                add_scope(comp, {scope})

    def _add_occ(self, comp: dict, occ: dict) -> None:
        """같은 (location, line) 은 하나만 남긴다. 나중 것에만 symbol 이 있으면 채운다."""
        occs = comp.setdefault("evidence", {}).setdefault("occurrences", [])
        ref = comp.get("bom-ref")
        idx = self._occ_idx.get(ref)
        if idx is None or idx[0] is not occs:
            idx = (occs, {(o.get("location"), o.get("line")): o for o in occs if isinstance(o, dict)})
            self._occ_idx[ref] = idx
        key = (occ.get("location"), occ.get("line"))
        cur = idx[1].get(key)
        if cur is not None:
            if "symbol" in occ and "symbol" not in cur:
                cur["symbol"] = occ["symbol"]
            return
        new = dict(occ)
        occs.append(new)
        idx[1][key] = new

    def _detect(self, comp: dict, technique: Optional[str], confidence: Optional[float]) -> None:
        """탐지 방식·신뢰도를 표준 필드 evidence.identity 에 반영한다."""
        if technique and confidence is not None:
            for el in comp.get("evidence", {}).get("identity") or []:
                if isinstance(el, dict) and el.get("field") == "name":
                    if any(m.get("technique") == technique and _num(m.get("confidence")) >= confidence
                           for m in el.get("methods", [])):
                        return          # 이미 같은 방식으로 더 높거나 같은 신뢰도
            add_identity(comp, {"field": "name", "concludedValue": comp.get("name", ""),
                                "confidence": confidence,
                                "methods": [{"technique": technique, "confidence": confidence}]})

    def _depend(self, parent: str, child: str) -> None:
        self.dependencies.setdefault(parent, set()).add(child)

    # ------------------------------------------------------------ 알고리즘
    def add_algorithm(self, c: Classified, *, location: str | None = None, line: int | None = None,
                      function: str | None = None,
                      scanner: str = "", technique: str | None = None,
                      confidence: float | None = None, symbol: str | None = None) -> str:
        ref = f"crypto/algorithm/{_slug(c.key)}"
        comp = self.components.get(ref)
        if comp is None:
            alg: dict = {"primitive": c.primitive, "nistQuantumSecurityLevel": c.nist_qsl,
                         "executionEnvironment": "software-plain-ram"}
            if c.parameter:
                alg["parameterSetIdentifier"] = c.parameter
            if c.curve:
                alg["curve"] = c.curve
            if c.mode:
                mode = c.mode.lower()
                if mode in ("cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"):
                    alg["mode"] = mode
            cp: dict = {"assetType": "algorithm", "algorithmProperties": alg}
            if c.oid:
                cp["oid"] = c.oid
            comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": c.key,
                    "cryptoProperties": cp}
            set_prop(comp, "status", c.status)
            set_prop(comp, "status-label", STATUS_LABEL_KO.get(c.status, c.status))
            if c.note:
                set_prop(comp, "note", c.note)
            self.components[ref] = comp
        if function:
            fns = comp["cryptoProperties"]["algorithmProperties"].setdefault("cryptoFunctions", [])
            if function not in fns:
                fns.append(function)
        if scanner:
            scanners = set((get_prop(comp, "scanners") or "").split(",")) - {""}
            scanners.add(scanner)
            set_prop(comp, "scanners", ",".join(sorted(scanners)))
        self._occ(comp, location, line, symbol)
        self._detect(comp, technique, confidence)
        return ref

    def add_algorithm_by_name(self, name: str, **kw) -> str:
        size = kw.pop("size", None)
        curve = kw.pop("curve", None)
        mode = kw.pop("mode", None)
        return self.add_algorithm(classify(name, size=size, curve=curve, mode=mode), **kw)

    # ------------------------------------------------------------ 인증서
    def add_certificate(self, *, fingerprint: str, subject: str, issuer: str,
                        not_before: str, not_after: str, sig_ref: str | None,
                        key_ref: str | None, location: str | None, fmt: str = "X.509",
                        status: str = "", note: str = "", scanner: str = "certs") -> str:
        ref = f"crypto/certificate/{fingerprint[:24]}"
        comp = self.components.get(ref)
        if comp is None:
            props: dict = {"subjectName": subject, "issuerName": issuer,
                           "notValidBefore": not_before, "notValidAfter": not_after,
                           "certificateFormat": fmt}
            if sig_ref:
                props["signatureAlgorithmRef"] = sig_ref
            if key_ref:
                props["subjectPublicKeyRef"] = key_ref
            comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": subject or fingerprint[:24],
                    "cryptoProperties": {"assetType": "certificate", "certificateProperties": props}}
            if status:
                set_prop(comp, "status", status)
                set_prop(comp, "status-label", STATUS_LABEL_KO.get(status, status))
            if note:
                set_prop(comp, "note", note)
            set_prop(comp, "scanners", scanner)
            self.components[ref] = comp
        for r in (sig_ref, key_ref):
            if r:
                self._depend(ref, r)
        self._occ(comp, location, None)
        return ref

    # ------------------------------------------------------------ 키 자료
    def add_key_material(self, *, kind: str, alg_ref: str | None, size: int | None,
                         ident: str, location: str | None, line: int | None = None,
                         status: str = "", note: str = "", scanner: str = "",
                         technique: str | None = None, confidence: float | None = None) -> str:
        ref = f"crypto/key/{kind}/{_slug(ident)[:40]}"
        comp = self.components.get(ref)
        if comp is None:
            rp: dict = {"type": kind}
            if alg_ref:
                rp["algorithmRef"] = alg_ref
            if size:
                rp["size"] = int(size)
            comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": f"{kind}:{ident}",
                    "cryptoProperties": {"assetType": "related-crypto-material",
                                         "relatedCryptoMaterialProperties": rp}}
            if not status and alg_ref and alg_ref in self.components:
                status = get_prop(self.components[alg_ref], "status") or ""
            if status:
                set_prop(comp, "status", status)
                set_prop(comp, "status-label", STATUS_LABEL_KO.get(status, status))
            if note:
                set_prop(comp, "note", note)
            if scanner:
                set_prop(comp, "scanners", scanner)
            self.components[ref] = comp
        if alg_ref:
            self._depend(ref, alg_ref)
        self._occ(comp, location, line)
        self._detect(comp, technique, confidence)
        return ref

    # ------------------------------------------------------------ 프로토콜
    def add_protocol(self, *, ptype: str, version: str, endpoint: str,
                     suites: Iterable[tuple[str, list[str]]], alg_refs: list[str],
                     status: str = "", note: str = "", scanner: str = "tls",
                     extra: dict | None = None, technique: str | None = None,
                     confidence: float | None = None) -> str:
        ref = f"crypto/protocol/{ptype}/{_slug(endpoint)}"
        cipher_suites = [{"name": n, "algorithms": refs} for n, refs in suites]
        pp: dict = {"type": ptype, "version": version}
        if cipher_suites:
            pp["cipherSuites"] = cipher_suites
        if alg_refs:
            pp["cryptoRefArray"] = sorted(set(alg_refs))
        comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": f"{ptype.upper()} {endpoint}",
                "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp}}
        if status:
            set_prop(comp, "status", status)
            set_prop(comp, "status-label", STATUS_LABEL_KO.get(status, status))
        if note:
            set_prop(comp, "note", note)
        set_prop(comp, "scanners", scanner)
        for k, v in (extra or {}).items():
            set_prop(comp, k, str(v))
        self._occ(comp, endpoint, None)
        self._detect(comp, technique, confidence)
        self.components[ref] = comp
        for r in alg_refs:
            self._depend(ref, r)
        return ref

    # ------------------------------------------------------------ 병합
    def merge_component(self, comp: dict) -> None:
        ref = comp.get("bom-ref")
        if not ref:
            return
        cur = self.components.get(ref)
        if cur is None:
            self.components[ref] = comp
            return
        for occ in comp.get("evidence", {}).get("occurrences", []):
            self._add_occ(cur, occ)
        ident = comp.get("evidence", {}).get("identity")
        if isinstance(ident, dict):
            ident = [ident]
        for el in ident or []:
            if isinstance(el, dict):
                add_identity(cur, el)
        if get_prop(comp, "scope"):
            add_scope(cur, set((get_prop(comp, "scope") or "").split(",")))
        a = cur.get("cryptoProperties", {}).get("algorithmProperties")
        b = comp.get("cryptoProperties", {}).get("algorithmProperties")
        if a is not None and b is not None:
            for fn in b.get("cryptoFunctions", []):
                fns = a.setdefault("cryptoFunctions", [])
                if fn not in fns:
                    fns.append(fn)
        s1 = set((get_prop(cur, "scanners") or "").split(",")) | set((get_prop(comp, "scanners") or "").split(","))
        s1.discard("")
        if s1:
            set_prop(cur, "scanners", ",".join(sorted(s1)))


# ------------------------------------------------------------ 근거 도우미
def add_scope(comp: dict, scopes: set) -> None:
    cur = set((get_prop(comp, "scope") or "").split(",")) | set(scopes)
    cur.discard("")
    if cur:
        set_prop(comp, "scope", ",".join(sorted(cur)))


def add_identity(comp: dict, el: dict) -> None:
    """evidence.identity 에 원소를 합친다. field 가 같으면 methods 는 technique 별 최댓값,
    confidence 는 최댓값, concludedValue 는 먼저 있던 값을 쓴다."""
    ev = comp.setdefault("evidence", {})
    ident = ev.get("identity")
    if isinstance(ident, dict):          # 1.5 이전 단일 객체 형식
        ident = [ident]
    if not isinstance(ident, list):
        ident = []
    ev["identity"] = ident
    field = el.get("field")
    cur = next((x for x in ident if isinstance(x, dict) and x.get("field") == field), None)
    if cur is None:
        cur = {"field": field}
        ident.append(cur)
    if "concludedValue" not in cur and el.get("concludedValue") is not None:
        cur["concludedValue"] = el["concludedValue"]
    methods = {m["technique"]: m for m in cur.get("methods", []) if isinstance(m, dict) and "technique" in m}
    for m in el.get("methods", []) or []:
        if not isinstance(m, dict) or "technique" not in m:
            continue
        old = methods.get(m["technique"])
        if old is None or _num(m.get("confidence")) > _num(old.get("confidence")):
            methods[m["technique"]] = {**(old or {}), **m}
    if methods:
        cur["methods"] = [methods[t] for t in sorted(methods)]
    best = max([_num(cur.get("confidence")), _num(el.get("confidence"))]
               + [_num(m.get("confidence")) for m in cur.get("methods", [])])
    if best >= 0:
        cur["confidence"] = best
    # 키 순서를 고정한다 (같은 입력이면 같은 출력)
    order = ["field", "confidence", "concludedValue", "methods"]
    rebuilt = {k: cur[k] for k in order if k in cur}
    rebuilt.update({k: v for k, v in cur.items() if k not in rebuilt})
    cur.clear()
    cur.update(rebuilt)


def _num(v) -> float:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else -1.0
