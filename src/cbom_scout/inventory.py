"""스캐너들이 찾은 결과를 모아 CycloneDX 1.6 CBOM 구성요소(component)로 만든다."""
from __future__ import annotations

import re
from typing import Iterable, Optional

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

    # ------------------------------------------------------------ 공통
    def _occ(self, comp: dict, location: Optional[str], line: Optional[int],
             context: Optional[str]) -> None:
        if not location:
            return
        occs = comp.setdefault("evidence", {}).setdefault("occurrences", [])
        occ = {"location": location}
        if line:
            occ["line"] = int(line)
        if context:
            occ["additionalContext"] = context[:200]
        if occ not in occs:
            occs.append(occ)

    def _depend(self, parent: str, child: str) -> None:
        self.dependencies.setdefault(parent, set()).add(child)

    # ------------------------------------------------------------ 알고리즘
    def add_algorithm(self, c: Classified, *, location: str | None = None, line: int | None = None,
                      context: str | None = None, function: str | None = None,
                      scanner: str = "") -> str:
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
        self._occ(comp, location, line, context)
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
        self._occ(comp, location, None, None)
        return ref

    # ------------------------------------------------------------ 키 자료
    def add_key_material(self, *, kind: str, alg_ref: str | None, size: int | None,
                         ident: str, location: str | None, line: int | None = None,
                         status: str = "", note: str = "", scanner: str = "") -> str:
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
        self._occ(comp, location, line, None)
        return ref

    # ------------------------------------------------------------ 프로토콜
    def add_protocol(self, *, ptype: str, version: str, endpoint: str,
                     suites: Iterable[tuple[str, list[str]]], alg_refs: list[str],
                     status: str = "", note: str = "", scanner: str = "tls",
                     extra: dict | None = None) -> str:
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
        self._occ(comp, endpoint, None, None)
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
            occs = cur.setdefault("evidence", {}).setdefault("occurrences", [])
            if occ not in occs:
                occs.append(occ)
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
