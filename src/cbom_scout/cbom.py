"""CycloneDX 1.6 CBOM 직렬화·읽기·병합."""
from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Iterable

from . import __version__
from .inventory import Inventory

SPEC_VERSION = "1.6"
SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.6.schema.json"


def to_cbom(inv: Inventory, *, subject: str = "", serial: str | None = None,
            timestamp: str | None = None) -> dict:
    comps = sorted(inv.components.values(), key=lambda c: c["bom-ref"])
    for c in comps:
        occs = c.get("evidence", {}).get("occurrences")
        if occs:
            occs.sort(key=lambda o: (o.get("location", ""), o.get("line", 0)))
    meta: dict = {
        "timestamp": timestamp or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": {"components": [{"type": "application", "name": "cbom-scout", "version": __version__}]},
    }
    if subject:
        meta["component"] = {"type": "application", "name": subject, "bom-ref": f"subject/{subject}"}
    bom: dict = {
        "$schema": SCHEMA_URL,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": meta,
        "components": comps,
    }
    deps = [{"ref": ref, "dependsOn": sorted(children)}
            for ref, children in sorted(inv.dependencies.items()) if ref in inv.components]
    if deps:
        bom["dependencies"] = deps
    return bom


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save(bom: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def inventory_from_boms(boms: Iterable[dict]) -> Inventory:
    """여러 CBOM(다른 도구가 만든 것 포함)을 하나의 Inventory 로 합친다."""
    inv = Inventory()
    for bom in boms:
        for comp in bom.get("components", []):
            if comp.get("type") == "cryptographic-asset":
                inv.merge_component(json.loads(json.dumps(comp)))
        for d in bom.get("dependencies", []) or []:
            for child in d.get("dependsOn", []) or []:
                inv._depend(d["ref"], child)
    return inv
