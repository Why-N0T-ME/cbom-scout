"""마크다운·HTML 리포트."""
from __future__ import annotations

import html
from collections import Counter

from .catalog import STATUS_LABEL_KO
from .detection import is_low_confidence, is_test_only
from .inventory import get_prop
from .policy import Result

ACTION_KO = {"fail": "실패", "warn": "경고", "info": "참고", "pass": "통과"}
ACTION_ICON = {"fail": "🔴", "warn": "🟠", "info": "🔵", "pass": "🟢"}
ASSET_KO = {"algorithm": "알고리즘", "certificate": "인증서", "protocol": "프로토콜",
            "related-crypto-material": "키 자료"}


def _asset_type(comp: dict) -> str:
    return comp.get("cryptoProperties", {}).get("assetType", "")


def summary_stats(bom: dict) -> dict:
    comps = [c for c in bom.get("components", []) if c.get("type") == "cryptographic-asset"]
    by_type = Counter(_asset_type(c) for c in comps)
    by_status = Counter(get_prop(c, "status") or "unknown" for c in comps)
    occ = sum(len(c.get("evidence", {}).get("occurrences", [])) for c in comps)
    algs = [c for c in comps if _asset_type(c) == "algorithm"]
    qv = sum(1 for c in algs if (get_prop(c, "status") in ("quantum-vulnerable", "broken")))
    pqc = sum(1 for c in algs if (get_prop(c, "status") in ("pqc", "hybrid")))
    return {"total": len(comps), "by_type": dict(by_type), "by_status": dict(by_status),
            "occurrences": occ, "algorithms": len(algs), "vulnerable_algorithms": qv, "pqc_algorithms": pqc}


TEST_ONLY_MARK = "(테스트·예제 전용)"
LOW_CONF_MARK = "(신뢰도 낮음)"


def marks(comp: dict) -> str:
    """자산 이름 뒤에 붙일 표시. 판정은 바꾸지 않는다."""
    out = ""
    if is_test_only(comp):
        out += " " + TEST_ONLY_MARK
    if is_low_confidence(comp):
        out += " " + LOW_CONF_MARK
    return out


def detection_note(bom: dict) -> str:
    """'탐지 참고:' 줄. 해당 자산이 없으면 빈 문자열."""
    comps = [c for c in bom.get("components", []) if c.get("type") == "cryptographic-asset"]
    t = sum(1 for c in comps if is_test_only(c))
    low = sum(1 for c in comps if is_low_confidence(c))
    if not t and not low:
        return ""
    return f"탐지 참고: 테스트·예제 경로에서만 발견 {t}개 · 신뢰도 낮음 {low}개"


def _locs_md(locations: list, max_locations: int) -> str:
    locs = ", ".join(f"`{l}`" for l in locations[:max_locations])
    if len(locations) > max_locations:
        locs += f" 외 {len(locations) - max_locations}곳"
    return locs


def _entry_rows(entries: list, max_locations: int, comps: dict) -> list:
    return [f"| {ACTION_ICON[e.action]} {ACTION_KO[e.action]} | **{_md(e.name)}**{marks(comps.get(e.ref, {}))} | "
            f"{ASSET_KO.get(e.asset_type, e.asset_type)} | {STATUS_LABEL_KO.get(e.status, e.status)} | "
            f"{_md(e.message)} | {_locs_md(e.locations, max_locations)} |" for e in entries]


_TABLE_HEAD = ["| 판정 | 자산 | 유형 | 상태 | 조치 | 위치 |", "|---|---|---|---|---|---|"]


def _baseline_sections(diff, max_locations: int, comps: dict) -> list:
    lines = ["## 신규 위반 (기준선 대비)", ""] + _TABLE_HEAD
    rows = _entry_rows(diff.new, max_locations, comps)
    lines += rows or ["| 🟢 | 기준선 대비 새로 생긴 위반이 없습니다 | | | | |"]
    lines += ["", "## 기존 위반", ""]
    if diff.existing:
        lines += [f"<details><summary>기준선에 이미 있던 위반 {diff.existing_count}건</summary>", ""]
        lines += _TABLE_HEAD + _entry_rows(diff.existing, max_locations, comps)
        lines += ["", "</details>"]
    else:
        lines.append("기준선에 있던 위반이 없습니다.")
    lines += ["", f"## 해결된 위반 ({diff.resolved_count}건)", ""]
    if diff.resolved:
        for e in diff.resolved:
            more = f" 외 {len(e.paths) - max_locations}곳" if len(e.paths) > max_locations else ""
            lines.append(f"- {_md(e.name)} — " + ", ".join(f"`{p}`" for p in e.paths[:max_locations]) + more)
    else:
        lines.append("기준선 대비 사라진 위반이 없습니다.")
    return lines


def to_markdown(bom: dict, result: Result, max_locations: int = 3, diff=None) -> str:
    s = summary_stats(bom)
    lines = ["# 🔐 cbom-scout 암호자산 리포트", ""]
    worst = result.worst()
    if diff is None:
        lines.append(f"**판정: {ACTION_ICON[worst]} {ACTION_KO[worst]}** · 정책 `{result.policy}`")
    else:
        bw = diff.worst()
        lines.append(f"**기준선 대비 판정: {ACTION_ICON[bw]} {ACTION_KO[bw]}** · "
                     f"전체 판정 {ACTION_ICON[worst]} {ACTION_KO[worst]} · 정책 `{result.policy}`")
    lines.append("")
    lines.append("| 전체 자산 | 알고리즘 | 취약 알고리즘 | PQC·하이브리드 | 발견 위치 |")
    lines.append("|---:|---:|---:|---:|---:|")
    lines.append(f"| {s['total']} | {s['algorithms']} | {s['vulnerable_algorithms']} | "
                 f"{s['pqc_algorithms']} | {s['occurrences']} |")
    lines.append("")
    c = result.counts
    lines.append(f"정책 결과: 🔴 실패 {c['fail']} · 🟠 경고 {c['warn']} · 🔵 참고 {c['info']} · 🟢 통과 {c['pass']}")
    lines.append("")
    note = detection_note(bom)
    if note:
        lines += [note, ""]
    comps = {x.get("bom-ref"): x for x in bom.get("components", [])}
    if diff is not None:
        lines += _baseline_sections(diff, max_locations, comps)
        _passed_details(lines, result, comps)
        lines += ["", "> CycloneDX 1.6 CBOM 원본은 워크플로 아티팩트로 내려받을 수 있습니다."]
        return "\n".join(lines) + "\n"
    lines.append("## 조치가 필요한 자산")
    lines.append("")
    lines.append("| 판정 | 자산 | 유형 | 상태 | 조치 | 위치 |")
    lines.append("|---|---|---|---|---|---|")
    shown = 0
    for f in result.findings:
        if f.action in ("pass",):
            continue
        comp = comps.get(f.ref, {})
        locs = ", ".join(f"`{l}`" for l in f.locations[:max_locations])
        if len(f.locations) > max_locations:
            locs += f" 외 {len(f.locations) - max_locations}곳"
        lines.append(f"| {ACTION_ICON[f.action]} {ACTION_KO[f.action]} | **{_md(f.name)}**{marks(comp)} | "
                     f"{ASSET_KO.get(_asset_type(comp), _asset_type(comp))} | "
                     f"{STATUS_LABEL_KO.get(f.status, f.status)} | {_md(f.message)} | {locs} |")
        shown += 1
    if shown == 0:
        lines.append("| 🟢 | 조치가 필요한 자산이 없습니다 | | | | |")
    _passed_details(lines, result, comps)
    lines += ["", "> CycloneDX 1.6 CBOM 원본은 워크플로 아티팩트로 내려받을 수 있습니다."]
    return "\n".join(lines) + "\n"


def _passed_details(lines: list, result: Result, comps: dict) -> None:
    passed = [f for f in result.findings if f.action == "pass"]
    if passed:
        lines += ["", "<details><summary>통과한 자산 " + str(len(passed)) + "개</summary>", ""]
        lines += [f"- {_md(f.name)} ({STATUS_LABEL_KO.get(f.status, f.status)}){marks(comps.get(f.ref, {}))}"
                  for f in passed]
        lines += ["", "</details>"]


def _md(t: str) -> str:
    return (t or "").replace("|", "\\|").replace("\n", " ")


def _html_row(f, asset_type: str, base_cell: str = "", mark: str = "") -> str:
    locs = "<br>".join(html.escape(l) for l in f.locations[:5])
    if len(f.locations) > 5:
        locs += f"<br>외 {len(f.locations) - 5}곳"
    return (f"<tr class='{f.action}'>{base_cell}<td><span class='badge {f.action}'>{ACTION_KO[f.action]}</span></td>"
            f"<td><b>{html.escape(f.name)}</b>{html.escape(mark)}</td><td>{ASSET_KO.get(asset_type, '')}</td>"
            f"<td>{html.escape(STATUS_LABEL_KO.get(f.status, f.status))}</td>"
            f"<td>{html.escape(f.message)}</td><td class='loc'>{locs}</td></tr>")


def to_html(bom: dict, result: Result, diff=None) -> str:
    s = summary_stats(bom)
    comps = {x["bom-ref"]: x for x in bom.get("components", [])}
    head = "<tr><th>판정</th><th>자산</th><th>유형</th><th>상태</th><th>조치</th><th>위치</th></tr>"
    baseline_p = ""
    if diff is None:
        rows = [_html_row(f, _asset_type(comps.get(f.ref, {})), mark=marks(comps.get(f.ref, {})))
                for f in result.findings]
    else:
        head = head.replace("<tr>", "<tr><th>기준선</th>", 1)
        rows = [_html_row(e, e.asset_type, "<td><span class='badge new'>신규</span></td>", marks(comps.get(e.ref, {})))
                for e in diff.new]
        rows += [_html_row(e, e.asset_type, "<td><span class='badge old'>기존</span></td>", marks(comps.get(e.ref, {})))
                 for e in diff.existing]
        for e in diff.resolved:
            paths = "<br>".join(html.escape(p) for p in e.paths[:5])
            rows.append(f"<tr class='pass'><td><span class='badge resolved'>해결</span></td><td></td>"
                        f"<td><b>{html.escape(e.name)}</b></td><td>{ASSET_KO.get(e.asset_type, '')}</td><td></td>"
                        f"<td>기준선 대비 사라짐</td><td class='loc'>{paths}</td></tr>")
        bw = diff.worst()
        nc = diff.new_counts()
        baseline_p = (f"<p>기준선 대비 판정: <b>{ACTION_KO[bw]}</b> · 신규 실패 {nc['fail']} / 신규 경고 {nc['warn']} / "
                      f"신규 참고 {nc['info']} · 기존 {diff.existing_count}건 · 해결 {diff.resolved_count}건</p>")
    c = result.counts
    worst = result.worst()
    note = detection_note(bom)
    note_p = f"<p>{html.escape(note)}</p>" if note else ""
    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8"><title>cbom-scout 리포트</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{{--ink:#0F1B2D;--paper:#F5F6F2;--line:#D9DEE4;--o:#F2703A;--b:#3A8FE0}}
body{{margin:0;font-family:'Noto Sans KR',system-ui,sans-serif;background:var(--paper);color:var(--ink)}}
header{{background:var(--ink);color:var(--paper);padding:32px 48px}}
h1{{margin:0 0 8px;font-size:28px}} header p{{margin:0;color:#B9C4D4}}
main{{padding:32px 48px}}
.kpis{{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:24px}}
.kpi{{background:#fff;border:1px solid var(--line);border-radius:14px;padding:16px 20px}}
.kpi b{{display:block;font-size:30px}} .kpi span{{color:#5b6779;font-size:14px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:14px;overflow:hidden}}
th{{background:var(--ink);color:var(--paper);text-align:left;padding:10px 12px;font-size:14px}}
td{{padding:10px 12px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:top}}
td.loc{{font-family:monospace;font-size:12px;color:#5b6779}}
.badge{{padding:3px 10px;border-radius:999px;font-weight:700;font-size:12px}}
.badge.fail{{background:#C0392B;color:#fff}} .badge.warn{{background:var(--o);color:var(--ink)}}
.badge.info{{background:#DCE8F7;color:var(--ink)}} .badge.pass{{background:#D7F0E1;color:var(--ink)}}
.badge.new{{background:#7B2CBF;color:#fff}} .badge.old{{background:#E4E7EB;color:var(--ink)}}
.badge.resolved{{background:#D7F0E1;color:var(--ink)}}
</style></head><body>
<header><h1>🔐 cbom-scout 암호자산 리포트</h1>
<p>판정: <b>{ACTION_KO[worst]}</b> · 정책 {html.escape(result.policy)} · 실패 {c['fail']} / 경고 {c['warn']} / 참고 {c['info']} / 통과 {c['pass']}</p>{baseline_p}{note_p}</header>
<main>
<div class="kpis">
<div class="kpi"><b>{s['total']}</b><span>전체 암호 자산</span></div>
<div class="kpi"><b>{s['algorithms']}</b><span>알고리즘</span></div>
<div class="kpi"><b>{s['vulnerable_algorithms']}</b><span>취약 알고리즘</span></div>
<div class="kpi"><b>{s['pqc_algorithms']}</b><span>PQC·하이브리드</span></div>
<div class="kpi"><b>{s['occurrences']}</b><span>발견 위치</span></div>
</div>
<table>{head}
{''.join(rows)}
</table></main></body></html>
"""
