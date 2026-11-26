"""평가 말뭉치로 탐지 엔진의 정밀도·재현율을 잰다.

  python tests/corpus/evaluate.py                      # 마크다운 표를 표준 출력으로
  python tests/corpus/evaluate.py --json result.json   # 같은 내용을 JSON 으로도
  python tests/corpus/evaluate.py --labels my.json --files my_files/   # 다른 말뭉치

채점은 닫힌 세계다: 말뭉치 파일 안의 탐지 중 양성 라벨과 (file, line, name) 이 맞지 않는 것은
모두 오탐(FP)이다. 음성 라벨은 그 오탐이 어느 범주(주석·문자열 등)인지 알려 준다.
phase 가 later 인 양성 라벨은 다음 단계 목표라 전체 지표에서 빼고 따로 집계한다.

라벨이 가리키는 파일이 없거나 줄이 범위를 벗어나면 종료 코드 2 와 함께 그 라벨 위치를 출력한다.
reviewed 는 사람이 라벨을 확인했는지 표시한다. 미검수 라벨도 채점하되, 결과에 검수·미검수 수를 함께 적는다.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "src"))

from cbom_scout.inventory import Inventory, get_prop  # noqa: E402
from cbom_scout.scanners.code import scan_code  # noqa: E402

ENGINES = ("auto", "regex")
REQUIRED = ("file", "line", "name", "label", "category", "phase", "source", "reviewed")
LANGS = [("Python", {".py"}), ("Java", {".java", ".kt", ".kts", ".scala"}), ("Go", {".go"}),
         ("JS/TS", {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}),
         ("C/C++", {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}), ("C#", {".cs"})]
CONFIG = "설정 파일"


def language(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    for name, exts in LANGS:
        if ext in exts:
            return name
    return CONFIG


class LabelError(Exception):
    pass


def load_labels(path: str, files_root: str) -> list:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    labels = doc["labels"] if isinstance(doc, dict) else doc
    errors = []
    line_counts: dict = {}
    for i, lb in enumerate(labels):
        where = f"{os.path.basename(path)} #{i} ({lb.get('file')}:{lb.get('line')})"
        missing = [k for k in REQUIRED if k not in lb]
        if missing:
            errors.append(f"{where}: 필수 필드 없음 {', '.join(missing)}")
            continue
        if lb["label"] not in ("positive", "negative"):
            errors.append(f"{where}: label 은 positive/negative")
        if str(lb["phase"]) not in ("1", "later"):
            errors.append(f"{where}: phase 는 1/later")
        if not isinstance(lb["reviewed"], bool):
            errors.append(f"{where}: reviewed 는 true/false")
        fp = os.path.join(files_root, *str(lb["file"]).split("/"))
        if not os.path.isfile(fp):
            errors.append(f"{where}: 파일 없음")
            continue
        if fp not in line_counts:
            with open(fp, encoding="utf-8", errors="ignore") as fh:
                line_counts[fp] = len(fh.read().splitlines())
        if not isinstance(lb["line"], int) or not 1 <= lb["line"] <= line_counts[fp]:
            errors.append(f"{where}: 줄 번호가 파일 범위(1~{line_counts[fp]})를 벗어남")
    if errors:
        raise LabelError("\n".join(errors))
    return labels


def detections(files_root: str, engine: str) -> tuple:
    inv = Inventory()
    scan_code(files_root, inv, rel_to=files_root, engine=engine)
    found, scopes = set(), {}
    for c in inv.components.values():
        if c.get("type") != "cryptographic-asset":
            continue
        scopes[c["name"]] = set((get_prop(c, "scope") or "").split(",")) - {""}
        for o in c.get("evidence", {}).get("occurrences", []):
            if o.get("line"):
                found.add((o["location"], o["line"], c["name"]))
    return found, scopes


def _metrics(tp: int, fp: int, fn: int) -> dict:
    prec = round(tp / (tp + fp), 3) if tp + fp else None
    rec = round(tp / (tp + fn), 3) if tp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "precision": prec, "recall": rec}


def score(labels: list, found: set, scopes: dict) -> dict:
    pos1 = [lb for lb in labels if lb["label"] == "positive" and str(lb["phase"]) == "1"]
    later = [lb for lb in labels if lb["label"] == "positive" and str(lb["phase"]) == "later"]
    neg = {(lb["file"], lb["line"], lb["name"]): lb for lb in labels if lb["label"] == "negative"}
    positive_keys = {(lb["file"], lb["line"], lb["name"]) for lb in pos1 + later}

    def hit(lb) -> bool:
        if (lb["file"], lb["line"], lb["name"]) not in found:
            return False
        return not lb.get("scope") or lb["scope"] in scopes.get(lb["name"], set())

    fps = sorted(d for d in found if d not in positive_keys)
    rows: dict = {"overall": [0, 0, 0], "language": {}, "category": {}}

    def bump(key, idx, sub=None):
        if sub is None:
            rows[key][idx] += 1
        else:
            rows[key].setdefault(sub, [0, 0, 0])[idx] += 1

    for lb in pos1:
        idx = 0 if hit(lb) else 2
        bump("overall", idx)
        bump("language", idx, language(lb["file"]))
        bump("category", idx, lb["category"])
    for d in fps:
        bump("overall", 1)
        bump("language", 1, language(d[0]))
        bump("category", 1, neg[d]["category"] if d in neg else "unlabeled")
    # 음성 라벨만 있는 범주도 표에 나오게
    for lb in neg.values():
        rows["category"].setdefault(lb["category"], [0, 0, 0])
    lt = sum(1 for lb in later if hit(lb))
    return {
        "overall": _metrics(*rows["overall"]),
        "language": {k: _metrics(*v) for k, v in sorted(rows["language"].items())},
        "category": {k: _metrics(*v) for k, v in sorted(rows["category"].items())},
        "later": {"tp": lt, "fn": len(later) - lt, "recall": round(lt / len(later), 3) if later else None},
        "false_positives": [{"file": f, "line": ln, "name": n,
                             "category": neg[(f, ln, n)]["category"] if (f, ln, n) in neg else "unlabeled"}
                            for f, ln, n in fps],
        "false_negatives": [{"file": lb["file"], "line": lb["line"], "name": lb["name"], "category": lb["category"]}
                            for lb in pos1 if not hit(lb)],
    }


def evaluate(labels_path: str, files_root: str, engines=ENGINES) -> dict:
    labels = load_labels(labels_path, files_root)
    out = {"labels": {"positive": sum(1 for lb in labels if lb["label"] == "positive"),
                      "negative": sum(1 for lb in labels if lb["label"] == "negative"),
                      "reviewed": sum(1 for lb in labels if lb["reviewed"] is True),
                      "unreviewed": sum(1 for lb in labels if lb["reviewed"] is not True)},
           "engines": {}}
    for e in engines:
        out["engines"][e] = score(labels, *detections(files_root, e))
    return out


def _f(v) -> str:
    return "-" if v is None else f"{v:.3f}"


def to_markdown(res: dict) -> str:
    engines = list(res["engines"])
    L = ["# 평가 말뭉치 결과", "",
         f"라벨: 양성 {res['labels']['positive']}개 · 음성 {res['labels']['negative']}개 (닫힌 세계 채점)", "",
         f"사람 검수: 검수 {res['labels']['reviewed']}개 · 미검수 {res['labels']['unreviewed']}개", "",
         "## 전체 (phase 1)", "", "| 엔진 | TP | FP | FN | 정밀도 | 재현율 |", "|---|---:|---:|---:|---:|---:|"]
    for e in engines:
        m = res["engines"][e]["overall"]
        L.append(f"| {e} | {m['tp']} | {m['fp']} | {m['fn']} | {_f(m['precision'])} | {_f(m['recall'])} |")
    for title, key in (("언어별", "language"), ("범주별", "category")):
        L += ["", f"## {title}", "", f"| {'언어' if key == 'language' else '범주'} | 엔진 | TP | FP | FN | 정밀도 | 재현율 |",
              "|---|---|---:|---:|---:|---:|---:|"]
        keys = sorted({k for e in engines for k in res["engines"][e][key]})
        for k in keys:
            for e in engines:
                m = res["engines"][e][key].get(k, _metrics(0, 0, 0))
                L.append(f"| {k} | {e} | {m['tp']} | {m['fp']} | {m['fn']} | {_f(m['precision'])} | {_f(m['recall'])} |")
    L += ["", "## 후속 단계 목표 (phase later)", "", "| 엔진 | TP | FN | 재현율 |", "|---|---:|---:|---:|"]
    for e in engines:
        m = res["engines"][e]["later"]
        L.append(f"| {e} | {m['tp']} | {m['fn']} | {_f(m['recall'])} |")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="cbom-scout 평가 말뭉치 채점")
    ap.add_argument("--labels", default=os.path.join(HERE, "labels.json"))
    ap.add_argument("--files", default=os.path.join(HERE, "files"))
    ap.add_argument("--engines", default=",".join(ENGINES))
    ap.add_argument("--json", help="결과 JSON 저장 경로")
    ap.add_argument("--markdown", help="결과 마크다운 저장 경로 (표준 출력에도 나옴)")
    a = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass
    try:
        res = evaluate(a.labels, a.files, [e for e in a.engines.split(",") if e])
    except LabelError as e:
        print(f"라벨 오류:\n{e}", file=sys.stderr)
        return 2
    md = to_markdown(res)
    print(md, end="")
    if a.markdown:
        with open(a.markdown, "w", encoding="utf-8") as fh:
            fh.write(md)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
