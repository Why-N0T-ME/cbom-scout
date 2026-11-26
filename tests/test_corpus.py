"""평가 말뭉치·평가 도구 (명세 AC-60~63) 개발자 테스트."""
import json
import os
import subprocess
import sys
from collections import Counter

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus")
sys.path.insert(0, CORPUS)

import evaluate  # noqa: E402

LABELS = os.path.join(CORPUS, "labels.json")
FILES = os.path.join(CORPUS, "files")


def labels():
    return evaluate.load_labels(LABELS, FILES, allow_unreviewed=True)


def test_corpus_minimum_size():
    lbs = labels()
    pos = [x for x in lbs if x["label"] == "positive"]
    neg = [x for x in lbs if x["label"] == "negative"]
    assert len(pos) >= 80 and len(neg) >= 40
    by_lang = Counter(evaluate.language(x["file"]) for x in pos)
    for lang in ("Python", "Java", "Go", "JS/TS", "C/C++", "C#", "설정 파일"):
        assert by_lang[lang] >= 5, lang
    phase1 = Counter(x["category"] for x in lbs if str(x["phase"]) == "1")
    for cat, n in {"direct": 20, "comment": 10, "docstring": 5, "string-literal": 10, "lookalike": 5,
                   "alias": 5, "multiline": 5, "indirect-const": 8, "indirect-default": 3, "test-path": 5}.items():
        assert phase1[cat] >= n, cat
    comments = [x for x in lbs if x["category"] == "comment"]
    assert sum(1 for x in comments if x["file"].endswith(".py")) >= 3
    assert sum(1 for x in comments if not x["file"].endswith(".py")) >= 7
    assert sum(1 for x in lbs if x["category"] == "cross-function" and x["phase"] == "later") >= 5


def test_label_format():
    for x in labels():
        for k in evaluate.REQUIRED:
            assert k in x
        assert "\\" not in x["file"]
        assert x["source"]


def test_label_errors_exit_2(tmp_path, capsys):
    bad = json.load(open(LABELS, encoding="utf-8"))
    bad["labels"] = [dict(bad["labels"][0], reviewed=True), dict(bad["labels"][1], reviewed=True)]
    bad["labels"].append(dict(bad["labels"][0], file="python/없는파일.py"))
    bad["labels"].append(dict(bad["labels"][0], line=9999))
    bad["labels"].append(dict(bad["labels"][0], reviewed=False))
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(bad, ensure_ascii=False), encoding="utf-8")
    assert evaluate.main(["--labels", str(p), "--files", FILES]) == 2
    err = capsys.readouterr().err
    assert "#2" in err and "#3" in err and "#4" in err and "#0" not in err


def test_unreviewed_labels_rejected_by_default(tmp_path, capsys):
    """사람 검수(reviewed) 표시가 하나라도 빠지면 지표를 내지 않는다."""
    lbs = json.load(open(LABELS, encoding="utf-8"))
    if all(x["reviewed"] is True for x in lbs["labels"]):
        pytest.skip("모든 라벨이 검수됨")
    assert evaluate.main(["--labels", LABELS, "--files", FILES]) == 2


def test_deterministic_and_targets(tmp_path):
    a = evaluate.evaluate(LABELS, FILES, allow_unreviewed=True)
    b = evaluate.evaluate(LABELS, FILES, allow_unreviewed=True)
    assert a == b
    md = evaluate.to_markdown(a)
    assert md == evaluate.to_markdown(b) and "phase later" in md
    auto, rx = a["engines"]["auto"], a["engines"]["regex"]
    for cat in ("comment", "docstring", "string-literal", "lookalike"):
        assert auto["category"][cat]["fp"] == 0, cat
    assert auto["overall"]["recall"] >= rx["overall"]["recall"]
    assert auto["overall"]["precision"] >= rx["overall"]["precision"]
    for lang, m in auto["language"].items():
        assert (m["recall"] or 0) >= (rx["language"][lang]["recall"] or 0), lang
    for cat in ("alias", "multiline", "indirect-const"):
        assert auto["category"][cat]["recall"] >= 0.9, cat


def test_cli_outputs(tmp_path):
    out = tmp_path / "r.json"
    md = tmp_path / "r.md"
    r = subprocess.run([sys.executable, os.path.join(CORPUS, "evaluate.py"), "--allow-unreviewed",
                        "--json", str(out), "--markdown", str(md)], capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, r.stderr
    res = json.loads(out.read_text(encoding="utf-8"))
    assert set(res["engines"]) == {"auto", "regex"}
    assert md.read_text(encoding="utf-8") == r.stdout
