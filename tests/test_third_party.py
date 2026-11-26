"""외부 파일 출처·라이선스 관리 테스트 (docs/specs/third-party-attribution.md)."""
import copy
import json
import os

import pytest
from conftest import ROOT

import third_party_check as tpc


@pytest.fixture
def manifest():
    return tpc.load_manifest(ROOT)


def make_repo(tmp_path, manifest, files=None, notice=None):
    """임시 저장소: 매니페스트, NOTICE, 파일들을 만든다."""
    (tmp_path / tpc.MANIFEST_NAME).write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    for rel, text in (files or {}).items():
        p = tmp_path.joinpath(*rel.split("/"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    if notice is None:
        notice = "\n".join(f"{e['path']} {e['name']} {e['source_url']}" for e in manifest.get("files", []))
    (tmp_path / tpc.NOTICE_NAME).write_text(notice, encoding="utf-8")
    return str(tmp_path)


def entry(path="vendor/a.txt", **kw):
    e = {"path": path, "name": "A", "author": "Someone", "license": "MIT",
         "source_url": "https://example.com/a", "version": "1.0", "retrieved": "2026-11-27", "modified": False}
    e.update(kw)
    return e


# ------------------------------------------------------------------ 현재 저장소
def test_repository_passes_all_checks():
    assert tpc.check_all(ROOT) == []


def test_current_registrations(manifest):
    paths = {e["path"] for e in manifest["files"]}
    assert paths == {"tests/schemas/bom-1.6.schema.json", "tests/schemas/jsf-0.82.schema.json",
                     "tests/schemas/spdx.schema.json"}
    spdx = next(e for e in manifest["files"] if e["path"].endswith("spdx.schema.json"))
    assert spdx.get("license_evidence")                      # AC-6
    notice = open(os.path.join(ROOT, "NOTICE"), encoding="utf-8").read()
    assert "Anders Rundgren" in notice and "Apache License 2.0" in notice   # AC-1


# ------------------------------------------------------------------ AC-2 형식
def test_missing_fields_and_modifications():
    m = {"vendored_dirs": [], "files": [entry(author=""), entry(path="vendor/b.txt", modified=True)]}
    probs = tpc.check_fields(m)
    assert any("'author'" in p for p in probs)
    assert any("modifications" in p for p in probs)


def test_bad_path_and_date_formats():
    m = {"vendored_dirs": [], "files": [entry(path="vendor\\a.txt"), entry(path="../x.txt", retrieved="27/11/2026")]}
    probs = tpc.check_fields(m)
    assert sum("상대경로" in p for p in probs) == 2
    assert any("YYYY-MM-DD" in p for p in probs)


# ------------------------------------------------------------------ AC-3 존재
def test_registered_path_must_exist(tmp_path):
    m = {"vendored_dirs": [], "files": [entry(path="vendor/missing.txt")]}
    root = make_repo(tmp_path, m)
    assert any("파일이 없습니다" in p for p in tpc.check_paths_exist(m, root))


# ------------------------------------------------------------------ AC-4 미등록
def test_unregistered_vendored_file(tmp_path):
    m = {"vendored_dirs": ["vendor/"], "files": [entry()]}
    root = make_repo(tmp_path, m, files={"vendor/a.txt": "a", "vendor/new.json": "{}", "vendor/README.md": "설명"})
    probs = tpc.check_vendored_registered(m, root)
    assert len(probs) == 1 and "vendor/new.json" in probs[0] and "third_party.json 에 등록" in probs[0]


# ------------------------------------------------------------------ AC-5 라이선스
@pytest.mark.parametrize("lic", ["LicenseRef-scancode-" + "semgrep-rules-1.0", "NOASSERTION", "GPL-3.0-only",
                                 "AGPL-3.0-or-later", "LGPL-2.1-only", "MPL-2.0"])
def test_forbidden_licenses(lic):
    probs = tpc.check_fields({"vendored_dirs": [], "files": [entry(license=lic)]})
    assert any("넣을 수 없습니다" in p for p in probs), probs


def test_unlisted_license_and_cc_by_on_code():
    probs = tpc.check_fields({"vendored_dirs": [], "files": [entry(license="WTFPL"),
                                                              entry(path="vendor/x.py", license="CC-BY-4.0"),
                                                              entry(path="vendor/data.csv", license="CC-BY-4.0")]})
    assert any("허용 목록에 없습니다" in p for p in probs)
    assert sum("코드 파일에는" in p for p in probs) == 1


# ------------------------------------------------------------------ AC-1 NOTICE
def test_notice_must_list_entries(tmp_path):
    m = {"vendored_dirs": [], "files": [entry()]}
    root = make_repo(tmp_path, m, files={"vendor/a.txt": "a"}, notice="비어 있음")
    assert len(tpc.check_notice(m, root)) == 3
    os.remove(os.path.join(root, "NOTICE"))
    assert tpc.check_notice(m, root) == ["NOTICE 파일이 없습니다"]


# ------------------------------------------------------------------ AC-8 수정 고지
def test_modified_text_file_needs_notice(tmp_path):
    e = entry(path="vendor/rules.py", modified=True, modifications="규칙 이름 변경")
    m = {"vendored_dirs": [], "files": [e]}
    root = make_repo(tmp_path, m, files={"vendor/rules.py": "x = 1\n"})
    probs = tpc.check_modified_notice(m, root)
    assert probs and "변경 고지" in probs[0]
    good = f"# 원본: {e['source_url']} (MIT) — 이 저장소에서 수정함\nx = 1\n"
    root = make_repo(tmp_path, m, files={"vendor/rules.py": good})
    assert tpc.check_modified_notice(m, root) == []


def test_modified_json_uses_manifest_only(tmp_path):
    m = {"vendored_dirs": [], "files": [entry(path="vendor/s.json", modified=True, modifications="필드 추가")]}
    root = make_repo(tmp_path, m, files={"vendor/s.json": "{}"})
    assert tpc.check_modified_notice(m, root) == []


# ------------------------------------------------------------------ AC-7 Semgrep 흔적
@pytest.mark.parametrize("marker", list(tpc.SEMGREP_MARKERS))
def test_semgrep_marker_detected(tmp_path, marker):
    p = tmp_path / "src" / "rules" / "copied.yaml"
    p.parent.mkdir(parents=True)
    p.write_text("rules:\n  - id: x\n    metadata:\n      license: " + marker.upper() + "\n", encoding="utf-8")
    probs = tpc.check_semgrep_markers(str(tmp_path))
    assert len(probs) == 1 and probs[0].startswith("src/rules/copied.yaml:4:")


def test_semgrep_marker_allowed_in_docs(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "policy.md").write_text(tpc.SEMGREP_MARKERS[0], encoding="utf-8")
    assert tpc.check_semgrep_markers(str(tmp_path), dirs=("src/", "tests/", "examples/", "docs/")) == []
