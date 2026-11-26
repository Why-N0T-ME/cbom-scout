"""외부 파일 출처·라이선스 관리 인수 테스트 — docs/specs/third-party-attribution.md 완료 기준(AC-1~AC-13).

테스터 작성. 명세가 기준이며, 결함을 재현하는 테스트는 실패한 채로 둔다.
Semgrep 라이선스 흔적 문자열은 이 파일 자신이 AC-7 검사에 걸리지 않도록 조각을 이어 붙여 만든다.
"""
import json
import ntpath
import os
import re
import shutil
import subprocess
import sys
import types
import zipfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import third_party_check as tpc  # noqa: E402

MANIFEST = os.path.join(ROOT, "third_party.json")
NOTICE = os.path.join(ROOT, "NOTICE")
SCHEMA_FILES = ("tests/schemas/bom-1.6.schema.json", "tests/schemas/jsf-0.82.schema.json",
                "tests/schemas/spdx.schema.json")
MARKERS = ("Semgrep Rules " + "License", "semgrep.dev/legal/" + "rules-license", "LicenseRef-scancode-" + "semgrep")
SEMGREP_LIC = "LicenseRef-scancode-" + "semgrep-rules-1.0"
REQUIRED = ("path", "name", "license", "source_url", "version", "retrieved", "modified")


def read(rel):
    with open(os.path.join(ROOT, *rel.split("/")), encoding="utf-8") as fh:
        return fh.read()


def manifest():
    with open(MANIFEST, encoding="utf-8") as fh:
        return json.load(fh)


def ent(path="vendor/a.txt", **kw):
    e = {"path": path, "name": "A", "author": "Someone", "license": "MIT", "source_url": "https://example.com/a",
         "version": "1.0", "retrieved": "2026-11-27", "modified": False}
    e.update(kw)
    return e


def write(root, rel, text, encoding="utf-8"):
    p = os.path.join(str(root), *rel.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding=encoding) as fh:
        fh.write(text)
    return p


def make_repo(root, m, files=None):
    """임시 저장소. NOTICE 는 매니페스트 항목을 모두 담아 만든다."""
    write(root, "third_party.json", json.dumps(m, ensure_ascii=False))
    for rel, text in (files or {}).items():
        write(root, rel, text)
    write(root, "NOTICE", "\n\n".join(f"{e['name']}\n{e['path']}\n{e.get('author', '')}\n{e['license']}\n"
                                       f"{e['source_url']}" for e in m["files"] if isinstance(e, dict)))
    return str(root)


def copy_real_repo(dst):
    """현재 저장소의 매니페스트·NOTICE·스키마 폴더만 임시 위치에 복사."""
    shutil.copy(MANIFEST, os.path.join(dst, "third_party.json"))
    shutil.copy(NOTICE, os.path.join(dst, "NOTICE"))
    shutil.copytree(os.path.join(ROOT, "tests", "schemas"), os.path.join(dst, "tests", "schemas"))
    return str(dst)


# ===================================================================== AC-1 NOTICE
def notice_block(text, path):
    blocks = re.split(r"\n\s*\n", text)
    hits = [b for b in blocks if path in b]
    assert len(hits) == 1, f"NOTICE 에 {path} 블록이 정확히 하나 있어야 함: {len(hits)}"
    return hits[0]


@pytest.mark.parametrize("path", SCHEMA_FILES)
def test_ac1_notice_lists_each_schema_with_all_fields(path):
    assert os.path.isfile(NOTICE)
    text = read("NOTICE")
    e = next(x for x in manifest()["files"] if x["path"] == path)
    block = notice_block(text, path)
    assert e["name"] in block                       # 이름
    assert "OWASP CycloneDX" in block               # 원저작(프로젝트)
    assert "Apache" in block and "2.0" in block     # 라이선스
    assert "https://github.com/CycloneDX/specification" in block   # 원본 URL
    assert path in block                            # 저장소 내 경로


def test_ac1_notice_names_jsf_author():
    block = notice_block(read("NOTICE"), "tests/schemas/jsf-0.82.schema.json")
    assert "Anders Rundgren" in block


def test_ac1_notice_check_detects_missing_entry(tmp_path):
    m = {"vendored_dirs": [], "files": [ent()]}
    root = make_repo(tmp_path, m, {"vendor/a.txt": "a"})
    write(root, "NOTICE", "다른 내용")
    assert tpc.check_notice(m, root)


# ===================================================================== AC-2 매니페스트 형식
def test_ac2_manifest_exists_at_root_and_has_required_fields():
    m = manifest()
    assert isinstance(m.get("files"), list) and m["files"]
    for e in m["files"]:
        for f in REQUIRED:
            assert f in e and e[f] not in ("", None), (e.get("path"), f)
        assert re.fullmatch(r"(?:[A-Za-z0-9.\-+]+|LicenseRef-[A-Za-z0-9.\-]+)", e["license"])
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", e["retrieved"])
        assert isinstance(e["modified"], bool)
        if e["modified"]:
            assert isinstance(e.get("modifications"), str) and e["modifications"].strip()
    assert tpc.check_fields(m) == []


@pytest.mark.parametrize("field", REQUIRED)
def test_ac2_missing_required_field_fails(field):
    e = ent()
    del e[field]
    assert tpc.check_fields({"vendored_dirs": [], "files": [e]}), field


@pytest.mark.parametrize("field", ["name", "license", "source_url", "version", "retrieved"])
def test_ac2_empty_required_field_fails(field):
    assert tpc.check_fields({"vendored_dirs": [], "files": [ent(**{field: ""})]}), field


def test_ac2_modified_true_requires_modifications():
    assert any("modifications" in p for p in tpc.check_fields({"vendored_dirs": [], "files": [ent(modified=True)]}))
    assert tpc.check_fields({"vendored_dirs": [], "files": [ent(modified=True, modifications="이름 변경")]}) == []


def test_ac2_modified_must_be_bool():
    assert tpc.check_fields({"vendored_dirs": [], "files": [ent(modified="false")]})


@pytest.mark.parametrize("bad", ["27/11/2026", "2026-1-5", "20261127", "2026-11-27T00:00"])
def test_ac2_retrieved_format(bad):
    assert any("YYYY-MM-DD" in p for p in tpc.check_fields({"vendored_dirs": [], "files": [ent(retrieved=bad)]}))


def test_ac2_retrieved_must_be_real_date():
    """경계값: 형식은 맞지만 존재하지 않는 날짜."""
    assert tpc.check_fields({"vendored_dirs": [], "files": [ent(retrieved="2026-13-45")]})


@pytest.mark.parametrize("bad", [["목록"], 1, "   "])
def test_ac2_modifications_must_be_nonblank_string(bad):
    assert tpc.check_fields({"vendored_dirs": [], "files": [ent(modified=True, modifications=bad)]}), repr(bad)


def test_ac2_broken_manifest_json_is_not_silently_accepted(tmp_path):
    write(tmp_path, "third_party.json", "{ broken")
    with pytest.raises(ValueError):
        tpc.load_manifest(str(tmp_path))


def test_ac2_missing_manifest_is_not_silently_accepted(tmp_path):
    with pytest.raises(OSError):
        tpc.check_all(str(tmp_path))


# ===================================================================== AC-3 경로 존재
def test_ac3_all_manifest_paths_exist():
    for e in manifest()["files"]:
        assert "\\" not in e["path"] and not e["path"].startswith("/")
        assert os.path.exists(os.path.join(ROOT, *e["path"].split("/"))), e["path"]
    assert tpc.check_paths_exist(manifest(), ROOT) == []


def test_ac3_missing_path_fails(tmp_path):
    m = {"vendored_dirs": [], "files": [ent(path="vendor/없는파일.txt")]}
    root = make_repo(tmp_path, m)
    probs = tpc.check_paths_exist(m, root)
    assert len(probs) == 1 and "vendor/없는파일.txt" in probs[0]


@pytest.mark.parametrize("bad", ["vendor\\a.txt", "/vendor/a.txt", "./vendor/a.txt", "vendor/../vendor/a.txt"])
def test_ac3_non_slash_relative_path_rejected(bad):
    assert any("상대경로" in p for p in tpc.check_fields({"vendored_dirs": [], "files": [ent(path=bad)]})), bad


def test_ac3_non_string_path_rejected(tmp_path):
    """잘못된 입력: path 가 문자열이 아니면 어느 검사에서든 문제로 보고돼야 한다."""
    m = {"vendored_dirs": [], "files": [ent(path=123)]}
    root = make_repo(tmp_path, m)
    assert tpc.check_fields(m) + tpc.check_paths_exist(m, root)


def test_ac3_windows_relpath_normalized(monkeypatch):
    """Windows 에서 os.walk 가 돌려주는 '\\' 경로도 '/' 상대경로로 바뀌어야 같은 결과가 나온다."""
    fake_os = types.SimpleNamespace(path=ntpath, sep="\\")
    monkeypatch.setattr(tpc, "os", fake_os)
    assert tpc.to_rel("C:\\repo\\tests\\schemas\\bom-1.6.schema.json", "C:\\repo") == "tests/schemas/bom-1.6.schema.json"


def test_ac3_korean_path_with_spaces(tmp_path):
    base = tmp_path / "한글 저장소"
    base.mkdir()
    m = {"vendored_dirs": ["외부 자료/"], "files": [ent(path="외부 자료/스키마.json")]}
    root = make_repo(base, m, {"외부 자료/스키마.json": "{}", "외부 자료/README.md": "설명"})
    assert tpc.check_all(root) == []
    write(root, "외부 자료/미등록.json", "{}")
    probs = tpc.check_all(root)
    assert len(probs) == 1 and "외부 자료/미등록.json" in probs[0]


# ===================================================================== AC-4 미등록 파일
def test_ac4_vendored_dirs_includes_tests_schemas():
    assert "tests/schemas/" in [d.rstrip("/") + "/" for d in manifest()["vendored_dirs"]]


def test_ac4_current_schema_dir_fully_registered():
    assert tpc.check_vendored_registered(manifest(), ROOT) == []


def test_ac4_unregistered_file_fails_with_guidance(tmp_path):
    root = copy_real_repo(tmp_path)
    write(root, "tests/schemas/bom-1.7.schema.json", "{}")
    probs = tpc.check_all(root)
    assert len(probs) == 1
    assert "tests/schemas/bom-1.7.schema.json" in probs[0] and "third_party.json 에 등록" in probs[0]


def test_ac4_readme_excluded_but_other_md_not(tmp_path):
    root = copy_real_repo(tmp_path)
    write(root, "tests/schemas/CHANGES.md", "x")
    probs = tpc.check_vendored_registered(json.load(open(os.path.join(root, "third_party.json"), encoding="utf-8")), root)
    assert len(probs) == 1 and "CHANGES.md" in probs[0]


def test_ac4_unregistered_file_in_subdirectory(tmp_path):
    root = copy_real_repo(tmp_path)
    write(root, "tests/schemas/ext/a.json", "{}")
    assert any("tests/schemas/ext/a.json" in p for p in tpc.check_all(root))


def test_ac4_cannot_bypass_by_removing_tests_schemas_from_vendored_dirs(tmp_path):
    """우회: 매니페스트의 vendored_dirs 에서 tests/schemas/ 를 빼면 미등록 파일 검사가 꺼진다.
    명세는 '최소 tests/schemas/' 를 요구하므로 이 상태는 실패해야 한다."""
    root = copy_real_repo(tmp_path)
    path = os.path.join(root, "third_party.json")
    m = json.load(open(path, encoding="utf-8"))
    m["vendored_dirs"] = []
    write(root, "third_party.json", json.dumps(m, ensure_ascii=False))
    write(root, "tests/schemas/bom-1.7.schema.json", "{}")
    assert tpc.check_all(root), "vendored_dirs 를 비우면 미등록 스키마가 통과한다"


# ===================================================================== AC-5 라이선스
@pytest.mark.parametrize("lic", sorted(tpc.ALLOWED_LICENSES - {"CC-BY-4.0"}) + ["CC-BY-4.0"])
def test_ac5_allowed_licenses_pass(lic):
    path = "vendor/data.csv" if lic == "CC-BY-4.0" else "vendor/a.txt"
    assert tpc.check_fields({"vendored_dirs": [], "files": [ent(path=path, license=lic)]}) == []


def test_ac5_allowed_list_matches_spec():
    assert tpc.ALLOWED_LICENSES == {"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "CC0-1.0", "CC-BY-4.0"}


@pytest.mark.parametrize("lic", [SEMGREP_LIC, "NOASSERTION", "", "   ", "GPL-2.0-only", "GPL-3.0-or-later",
                                 "LGPL-2.1-only", "LGPL-3.0-or-later", "AGPL-3.0-only", "MPL-2.0",
                                 "gpl-3.0-only", "licenseref-scancode-" + "semgrep-rules-1.0", " MPL-2.0 ",
                                 "MIT OR GPL-3.0-only", "Unknown", None])
def test_ac5_forbidden_or_unknown_license_fails(lic):
    assert tpc.check_fields({"vendored_dirs": [], "files": [ent(license=lic)]}), repr(lic)


def test_ac5_unlisted_license_fails():
    assert any("허용 목록" in p for p in tpc.check_fields({"vendored_dirs": [], "files": [ent(license="Unlicense")]}))


def test_ac5_cc_by_not_allowed_for_code():
    assert tpc.check_fields({"vendored_dirs": [], "files": [ent(path="vendor/x.py", license="CC-BY-4.0")]})
    assert tpc.check_fields({"vendored_dirs": [], "files": [ent(path="vendor/X.PY", license="CC-BY-4.0")]})


def test_ac5_forbidden_license_fails_in_full_check(tmp_path):
    m = {"vendored_dirs": [], "files": [ent(license=SEMGREP_LIC)]}
    root = make_repo(tmp_path, m, {"vendor/a.txt": "a"})
    assert tpc.check_all(root)


# ===================================================================== AC-6 license_evidence
def test_ac6_spdx_schema_has_license_evidence():
    e = next(x for x in manifest()["files"] if x["path"] == "tests/schemas/spdx.schema.json")
    ev = e.get("license_evidence", "")
    assert ev.strip()
    assert "cyclonedx-python-lib" in ev or "CycloneDX/specification" in ev   # 배포본 이름
    assert "Apache-2.0" in ev                                                 # 그 라이선스


# ===================================================================== AC-7 Semgrep 흔적
def test_ac7_current_repository_has_no_marker():
    assert tpc.check_semgrep_markers(ROOT) == []


@pytest.mark.parametrize("marker", MARKERS)
@pytest.mark.parametrize("rel", ["src/cbom_scout/rules.yaml", "src/cbom_scout/policies/x.json",
                                 "tests/test_copied.py", "examples/demo/app.py"])
def test_ac7_marker_detected_in_scanned_dirs(tmp_path, marker, rel):
    write(tmp_path, rel, "# meta\nlicense: " + marker + "\n")
    probs = tpc.check_semgrep_markers(str(tmp_path))
    assert len(probs) == 1 and probs[0].startswith(rel + ":"), probs


@pytest.mark.parametrize("variant", [MARKERS[0].upper(), MARKERS[0].lower(), "sEmGrEp RuLeS " + "lIcEnSe",
                                     "HTTPS://SEMGREP.DEV/LEGAL/" + "RULES-LICENSE"])
def test_ac7_case_insensitive(tmp_path, variant):
    write(tmp_path, "src/a.yaml", variant)
    assert tpc.check_semgrep_markers(str(tmp_path))


@pytest.mark.parametrize("rel", ["docs/policy.md", "CLAUDE.md", ".claude/agents/x.md", "NOTICE"])
def test_ac7_policy_locations_excluded(tmp_path, rel):
    write(tmp_path, rel, MARKERS[0])
    assert tpc.check_semgrep_markers(str(tmp_path)) == []


def test_ac7_marker_in_korean_path(tmp_path):
    write(tmp_path, "src/규칙 모음/복사.yaml", MARKERS[1])
    probs = tpc.check_semgrep_markers(str(tmp_path))
    assert len(probs) == 1 and probs[0].startswith("src/규칙 모음/복사.yaml:")


def test_ac7_marker_in_utf16_file(tmp_path):
    """우회: UTF-16 으로 저장하면 utf-8(errors=ignore) 로 읽어 흔적을 놓친다."""
    write(tmp_path, "src/rules.yaml", "license: " + MARKERS[0] + "\n", encoding="utf-16")
    assert tpc.check_semgrep_markers(str(tmp_path))


def test_ac7_repo_detects_planted_marker_via_check_all(tmp_path):
    root = copy_real_repo(tmp_path)
    write(root, "src/cbom_scout/scanners/x.py", "# " + MARKERS[2] + "\n")
    assert any("x.py" in p for p in tpc.check_all(root))


# ===================================================================== AC-8 수정 고지
def _mod_repo(tmp_path, body, path="vendor/rules.py"):
    e = ent(path=path, modified=True, modifications="규칙 이름 변경")
    m = {"vendored_dirs": [], "files": [e]}
    return m, make_repo(tmp_path, m, {path: body})


def test_ac8_complete_notice_passes(tmp_path):
    m, root = _mod_repo(tmp_path, "# 원본: https://example.com/a (MIT) — 이 저장소에서 수정함\nx = 1\n")
    assert tpc.check_modified_notice(m, root) == []
    assert tpc.check_all(root) == []


@pytest.mark.parametrize("body", [
    "x = 1\n",
    "# 원본: https://example.com/a (MIT)\nx = 1\n",                 # 수정 고지 없음
    "# (MIT) — 이 저장소에서 수정함\nx = 1\n",                       # 원본 없음
    "# 원본: https://example.com/a — 이 저장소에서 수정함\nx = 1\n",  # 라이선스 없음
])
def test_ac8_missing_notice_part_fails(tmp_path, body):
    m, root = _mod_repo(tmp_path, body)
    assert tpc.check_modified_notice(m, root)
    assert tpc.check_all(root)


def test_ac8_json_uses_manifest_record(tmp_path):
    m, root = _mod_repo(tmp_path, "{}", path="vendor/s.json")
    assert tpc.check_modified_notice(m, root) == []


def test_ac8_unmodified_text_needs_no_notice(tmp_path):
    m = {"vendored_dirs": [], "files": [ent()]}
    root = make_repo(tmp_path, m, {"vendor/a.txt": "a"})
    assert tpc.check_modified_notice(m, root) == []


# ===================================================================== AC-9 CLAUDE.md
def claude_section():
    text = read("CLAUDE.md")
    m = re.search(r"^## 외부 코드·데이터\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert m, "CLAUDE.md 에 '외부 코드·데이터' 절이 없음"
    return m.group(1)


def test_ac9_claude_md_section_contents():
    s = claude_section()
    assert "third_party.json" in s and "NOTICE" in s                     # 등록 절차
    for lic in ("Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "CC0-1.0", "CC-BY-4.0"):
        assert lic in s, lic                                              # 허용
    assert "금지" in s and "카피레프트" in s and "GPL" in s               # 금지
    assert "참고만" in s and "새로 쓴다" in s                             # 참고만 정의
    assert "Semgrep" in s and "복사하지 않" in s                          # Semgrep 복사 금지
    assert "modified" in s and "이 저장소에서 수정함" in s                # 수정 고지
    assert "한계" in s                                                    # 설계 메모: 흔적 검사의 한계


# ===================================================================== AC-10 템플릿
def test_ac10_spec_template_has_external_section():
    text = read("docs/specs/_template.md")
    m = re.search(r"^## 외부 자료\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert m
    s = m.group(1)
    assert "출처" in s and "라이선스" in s and "참고" in s and "복사" in s


# ===================================================================== AC-11 README
def test_ac11_readme_license_section_points_to_notice_and_manifest():
    text = read("README.md")
    m = re.search(r"^## 라이선스\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert m
    assert "NOTICE" in m.group(1) and "third_party.json" in m.group(1)


def test_ac11_schema_readme_points_to_notice():
    assert "NOTICE" in read("tests/schemas/README.md")


# ===================================================================== AC-12 wheel
def test_ac12_wheel_excludes_schemas(tmp_path):
    src = tmp_path / "src-copy"
    shutil.copytree(ROOT, src, ignore=shutil.ignore_patterns(".git", "build", "*.egg-info", "__pycache__",
                                                             ".pytest_cache", "dist"))
    out = tmp_path / "wheel"
    p = subprocess.run([sys.executable, "-m", "pip", "wheel", str(src), "--no-deps", "--no-build-isolation",
                        "-w", str(out)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr[-2000:]
    wheels = list(out.glob("*.whl"))
    assert len(wheels) == 1
    names = zipfile.ZipFile(wheels[0]).namelist()
    assert not [n for n in names if "schema.json" in n], names
    assert not [n for n in names if "tests/" in n]
    assert any(n.endswith("policies/nist-ir8547.json") for n in names)   # 기존 패키지 데이터 유지


# ===================================================================== AC-13 회귀
def test_ac13_existing_cbom_schema_test_present():
    assert "def test_cbom_schema_valid" in read("tests/test_policy_cli.py")


def test_ac13_full_repo_check_passes():
    assert tpc.check_all(ROOT) == []
