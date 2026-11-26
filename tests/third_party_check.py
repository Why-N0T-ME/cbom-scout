"""외부 파일 출처·라이선스 검사 (docs/specs/third-party-attribution.md).

제품 기능이 아니라 저장소 관리 규칙이므로 tests/ 아래에 둔다.
각 함수는 문제 목록(문자열)을 돌려준다. 빈 목록이면 통과.
경로는 모두 저장소 루트 기준 '/' 구분 상대경로로 다룬다 (Windows·Linux 공통).
"""
from __future__ import annotations

import json
import os
import re
from typing import Iterable

MANIFEST_NAME = "third_party.json"
NOTICE_NAME = "NOTICE"

# 허용 라이선스 (확인 필요 2 승인안). 매니페스트가 아니라 여기에 두어,
# 외부 파일을 추가하는 같은 변경에서 허용 목록까지 늘리는 일을 막는다.
ALLOWED_LICENSES = {"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "CC0-1.0", "CC-BY-4.0"}
DOC_DATA_ONLY = {"CC-BY-4.0"}           # 코드 파일에는 쓸 수 없는 라이선스
CODE_EXTENSIONS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".c", ".h",
                   ".cc", ".cpp", ".hpp", ".cs", ".rs", ".rb", ".php", ".swift", ".sh", ".ps1"}
REQUIRED_FIELDS = ("path", "name", "author", "license", "source_url", "version", "retrieved", "modified")

# 금지 흔적 (Semgrep 규칙 라이선스). 문자열을 쪼개 두어 이 파일 자신이 걸리지 않게 한다.
# 다른 테스트에서 이 흔적을 써야 하면 이 상수를 가져다 쓰거나 같은 방식으로 조립한다.
SEMGREP_MARKERS = (
    "semgrep rules " + "license",
    "semgrep.dev/legal/" + "rules-license",
    "licenseref-scancode-" + "semgrep",
)
FORBIDDEN_LICENSE_RE = re.compile(
    r"(?i)^(?:LicenseRef-scancode-" r"semgrep.*|NOASSERTION|NONE|UNKNOWN|"
    r"(?:A|L)?GPL-.*|MPL-.*|EUPL-.*|CDDL-.*|SSPL-.*|BUSL-.*)$")
# 흔적 검사 대상과 제외 (확인된 정책 설명 위치)
MARKER_SCAN_DIRS = ("src/", "tests/", "examples/")
MARKER_EXCLUDE_PREFIXES = ("docs/", ".claude/", "CLAUDE.md", "NOTICE")
TEXT_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".der", ".zip", ".gz", ".whl", ".pyc"}
MODIFIED_PHRASE = "이 저장소에서 수정"


def to_rel(path: str, root: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def load_manifest(root: str) -> dict:
    with open(os.path.join(root, MANIFEST_NAME), encoding="utf-8") as fh:
        return json.load(fh)


# ------------------------------------------------------------------ AC-2, AC-5, AC-6
def check_fields(manifest: dict) -> list[str]:
    problems = []
    files = manifest.get("files")
    if not isinstance(files, list):
        return [f"{MANIFEST_NAME}: 'files' 는 배열이어야 합니다"]
    if not isinstance(manifest.get("vendored_dirs"), list):
        problems.append(f"{MANIFEST_NAME}: 'vendored_dirs' 는 배열이어야 합니다")
    seen = set()
    for i, entry in enumerate(files):
        label = entry.get("path") if isinstance(entry, dict) else None
        label = label or f"files[{i}]"
        if not isinstance(entry, dict):
            problems.append(f"{label}: 항목은 객체여야 합니다")
            continue
        for f in REQUIRED_FIELDS:
            if f not in entry or entry[f] in ("", None):
                problems.append(f"{label}: 필수 항목 '{f}' 가 없습니다")
        path = entry.get("path", "")
        if isinstance(path, str) and ("\\" in path or path.startswith(("/", "./")) or ".." in path.split("/")):
            problems.append(f"{label}: path 는 저장소 루트 기준 '/' 구분 상대경로여야 합니다")
        if path in seen:
            problems.append(f"{label}: 같은 path 가 두 번 등록됐습니다")
        seen.add(path)
        if "modified" in entry and not isinstance(entry["modified"], bool):
            problems.append(f"{label}: modified 는 true/false 여야 합니다")
        if entry.get("modified") is True and not entry.get("modifications"):
            problems.append(f"{label}: modified 가 true 이면 'modifications'(무엇을 고쳤는지)가 필요합니다")
        retrieved = entry.get("retrieved")
        if retrieved and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(retrieved)):
            problems.append(f"{label}: retrieved 는 YYYY-MM-DD 형식이어야 합니다")
        url = entry.get("source_url")
        if url and not str(url).startswith(("https://", "http://")):
            problems.append(f"{label}: source_url 은 http(s) 주소여야 합니다")
        problems += check_license(entry, label)
    return problems


def check_license(entry: dict, label: str) -> list[str]:
    lic = str(entry.get("license") or "").strip()
    if not lic:
        return []  # 필수 항목 누락으로 이미 보고됨
    if FORBIDDEN_LICENSE_RE.match(lic):
        return [f"{label}: 라이선스 '{lic}' 는 이 저장소에 넣을 수 없습니다 (금지: Semgrep 규칙 라이선스, 알 수 없음, 카피레프트)"]
    if lic not in ALLOWED_LICENSES:
        return [f"{label}: 라이선스 '{lic}' 는 허용 목록에 없습니다 (허용: {', '.join(sorted(ALLOWED_LICENSES))})"]
    if lic in DOC_DATA_ONLY and os.path.splitext(str(entry.get("path", "")))[1].lower() in CODE_EXTENSIONS:
        return [f"{label}: '{lic}' 는 문서·데이터에만 쓸 수 있고 코드 파일에는 쓸 수 없습니다"]
    return []


# ------------------------------------------------------------------ AC-3
def check_paths_exist(manifest: dict, root: str) -> list[str]:
    problems = []
    for entry in manifest.get("files", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            continue
        if not os.path.isfile(os.path.join(root, *entry["path"].split("/"))):
            problems.append(f"{entry['path']}: {MANIFEST_NAME} 에 등록됐지만 파일이 없습니다")
    return problems


# ------------------------------------------------------------------ AC-4
def check_vendored_registered(manifest: dict, root: str) -> list[str]:
    registered = {e.get("path") for e in manifest.get("files", []) if isinstance(e, dict)}
    problems = []
    for vdir in manifest.get("vendored_dirs", []):
        base = os.path.join(root, *vdir.strip("/").split("/"))
        if not os.path.isdir(base):
            problems.append(f"{vdir}: vendored_dirs 에 있지만 디렉터리가 없습니다")
            continue
        for d, dirs, files in os.walk(base):
            dirs[:] = [x for x in dirs if x != "__pycache__"]
            for f in files:
                if f == "README.md" or f.endswith(".pyc"):
                    continue
                rel = to_rel(os.path.join(d, f), root)
                if rel not in registered:
                    problems.append(f"{rel}: 외부 파일 디렉터리에 있지만 미등록 — {MANIFEST_NAME} 에 등록하고 "
                                    f"{NOTICE_NAME} 에도 적으세요 (필수 항목: {', '.join(REQUIRED_FIELDS)})")
    return problems


# ------------------------------------------------------------------ AC-1
def check_notice(manifest: dict, root: str) -> list[str]:
    path = os.path.join(root, NOTICE_NAME)
    if not os.path.isfile(path):
        return [f"{NOTICE_NAME} 파일이 없습니다"]
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    problems = []
    for e in manifest.get("files", []):
        if not isinstance(e, dict):
            continue
        for key in ("path", "name", "source_url"):
            val = e.get(key)
            if val and str(val) not in text:
                problems.append(f"{e.get('path')}: {NOTICE_NAME} 에 {key} '{val}' 가 없습니다")
    return problems


# ------------------------------------------------------------------ AC-8
def check_modified_notice(manifest: dict, root: str) -> list[str]:
    problems = []
    for e in manifest.get("files", []):
        if not isinstance(e, dict) or e.get("modified") is not True:
            continue
        p = str(e.get("path", ""))
        if p.lower().endswith(".json"):
            continue  # 주석을 넣을 수 없는 형식: 매니페스트의 modifications 로 대신
        full = os.path.join(root, *p.split("/"))
        try:
            with open(full, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue  # 존재 여부는 check_paths_exist 가 보고
        missing = [what for what, needle in (("원본 주소", str(e.get("source_url", ""))),
                                              ("라이선스", str(e.get("license", ""))),
                                              ("변경 고지", MODIFIED_PHRASE)) if needle and needle not in text]
        if missing:
            problems.append(f"{p}: 수정한 외부 파일에 {', '.join(missing)} 가 없습니다 "
                            f"(파일 안에 원본·라이선스·'{MODIFIED_PHRASE}함'을 적으세요)")
    return problems


# ------------------------------------------------------------------ AC-7
def iter_scan_files(root: str, dirs: Iterable[str] = MARKER_SCAN_DIRS) -> Iterable[str]:
    for top in dirs:
        base = os.path.join(root, *top.strip("/").split("/"))
        if not os.path.isdir(base):
            continue
        for d, subdirs, files in os.walk(base):
            subdirs[:] = [x for x in subdirs if x not in ("__pycache__", ".pytest_cache") and not x.endswith(".egg-info")]
            for f in files:
                if os.path.splitext(f)[1].lower() in TEXT_SKIP_EXT:
                    continue
                yield os.path.join(d, f)


def check_semgrep_markers(root: str, dirs: Iterable[str] = MARKER_SCAN_DIRS) -> list[str]:
    problems = []
    for path in iter_scan_files(root, dirs):
        rel = to_rel(path, root)
        if rel.startswith(MARKER_EXCLUDE_PREFIXES):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read().lower()
        except OSError:
            continue
        for marker in SEMGREP_MARKERS:
            if marker in text:
                line = text[: text.index(marker)].count("\n") + 1
                problems.append(f"{rel}:{line}: Semgrep 규칙 라이선스 흔적이 있습니다 — Semgrep 규칙은 복사하지 말고 "
                                f"참고만 하세요 (CLAUDE.md '외부 코드·데이터')")
                break
    return problems


def check_all(root: str) -> list[str]:
    manifest = load_manifest(root)
    return (check_fields(manifest) + check_paths_exist(manifest, root) + check_vendored_registered(manifest, root)
            + check_notice(manifest, root) + check_modified_notice(manifest, root) + check_semgrep_markers(root))
