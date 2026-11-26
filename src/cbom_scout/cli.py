"""cbom-scout 명령행 인터페이스.

  cbom-scout scan .  --tls example.com:443 -o cbom.json --markdown report.md
  cbom-scout check cbom.json --policy strict --fail-on warn
  cbom-scout merge a.json b.json -o all.json
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from . import __version__
from .cbom import inventory_from_boms, load, save, to_cbom
from .inventory import Inventory
from .policy import ACTIONS, PolicyError, evaluate, fails_at, load_policy, should_fail, validate_policy
from .report import ACTION_KO, summary_stats, to_html, to_markdown

BUILTIN_POLICIES = {
    "nist-ir8547": "nist-ir8547.json",
    "strict": "strict.json",
}


def _policy_path(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    if p in BUILTIN_POLICIES:
        return os.path.join(os.path.dirname(__file__), "policies", BUILTIN_POLICIES[p])
    return p


def _targets(args) -> list[str]:
    t = list(args.tls or [])
    for f in args.tls_file or []:
        with open(f, encoding="utf-8") as fh:
            t += [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
    return t


def _load_baseline(args) -> tuple[Optional[dict], int]:
    """--baseline 이 있으면 스캔 전에 읽는다. 오류면 (None, 2) — 출력 파일은 만들지 않는다."""
    path = getattr(args, "baseline", None)
    if not path:
        return None, 0
    from .baseline import BaselineError, load_baseline
    try:
        return load_baseline(path), 0
    except BaselineError as e:
        print(f"cbom-scout: {e}", file=sys.stderr)
        return None, 2


def _finish(bom: dict, args, baseline: Optional[dict] = None) -> int:
    from .baseline import clear_marks
    clear_marks(bom)   # check 입력에 남은 이전 비교 결과는 이번 평가와 무관하다
    policy = load_policy(_policy_path(args.policy))
    try:
        validate_policy(policy)
    except PolicyError as e:
        print(f"cbom-scout: 정책 파일 오류: {e}", file=sys.stderr)
        return 2
    result = evaluate(bom, policy)
    diff = None
    if baseline is not None:
        from .baseline import BaselineError, compare
        try:
            diff = compare(bom, result, baseline, policy)
        except BaselineError as e:   # 출력 파일을 쓰기 전이므로 아무것도 남지 않는다
            print(f"cbom-scout: {e}: {args.baseline}", file=sys.stderr)
            return 2
    if getattr(args, "output", None):
        save(bom, args.output)
    md = to_markdown(bom, result, diff=diff)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(md)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(bom, result, diff=diff))
    gh = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh and not args.no_github_summary:
        with open(gh, "a", encoding="utf-8") as fh:
            fh.write(md)
    s = summary_stats(bom)
    c = result.counts
    print(f"cbom-scout: 자산 {s['total']}개 (알고리즘 {s['algorithms']}, 취약 {s['vulnerable_algorithms']}, "
          f"PQC·하이브리드 {s['pqc_algorithms']}) · 실패 {c['fail']} / 경고 {c['warn']} / "
          f"참고 {c['info']} / 통과 {c['pass']} → {ACTION_KO[result.worst()]}", file=sys.stderr)
    if diff is not None:
        from .baseline import NO_OVERLAP_WARNING, summary_line
        print(summary_line(diff, ACTION_KO), file=sys.stderr)
        if diff.no_overlap:
            print(NO_OVERLAP_WARNING, file=sys.stderr)
    if args.verbose:
        if diff is None:
            for f in result.findings:
                if f.action != "pass":
                    print(f"  [{f.action.upper():4}] {f.name}: {f.message}  @ {', '.join(f.locations[:3])}",
                          file=sys.stderr)
        else:
            for tag, entries in (("신규", diff.new), ("기존", diff.existing)):
                for e in entries:
                    print(f"  [{tag}] [{e.action.upper():4}] {e.name}: {e.message}  @ {', '.join(e.locations[:3])}",
                          file=sys.stderr)
            for e in diff.resolved:
                print(f"  [해결] {e.name}  @ {', '.join(e.paths[:3])}", file=sys.stderr)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        # 기준선이 있으면 신규 위치에만 주석을 단다
        for f in (diff.new if diff is not None else result.findings):
            if f.action in ("fail", "warn"):
                level = "error" if f.action == "fail" else "warning"
                for loc in f.locations[:5]:
                    path, _, line = loc.partition(":")
                    if os.path.isfile(path) and line.isdigit():
                        print(f"::{level} file={path},line={line},title=cbom-scout {f.name}::{f.message}")
    if diff is not None:
        return 1 if fails_at(diff.worst(), args.fail_on) else 0
    if should_fail(result, args.fail_on):
        return 1
    return 0


def _rel_base(p: str) -> str:
    """위치를 작업 디렉터리 기준 상대경로로 남긴다(GitHub 주석·PR 링크용). 밖이면 스캔 경로 기준."""
    cwd = os.path.abspath(os.getcwd())
    ap = os.path.abspath(p)
    if ap == cwd or ap.startswith(cwd + os.sep):
        return cwd
    return ap if os.path.isdir(ap) else os.path.dirname(ap)


def _ignore_file(path: str, rel_to: str, explicit: Optional[str]) -> list[str]:
    """.cbomignore (gitignore 와 비슷한 한 줄 한 패턴) 을 읽는다. 패턴은 rel_to 기준 경로."""
    candidates = [explicit] if explicit else [os.path.join(rel_to, ".cbomignore"),
                                              os.path.join(path, ".cbomignore")]
    for c in candidates:
        if c and os.path.isfile(c):
            with open(c, encoding="utf-8") as fh:
                return [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
    return []


def cmd_scan(args) -> int:
    from .scanners.code import scan_code
    from .scanners.certs import scan_certs

    baseline, err = _load_baseline(args)
    if err:
        return err
    inv = Inventory()
    paths = args.paths or ([] if (args.tls or args.tls_file) else ["."])
    for p in paths:
        if not os.path.exists(p):
            print(f"경로 없음: {p}", file=sys.stderr)
            return 2
        rel_to = _rel_base(p)
        excludes = list(args.exclude or []) + _ignore_file(p, rel_to, args.ignore_file)
        # 명시적으로 지정한 스캔 경로 자체를 가리는 패턴은 무시한다 (예: examples/ 를 직접 스캔)
        root_rel = os.path.relpath(os.path.abspath(p), rel_to).replace(os.sep, "/")
        if root_rel not in (".", ""):
            from .scanners.code import is_excluded
            excludes = [e for e in excludes if not is_excluded(root_rel + "/", [e])
                        and not is_excluded(root_rel, [e])]
        if not args.no_code:
            warn = (lambda msg: print(f"cbom-scout: {msg}", file=sys.stderr)) if args.verbose else None
            scan_code(p, inv, rel_to=rel_to, excludes=excludes, engine=args.engine, warn=warn)
        if not args.no_certs:
            scan_certs(p, inv, rel_to=rel_to, excludes=excludes)
    targets = _targets(args)
    if targets:
        from .scanners.tls import scan_tls
        for r in scan_tls(targets, inv, timeout=args.timeout):
            if not r.ok:
                print(f"TLS 접속 실패 {r.host}:{r.port} — {r.error}", file=sys.stderr)
    for extra in args.merge or []:
        for comp in load(extra).get("components", []):
            inv.merge_component(comp)
    subject = args.name or os.path.basename(os.path.abspath(paths[0])) if paths else (args.name or "tls-scan")
    bom = to_cbom(inv, subject=subject)
    return _finish(bom, args, baseline)


def cmd_check(args) -> int:
    baseline, err = _load_baseline(args)
    if err:
        return err
    inv = inventory_from_boms(load(p) for p in args.cboms)
    bom = to_cbom(inv, subject=args.name or "merged")
    return _finish(bom, args, baseline)


def cmd_merge(args) -> int:
    inv = inventory_from_boms(load(p) for p in args.cboms)
    save(to_cbom(inv, subject=args.name or "merged"), args.output)
    print(f"{len(inv.components)}개 자산을 {args.output} 에 저장", file=sys.stderr)
    return 0


def _common_out(p: argparse.ArgumentParser) -> None:
    p.add_argument("--policy", default=None,
                   help="정책 파일 경로 또는 내장 정책 이름 (nist-ir8547 [기본], strict)")
    p.add_argument("--fail-on", default="fail", choices=ACTIONS[1:] + ["never"],
                   help="이 수준 이상의 결과가 있으면 종료 코드 1 (기본: fail)")
    p.add_argument("--markdown", help="마크다운 리포트 경로")
    p.add_argument("--html", help="HTML 리포트 경로")
    p.add_argument("--no-github-summary", action="store_true", help="GitHub Actions 요약 출력을 끈다")
    p.add_argument("--name", help="CBOM 메타데이터에 넣을 대상 이름")
    p.add_argument("--baseline", metavar="CBOM",
                   help="기준 CBOM (예: main 브랜치 스캔 결과). 주면 기준선 대비 새로 생긴 위반만 "
                        "--fail-on 판정에 쓴다. 파일이 없거나 깨지면 종료 코드 2")
    p.add_argument("-v", "--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cbom-scout", description="암호자산 자동 식별 → CycloneDX 1.6 CBOM")
    ap.add_argument("--version", action="version", version=f"cbom-scout {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="코드·인증서·TLS 엔드포인트를 스캔해 CBOM 생성")
    s.add_argument("paths", nargs="*", help="스캔할 디렉터리나 파일 (기본: 현재 디렉터리)")
    s.add_argument("--tls", action="append", metavar="HOST[:PORT]", help="TLS 엔드포인트 (여러 번 지정 가능)")
    s.add_argument("--tls-file", action="append", metavar="FILE", help="한 줄에 하나씩 엔드포인트가 적힌 파일")
    s.add_argument("--timeout", type=float, default=8.0, help="TLS 접속 제한 시간(초)")
    s.add_argument("--no-code", action="store_true", help="소스코드 스캔 끄기")
    s.add_argument("--engine", default="auto", choices=["auto", "regex"],
                   help="코드 분석 엔진. auto [기본]: Python 은 구문 트리, 그 밖의 언어는 주석·문자열을 "
                        "가린 정규식. regex: 예전 줄 단위 정규식 (비교·비상용)")
    s.add_argument("--no-certs", action="store_true", help="인증서·키 파일 스캔 끄기")
    s.add_argument("--merge", action="append", metavar="CBOM", help="다른 도구가 만든 CBOM 을 함께 합치기")
    s.add_argument("--exclude", action="append", metavar="GLOB",
                   help="제외할 경로 패턴 (여러 번 지정 가능, 예: tests/ '*.min.js')")
    s.add_argument("--ignore-file", metavar="FILE", help="제외 패턴 파일 (기본: .cbomignore)")
    s.add_argument("-o", "--output", default="cbom.json", help="CBOM 출력 경로 (기본: cbom.json)")
    _common_out(s)
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("check", help="기존 CBOM 들을 정책으로 평가")
    c.add_argument("cboms", nargs="+")
    c.add_argument("-o", "--output", help="평가 결과가 반영된 CBOM 저장 경로")
    _common_out(c)
    c.set_defaults(func=cmd_check)

    m = sub.add_parser("merge", help="여러 CBOM 을 하나로 합치기")
    m.add_argument("cboms", nargs="+")
    m.add_argument("-o", "--output", required=True)
    m.add_argument("--name")
    m.set_defaults(func=cmd_merge)
    return ap


def _utf8_console() -> None:
    """한국어 출력이 깨지거나 UnicodeEncodeError 로 죽지 않게 표준 출력을 UTF-8 로 맞춘다.

    Windows 에서 파이프·리디렉션(Git Bash, CI 로그, `> out.txt`)으로 출력하면 기본 인코딩이
    cp1252 같은 ANSI 코드 페이지라 한글을 쓸 수 없다. 이미 UTF-8 이면 건드리지 않는다.
    """
    for stream in (sys.stdout, sys.stderr):
        enc = (getattr(stream, "encoding", None) or "").lower().replace("-", "").replace("_", "")
        if enc == "utf8" or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def main(argv: Optional[list] = None) -> int:
    _utf8_console()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
