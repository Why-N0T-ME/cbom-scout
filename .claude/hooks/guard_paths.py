"""PreToolUse 훅: 에이전트가 허용된 경로 밖의 파일을 쓰지 못하게 막는다.

사용: python .claude/hooks/guard_paths.py <허용 경로 접두어> [<접두어> ...]
Claude Code 가 표준입력으로 도구 호출 JSON 을 넘긴다. 허용 범위 밖이면 종료 코드 2 로 막고,
표준오류에 쓴 이유가 에이전트에게 전달된다. Windows·Linux 모두 동작한다.
"""
from __future__ import annotations

import json
import os
import sys


def project_root() -> str:
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        return os.path.abspath(env)
    # 이 파일은 <root>/.claude/hooks/ 에 있다
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def normalize(path: str, root: str) -> str | None:
    """root 기준 '/' 구분 상대경로. root 밖이면 None."""
    full = os.path.abspath(path if os.path.isabs(path) else os.path.join(root, path))
    try:
        rel = os.path.relpath(full, root)
    except ValueError:  # Windows: 다른 드라이브
        return None
    rel = rel.replace(os.sep, "/")
    if rel == ".." or rel.startswith("../"):
        return None
    return rel


def main(argv: list[str]) -> int:
    allowed = [a.replace("\\", "/").lstrip("./") for a in argv[1:]]
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0  # 해석할 수 없는 입력은 막지 않는다 (훅 고장으로 작업 전체가 멈추지 않게)
    tool_input = data.get("tool_input") or {}
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or tool_input.get("path")
    if not path:
        return 0
    root = project_root()
    rel = normalize(path, root)
    if rel is not None and any(rel == a.rstrip("/") or rel.startswith(a if a.endswith("/") else a + "/")
                               for a in allowed):
        return 0
    shown = rel if rel is not None else path
    print(f"이 역할은 {', '.join(allowed)} 아래만 수정할 수 있습니다. 차단된 경로: {shown}. "
          f"다른 파일의 변경이 필요하면 보고서에 적어 메인 세션에 넘기세요.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
