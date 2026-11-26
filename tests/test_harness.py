"""파이프라인 하네스 점검: 역할 정의 파일과 경로 차단 훅."""
import json
import os
import subprocess
import sys

from conftest import ROOT

HOOK = os.path.join(ROOT, ".claude", "hooks", "guard_paths.py")
AGENTS = os.path.join(ROOT, ".claude", "agents")


def run_hook(file_path, *allowed, tool="Write"):
    payload = json.dumps({"tool_name": tool, "tool_input": {"file_path": file_path}})
    env = dict(os.environ, CLAUDE_PROJECT_DIR=ROOT)
    p = subprocess.run([sys.executable, HOOK, *allowed], input=payload, capture_output=True,
                       text=True, encoding="utf-8", env=env)
    return p.returncode, p.stderr


def test_hook_allows_inside():
    assert run_hook("docs/specs/baseline.md", "docs/specs/")[0] == 0
    assert run_hook(os.path.join(ROOT, "tests", "acceptance", "t.py"), "tests/", "docs/test-reports/")[0] == 0


def test_hook_blocks_outside():
    code, err = run_hook("src/cbom_scout/cli.py", "docs/specs/")
    assert code == 2 and "docs/specs/" in err
    # 접두어만 같은 형제 폴더도 막는다
    assert run_hook("docs/specs-old/x.md", "docs/specs/")[0] == 2
    # 상위 경로 탈출
    assert run_hook("docs/specs/../../src/x.py", "docs/specs/")[0] == 2
    assert run_hook(os.path.abspath(os.path.join(ROOT, "..", "elsewhere.txt")), "docs/specs/")[0] == 2


def test_hook_windows_style_path():
    rel = "docs\\specs\\baseline.md" if os.sep == "\\" else "docs/specs/baseline.md"
    assert run_hook(rel, "docs\\specs\\")[0] == 0


def test_hook_ignores_bad_input():
    p = subprocess.run([sys.executable, HOOK, "docs/specs/"], input="not json", capture_output=True, text=True)
    assert p.returncode == 0


def test_agent_definitions():
    expect = {"pm.md": "docs/specs/", "tester.md": "tests/ docs/test-reports/", "reporter.md": "docs/reports/"}
    for fname, allowed in expect.items():
        text = open(os.path.join(AGENTS, fname), encoding="utf-8").read()
        assert text.startswith("---\n")
        front = text.split("---\n")[1]
        assert f"name: {fname[:-3]}" in front and "description:" in front
        assert f"guard_paths.py {allowed}" in front
        assert "Bash" not in front.split("tools:")[1].split("\n")[0] or fname != "pm.md"
