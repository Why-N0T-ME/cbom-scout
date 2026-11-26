"""Windows ANSI 코드 페이지(cp1252 등)로 출력이 리디렉션돼도 한국어 출력이 죽지 않아야 한다."""
import os
import subprocess
import sys

import pytest
from conftest import DEMO, ROOT


def run_cli(*args, encoding="cp1252"):
    env = dict(os.environ, PYTHONIOENCODING=encoding, PYTHONPATH=os.path.join(ROOT, "src"))
    env.pop("GITHUB_STEP_SUMMARY", None)
    env.pop("GITHUB_ACTIONS", None)
    return subprocess.run([sys.executable, "-m", "cbom_scout.cli", *args], capture_output=True, env=env)


@pytest.mark.parametrize("encoding", ["cp1252", "ascii"])
def test_help_on_non_utf8_console(encoding):
    r = run_cli("scan", "--help", encoding=encoding)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    assert "스캔할 디렉터리" in r.stdout.decode("utf-8")


def test_scan_summary_on_non_utf8_console(tmp_path):
    r = run_cli("scan", DEMO, "-o", str(tmp_path / "c.json"))
    err = r.stderr.decode("utf-8")
    assert r.returncode == 1, err          # 데모는 취약 예제라 1 이 정상
    assert "Traceback" not in err
    assert "cbom-scout: 자산" in err
