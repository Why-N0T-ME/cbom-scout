"""키·비밀 값이 CBOM 에 새지 않는지 확인한다 (CLAUDE.md 규칙)."""
import json

from cbom_scout.cbom import to_cbom
from cbom_scout.inventory import Inventory
from cbom_scout.scanners.code import scan_code

SECRET = "0123456789abcdef-TOPSECRET"


def test_hardcoded_key_on_same_line_not_in_cbom(tmp_path):
    (tmp_path / "a.py").write_text(
        "from Crypto.Cipher import DES\n"
        f'c = DES.new(b"{SECRET}", DES.MODE_ECB)\n'
        f'h = hashlib.md5(b"{SECRET}")\n',
        encoding="utf-8")
    (tmp_path / "B.java").write_text(
        f'class B {{ byte[] k = "{SECRET}".getBytes(); Cipher c = Cipher.getInstance("DES"); }}\n',
        encoding="utf-8")
    inv = Inventory()
    assert scan_code(str(tmp_path), inv) > 0
    out = json.dumps(to_cbom(inv), ensure_ascii=False)
    assert SECRET not in out
    assert "additionalContext" not in out
    # 위치·줄 번호는 그대로 남는다
    md5 = inv.components["crypto/algorithm/MD5"]
    assert {"location": "a.py", "line": 3} in md5["evidence"]["occurrences"]
