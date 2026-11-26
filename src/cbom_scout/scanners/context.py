"""C 계열 언어(Java·Kotlin·Scala·Go·JS/TS·C/C++·C#)의 주석·문자열 문맥 판정.

줄마다 '문맥 지도'를 만든다. 지도는 같은 길이의 문자열이고 각 글자는
  c = 코드, s = 문자열 리터럴(따옴표 포함), m = 주석
이다. 정규식 규칙은 매치 시작 글자가 코드(c)일 때만 기록한다.

지원 문법 (명세 '그 밖의 언어 — 최소 지원 문법'):
  // 줄 주석, /* */ 블록 주석(여러 줄), "…"·'…' (백슬래시 이스케이프, 줄 끝에서 끝남),
  Go·JS/TS `…`(여러 줄), Java/Kotlin·C# \"\"\"…\"\"\"(여러 줄), C# @"…"(\"\" 이스케이프, 여러 줄).
닫히지 않은 블록 주석은 파일 끝까지, 닫히지 않은 일반 문자열은 그 줄 끝까지로 본다.
템플릿 `${}` 보간, JS 정규식 리터럴, C++ R"(…)", 중첩 블록 주석은 다루지 않는다.
"""
from __future__ import annotations

import re

CODE, STRING, COMMENT = "c", "s", "m"

# 언어별 여러 줄 문자열 종류
_FEATURES = {
    "java": {"text_block"},
    "go": {"backtick"},
    "js": {"backtick"},
    "c": set(),
    "csharp": {"verbatim", "text_block"},
}

_OPENERS = {
    # 우선순위가 높은(긴) 토큰부터
    "java": re.compile(r'//|/\*|"""|"|\''),
    "go": re.compile(r'//|/\*|`|"|\''),
    "js": re.compile(r'//|/\*|`|"|\''),
    "c": re.compile(r'//|/\*|"|\''),
    "csharp": re.compile(r'//|/\*|"""|\$?@\$?"|"|\''),
}

_END_BLOCK = re.compile(r"\*/")
_END_TEXT_BLOCK = re.compile(r'"""')
_END_BACKTICK = re.compile(r"\\.|`")
_END_VERBATIM = re.compile(r'""|"')


def _end_quoted(line: str, i: int, q: str) -> int:
    """i 는 여는 따옴표 다음 위치. 닫는 따옴표 다음 위치를 돌려준다. 못 찾으면 줄 끝."""
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "\\":
            i += 2
            continue
        if ch == q:
            return i + 1
        i += 1
    return n


def context_maps(lines: list[str], lang: str) -> list[str]:
    """줄 목록 → 줄별 문맥 지도."""
    opener = _OPENERS[lang]
    feats = _FEATURES[lang]
    state = None          # None(코드) | 'block' | 'text_block' | 'backtick' | 'verbatim'
    maps: list[str] = []
    for line in lines:
        n = len(line)
        out: list[str] = []
        i = 0
        while i < n:
            if state == "block":
                m = _END_BLOCK.search(line, i)
                end = m.end() if m else n
                out.append(COMMENT * (end - i))
                i = end
                if m:
                    state = None
                continue
            if state in ("text_block", "backtick", "verbatim"):
                end = n
                closed = False
                if state == "text_block":
                    m = _END_TEXT_BLOCK.search(line, i)
                    if m:
                        end, closed = m.end(), True
                elif state == "backtick":
                    for m in _END_BACKTICK.finditer(line, i):
                        if m.group() == "`":
                            end, closed = m.end(), True
                            break
                else:
                    for m in _END_VERBATIM.finditer(line, i):
                        if m.group() == '"':
                            end, closed = m.end(), True
                            break
                out.append(STRING * (end - i))
                i = end
                if closed:
                    state = None
                continue
            m = opener.search(line, i)
            if not m:
                out.append(CODE * (n - i))
                break
            out.append(CODE * (m.start() - i))
            tok = m.group()
            i = m.start()
            if tok == "//":
                out.append(COMMENT * (n - i))
                i = n
            elif tok == "/*":
                out.append(COMMENT * 2)
                i += 2
                state = "block"
            elif tok == '"""' and "text_block" in feats:
                out.append(STRING * 3)
                i += 3
                state = "text_block"
            elif tok == "`" and "backtick" in feats:
                out.append(STRING)
                i += 1
                state = "backtick"
            elif tok.endswith('"') and "@" in tok and "verbatim" in feats:
                out.append(STRING * len(tok))
                i += len(tok)
                state = "verbatim"
            else:
                q = tok[-1]
                end = _end_quoted(line, i + 1, q)
                out.append(STRING * (end - i))
                i = end
        maps.append("".join(out)[:n])
    return maps


def blank_comments(line: str, cmap: str) -> str:
    """주석 글자를 공백으로 바꾼 줄 (앞보기용)."""
    if COMMENT not in cmap:
        return line
    return "".join(" " if k == COMMENT else ch for ch, k in zip(line, cmap))


def lang_of(ext: str) -> str | None:
    from .code import LANG_EXT
    for lang in ("java", "go", "js", "c", "csharp"):
        if ext in LANG_EXT[lang]:
            return lang
    return None
