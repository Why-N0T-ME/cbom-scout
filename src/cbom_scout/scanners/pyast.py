"""Python 구문 트리(AST) 기반 암호 API 탐지.

정규식과 달리 주석·docstring·문자열 리터럴을 코드와 구분하고, import 별칭과 같은 파일 안
상수·변수·기본값 인자를 따라가 간접적으로 넘긴 알고리즘 이름과 키 길이를 해석한다.

어떤 API 의 어느 인자가 알고리즘·키 길이·곡선·모드인지는 코드가 아니라
`data/python_api.json` 에 있다 (라이브러리 추가 = 데이터 추가).
값은 알고리즘 이름·키 길이로만 쓰고, 해석 과정에서 본 다른 값은 기록하지 않는다.
"""
from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass
from typing import Iterator, Optional

from ..catalog import classify

_KB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "python_api.json")
with open(_KB_PATH, encoding="utf-8") as _fh:
    KB: dict = json.load(_fh)["apis"]

# 마지막 구성요소 → 지식 베이스 키 (빠른 조회용)
_BY_LAST: dict = {}
for _k in KB:
    _BY_LAST.setdefault(_k.rsplit(".", 1)[-1], []).append(_k)

_MAX_DEPTH = 6
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")


@dataclass
class PyFinding:
    line: int
    alg: str
    function: Optional[str]
    kind: str                    # detection.json 의 상황 이름
    symbol: Optional[str]
    size: Optional[int] = None
    curve: Optional[str] = None
    mode: Optional[str] = None
    cipher_spec: Optional[str] = None   # 있으면 parse_cipher_spec 로 해석


class _Val:
    """해석된 값 후보. node 가 None 이면 해석 실패."""
    __slots__ = ("node", "level")

    def __init__(self, node, level: str):
        self.node = node
        self.level = level           # direct | const | ambiguous


_RANK = {"direct": 0, "const": 1, "ambiguous": 2}


def _worse(a: str, b: str) -> str:
    return a if _RANK[a] >= _RANK[b] else b


class _Scope:
    def __init__(self, node, parent: Optional["_Scope"]):
        self.node = node
        self.parent = parent
        self.assigns: dict = {}      # 이름 → [값 식 또는 None]
        self.params: dict = {}       # 이름 → 기본값 식 또는 None


def _assign_targets(target, value, out: dict) -> None:
    if isinstance(target, ast.Name):
        out.setdefault(target.id, []).append(value)
    elif isinstance(target, (ast.Tuple, ast.List)):
        vals = value.elts if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts) else None
        for i, t in enumerate(target.elts):
            _assign_targets(t, vals[i] if vals else None, out)
    elif isinstance(target, ast.Starred):
        _assign_targets(target.value, None, out)


class _Analyzer:
    def __init__(self, tree: ast.Module):
        self.tree = tree
        self.aliases: dict = {}
        self.scope_of: dict = {}     # id(노드) → _Scope (가장 가까운 함수 또는 모듈)
        self.docstrings: set = set()
        self.module = _Scope(tree, None)
        self._docstring(tree.body)
        self._index(tree, self.module)

    # ------------------------------------------------------------ 색인
    def _index(self, node, scope: _Scope) -> None:
        for child in ast.iter_child_nodes(node):
            self._visit(child, scope)

    def _visit(self, node, scope: _Scope) -> None:
        self.scope_of[id(node)] = scope
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for d in getattr(node.args, "defaults", []) + [d for d in node.args.kw_defaults if d is not None]:
                self._visit(d, scope)     # 기본값은 바깥 범위에서 평가된다
            for dec in getattr(node, "decorator_list", []):
                self._visit(dec, scope)
            inner = _Scope(node, scope)
            a = node.args
            pos = list(getattr(a, "posonlyargs", [])) + list(a.args)
            defaults = [None] * (len(pos) - len(a.defaults)) + list(a.defaults)
            for arg, d in zip(pos, defaults):
                inner.params[arg.arg] = d
            for arg, d in zip(a.kwonlyargs, a.kw_defaults):
                inner.params[arg.arg] = d
            if a.vararg:
                inner.params[a.vararg.arg] = None
            if a.kwarg:
                inner.params[a.kwarg.arg] = None
            body = node.body if isinstance(node.body, list) else [node.body]
            self._docstring(body)
            for stmt in body:
                self._visit(stmt, inner)
            return
        if isinstance(node, ast.ClassDef):
            self._docstring(node.body)
            for child in ast.iter_child_nodes(node):
                self._visit(child, scope)
            return
        if isinstance(node, ast.Import):
            for al in node.names:
                if al.asname:
                    self.aliases[al.asname] = al.name
                else:
                    head = al.name.split(".")[0]
                    self.aliases.setdefault(head, head)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for al in node.names:
                if al.name == "*":
                    continue
                self.aliases[al.asname or al.name] = f"{mod}.{al.name}" if mod else al.name
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                _assign_targets(t, node.value, scope.assigns)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            _assign_targets(node.target, node.value, scope.assigns)
        elif isinstance(node, ast.AugAssign):
            _assign_targets(node.target, None, scope.assigns)
        elif isinstance(node, ast.NamedExpr):
            _assign_targets(node.target, node.value, scope.assigns)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            _assign_targets(node.target, None, scope.assigns)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    _assign_targets(item.optional_vars, None, scope.assigns)
        self._index(node, scope)

    def _docstring(self, body: list) -> None:
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            self.docstrings.add(id(body[0].value))

    # ------------------------------------------------------------ 이름
    def qualified(self, expr) -> Optional[str]:
        parts = []
        while isinstance(expr, ast.Attribute):
            parts.append(expr.attr)
            expr = expr.value
        if not isinstance(expr, ast.Name):
            return None
        parts.append(expr.id)
        parts.reverse()
        head = self.aliases.get(parts[0])
        if head:
            parts = head.split(".") + parts[1:]
        return ".".join(parts)

    @staticmethod
    def kb_key(qn: Optional[str]) -> Optional[str]:
        if not qn:
            return None
        for key in _BY_LAST.get(qn.rsplit(".", 1)[-1], ()):
            if qn == key or qn.endswith("." + key):
                return key
        return None

    # ------------------------------------------------------------ 값 해석
    def resolve(self, expr, scope: _Scope, level: str = "direct", depth: int = 0) -> list:
        """식 → 값 후보 목록. 이름은 같은 함수 → 바깥 함수 → 모듈 순서로 대입문을 찾는다."""
        if depth > _MAX_DEPTH:
            return [_Val(None, "ambiguous")]
        if not isinstance(expr, ast.Name):
            return [_Val(expr, level)]
        name = expr.id
        s: Optional[_Scope] = scope
        while s is not None:
            if name in s.assigns or name in s.params:
                cands = list(s.assigns.get(name, []))
                via_default = False
                if name in s.params:
                    cands.append(s.params[name])
                    via_default = True
                outer = s.parent or self.module
                distinct = {ast.dump(c) if c is not None else None for c in cands}
                lv = _worse(level, "ambiguous" if (len(distinct) > 1 or via_default) else "const")
                out = []
                for c in cands:
                    if c is None:
                        out.append(_Val(None, "ambiguous"))
                    else:
                        # 기본값은 바깥 범위, 대입 값은 그 범위 안에서 평가된다
                        ev_scope = outer if (via_default and c is s.params.get(name)) else s
                        out += self.resolve(c, ev_scope, lv, depth + 1)
                return out
            s = s.parent
        return [_Val(expr, level)]   # 대입이 없는 이름 (import 한 클래스 등)

    # ------------------------------------------------------------ 인자
    @staticmethod
    def arg_expr(call: ast.Call, spec: Optional[dict]):
        if not spec:
            return None
        kw = spec.get("kw")
        for k in call.keywords:
            if kw and k.arg == kw:
                return k.value
        pos = spec.get("pos")
        if pos is not None and pos < len(call.args) and not any(isinstance(a, ast.Starred) for a in call.args[:pos + 1]):
            return call.args[pos]
        return None

    def values(self, call: ast.Call, spec: Optional[dict], scope: _Scope, kind: str):
        """인자 → [(값, 수준)]. 인자가 없으면 None, 있는데 해석 못 하면 []."""
        expr = self.arg_expr(call, spec)
        if expr is None:
            return None
        out = []
        for v in self.resolve(expr, scope):
            val = _extract(v.node, kind, spec or {})
            if val is None:
                continue
            if kind == "str" and v.level != "direct" and classify(val).status == "unknown":
                continue         # 상수로 넘어온 값은 알려진 알고리즘 이름일 때만 쓴다
            out.append((val, v.level))
        return out


def _extract(node, kind: str, spec: dict):
    if node is None:
        return None
    if kind == "str":
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and 0 < len(node.value) <= 64:
            return node.value
        return None
    if kind == "int":
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return node.value
        return None
    # attr: 곡선·모드처럼 클래스·상수 이름으로 넘기는 값
    if isinstance(node, ast.Call):
        node = node.func
    name = node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name) else None
    if not name or not _IDENT.match(name):
        return None
    prefix = spec.get("strip_prefix")
    if prefix:
        if not name.startswith(prefix):
            return None
        name = name[len(prefix):]
    return name


def _level_kind(level: str) -> str:
    return {"direct": "ast-direct", "const": "ast-const", "ambiguous": "ast-ambiguous"}[level]


def analyze(text: str, pqc_in_string: Optional[re.Pattern] = None) -> list:
    """Python 소스 → PyFinding 목록. 구문 오류면 SyntaxError 등 예외가 난다."""
    tree = ast.parse(text)
    an = _Analyzer(tree)
    findings: list = []
    consumed: set = set()

    def scope_for(node) -> _Scope:
        return an.scope_of.get(id(node), an.module)

    def ref_node(expr):
        return expr.func if isinstance(expr, ast.Call) else expr

    # 1) Cipher(algorithms.X(...), modes.Y(...)) 결합
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        key = an.kb_key(an.qualified(node.func))
        if not key or KB[key].get("role") != "cipher":
            continue
        spec = KB[key]
        scope = scope_for(node)
        alg_expr = an.arg_expr(node, spec.get("alg_arg"))
        if alg_expr is None:
            continue
        mode_expr = an.arg_expr(node, spec.get("mode_arg"))
        algs = []
        for v in an.resolve(alg_expr, scope):
            rk = an.kb_key(an.qualified(ref_node(v.node))) if v.node is not None else None
            if rk and KB[rk].get("role") == "cipher-alg":
                algs.append((KB[rk]["cipher"], v.level, ref_node(v.node)))
        if not algs:
            continue
        modes = []
        if mode_expr is None or (isinstance(mode_expr, ast.Constant) and mode_expr.value is None):
            modes = [(None, "direct", None)]
        else:
            for v in an.resolve(mode_expr, scope):
                rk = an.kb_key(an.qualified(ref_node(v.node))) if v.node is not None else None
                if rk and KB[rk].get("role") == "cipher-mode":
                    modes.append((KB[rk]["mode"], v.level, ref_node(v.node)))
            if not modes:
                continue     # 모드를 모르면 결합하지 않고 각각 따로 기록한다
        for cipher, lv1, n1 in algs:
            for mode, lv2, n2 in modes:
                consumed.add(id(n1))
                if n2 is not None:
                    consumed.add(id(n2))
                findings.append(PyFinding(node.lineno, cipher, "encrypt", _level_kind(_worse(lv1, lv2)), key,
                                          cipher_spec=cipher + (f"-{mode}" if mode else "")))

    # 2) 나머지 API
    for node in ast.walk(tree):
        if id(node) in consumed:
            continue
        if isinstance(node, ast.Call):
            key = an.kb_key(an.qualified(node.func))
            if key and KB[key].get("match") == "call" and KB[key].get("role") != "cipher":
                findings += _call_findings(an, node, key, scope_for(node))
        elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(getattr(node, "ctx", None), ast.Load):
            key = an.kb_key(an.qualified(node))
            if not key or KB[key].get("match") not in ("ref", "prefix"):
                continue
            spec = KB[key]
            role = spec.get("role")
            if role == "cipher-mode":
                st = spec.get("standalone")
                if st:
                    findings.append(PyFinding(node.lineno, st["alg"], st.get("function"), "ast-standalone-mode",
                                              key, mode=st.get("mode")))
                continue
            if "cipher" in spec:
                findings.append(PyFinding(node.lineno, spec["cipher"], spec.get("function"), "ast-direct", key,
                                          cipher_spec=spec["cipher"]))
                continue
            findings.append(PyFinding(node.lineno, spec["alg"], spec.get("function"), "ast-direct", key,
                                      mode=spec.get("mode")))

    # 3) 코드 문맥 문자열 속 PQC 이름 (docstring 제외)
    if pqc_in_string is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in an.docstrings:
                for m in pqc_in_string.finditer(node.value):
                    line = node.lineno + node.value.count("\n", 0, m.start())
                    findings.append(PyFinding(line, m.group("alg"), None, "ast-pqc-string", None))

    findings.sort(key=lambda f: (f.line, _RANK.get(f.kind, 9)))
    return findings


def _call_findings(an: _Analyzer, node: ast.Call, key: str, scope: _Scope) -> list:
    spec = KB[key]
    if "alg_arg" in spec:
        algs = an.values(node, spec["alg_arg"], scope, "str")
        if not algs:
            return []           # 알고리즘을 모르면 기록하지 않는다
    else:
        algs = [(spec.get("cipher") or spec.get("alg"), "direct")]
    sizes = an.values(node, spec.get("size_arg"), scope, "int") if "size_arg" in spec else None
    if spec.get("require_size") and not sizes:
        return []
    curves = an.values(node, spec.get("curve_arg"), scope, "attr") if "curve_arg" in spec else None
    if spec.get("require_curve") and not curves:
        return []
    modes = an.values(node, spec.get("mode_arg"), scope, "attr") if "mode_arg" in spec else None
    out = []
    for alg, lv_a in algs:
        for size, lv_s in (sizes or [(None, "direct")]):
            for curve, lv_c in (curves or [(None, "direct")]):
                for mode, lv_m in (modes or [(None, "direct")]):
                    lv = _worse(_worse(lv_a, lv_s), _worse(lv_c, lv_m))
                    if "cipher" in spec:
                        out.append(PyFinding(node.lineno, alg, spec.get("function"), _level_kind(lv), key,
                                             cipher_spec=alg + (f"-{mode}" if mode else "")))
                    else:
                        out.append(PyFinding(node.lineno, alg, spec.get("function"), _level_kind(lv), key,
                                             size=size, curve=curve))
    return out


def iter_kb_keys() -> Iterator[str]:
    return iter(KB)
