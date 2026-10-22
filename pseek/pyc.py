"""Python 字节码（.pyc / marshal 数据）读取与反汇编 —— 跨版本。

为什么需要它
------------
Python 字节码题非常常见（.pyc 附件、PyInstaller 打出来的模块、marshal blob），
而标准库帮不上忙：``marshal`` 只认**当前解释器版本**的 code object 布局，
拿 3.13 去读 3.10 编出来的 .pyc 会直接报 ``bad marshal data``。

本模块自带一个**版本无关的 marshal 解析器**（按 3.8/3.10/3.11 的 code object
字段布局），再用**对应版本的 opcode 表**做线性反汇编。opcode 数字表取自 CPython
仓库的 ``Lib/opcode.py``（3.10 那份），只做数据解析、不执行任何外部代码。

用法
----
    python autocrypt.py pyc check.pyc              # 版本 + 常量/名字/反汇编摘要
    python autocrypt.py pyc check.pyc --dis        # 反汇编所有 code object
    python autocrypt.py pyc check.pyc --json
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# 版本魔数（前两字节 = 版本号，后两字节固定 0d 0a）
# --------------------------------------------------------------------------

MAGIC_TO_VERSION = {
    b"3\r\r\n": "3.6", b"B\r\r\n": "3.7", b"U\r\r\n": "3.8", b"a\r\r\n": "3.9",
    b"o\r\r\n": "3.10", b"\xa7\r\r\n": "3.11", b"\xcb\r\r\n": "3.12",
    b"\xf3\r\r\n": "3.13", b"\x1b\r\r\n": "3.14",
}


def pyc_version(blob: bytes) -> Optional[str]:
    if len(blob) < 4:
        return None
    return MAGIC_TO_VERSION.get(blob[:4])


def _vtuple(version: str) -> Tuple[int, ...]:
    """把 "3.10" 变成 (3, 10)，避免用字符串比较版本（"3.10" < "3.8" 的坑）。"""
    parts: List[int] = []
    for piece in str(version).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits or 0))
    return tuple(parts)


# --------------------------------------------------------------------------
# 3.10 opcode 表（取自 CPython Lib/opcode.py）
# --------------------------------------------------------------------------

_OPCODE_3_10_RAW = """
POP_TOP 1 ROT_TWO 2 ROT_THREE 3 DUP_TOP 4 DUP_TOP_TWO 5 ROT_FOUR 6 NOP 9
UNARY_POSITIVE 10 UNARY_NEGATIVE 11 UNARY_NOT 12 UNARY_INVERT 15
BINARY_MATRIX_MULTIPLY 16 INPLACE_MATRIX_MULTIPLY 17 BINARY_POWER 19
BINARY_MULTIPLY 20 BINARY_MODULO 22 BINARY_ADD 23 BINARY_SUBTRACT 24
BINARY_SUBSCR 25 BINARY_FLOOR_DIVIDE 26 BINARY_TRUE_DIVIDE 27
INPLACE_FLOOR_DIVIDE 28 INPLACE_TRUE_DIVIDE 29 GET_LEN 30 MATCH_MAPPING 31
MATCH_SEQUENCE 32 MATCH_KEYS 33 COPY_DICT_WITHOUT_KEYS 34 WITH_EXCEPT_START 49
GET_AITER 50 GET_ANEXT 51 BEFORE_ASYNC_WITH 52 END_ASYNC_FOR 54 INPLACE_ADD 55
INPLACE_SUBTRACT 56 INPLACE_MULTIPLY 57 INPLACE_MODULO 59 STORE_SUBSCR 60
DELETE_SUBSCR 61 BINARY_LSHIFT 62 BINARY_RSHIFT 63 BINARY_AND 64 BINARY_XOR 65
BINARY_OR 66 INPLACE_POWER 67 GET_ITER 68 GET_YIELD_FROM_ITER 69 PRINT_EXPR 70
LOAD_BUILD_CLASS 71 YIELD_FROM 72 GET_AWAITABLE 73 LOAD_ASSERTION_ERROR 74
INPLACE_LSHIFT 75 INPLACE_RSHIFT 76 INPLACE_AND 77 INPLACE_XOR 78 INPLACE_OR 79
LIST_TO_TUPLE 82 RETURN_VALUE 83 IMPORT_STAR 84 SETUP_ANNOTATIONS 85
YIELD_VALUE 86 POP_BLOCK 87 POP_EXCEPT 89 STORE_NAME 90 DELETE_NAME 91
UNPACK_SEQUENCE 92 FOR_ITER 93 UNPACK_EX 94 STORE_ATTR 95 DELETE_ATTR 96
STORE_GLOBAL 97 DELETE_GLOBAL 98 ROT_N 99 LOAD_CONST 100 LOAD_NAME 101
BUILD_TUPLE 102 BUILD_LIST 103 BUILD_SET 104 BUILD_MAP 105 LOAD_ATTR 106
COMPARE_OP 107 IMPORT_NAME 108 IMPORT_FROM 109 JUMP_FORWARD 110
JUMP_IF_FALSE_OR_POP 111 JUMP_IF_TRUE_OR_POP 112 JUMP_ABSOLUTE 113
POP_JUMP_IF_FALSE 114 POP_JUMP_IF_TRUE 115 LOAD_GLOBAL 116 IS_OP 117
CONTAINS_OP 118 RERAISE 119 JUMP_IF_NOT_EXC_MATCH 121 SETUP_FINALLY 122
LOAD_FAST 124 STORE_FAST 125 DELETE_FAST 126 GEN_START 129 RAISE_VARARGS 130
CALL_FUNCTION 131 MAKE_FUNCTION 132 BUILD_SLICE 133 LOAD_CLOSURE 135 LOAD_DEREF 136
STORE_DEREF 137 DELETE_DEREF 138 CALL_FUNCTION_KW 141 CALL_FUNCTION_EX 142
SETUP_WITH 143 EXTENDED_ARG 144 LIST_APPEND 145 SET_ADD 146 MAP_ADD 147
LOAD_CLASSDEREF 148 MATCH_CLASS 152 SETUP_ASYNC_WITH 154 FORMAT_VALUE 155
BUILD_CONST_KEY_MAP 156 BUILD_STRING 157 LOAD_METHOD 160 CALL_METHOD 161
LIST_EXTEND 162 SET_UPDATE 163 DICT_MERGE 164 DICT_UPDATE 165
"""


def _parse_opcodes(raw: str) -> Tuple[List[str], Dict[str, int]]:
    tokens = raw.split()
    names = [f"<{i}>" for i in range(256)]
    mapping: Dict[str, int] = {}
    for i in range(0, len(tokens), 2):
        name, num = tokens[i], int(tokens[i + 1])
        names[num] = name
        mapping[name] = num
    return names, mapping


OPNAME_310, OPMAP_310 = _parse_opcodes(_OPCODE_3_10_RAW)

HAS_CONST = {100}
HAS_NAME = {90, 91, 95, 96, 97, 98, 101, 106, 108, 109, 116, 160}
HAS_LOCAL = {124, 125, 126}
HAS_FREE = {135, 136, 137, 138, 148}
HAS_COMPARE = {107}
HAS_JREL = {93, 110, 114, 115, 122, 143, 154}
HAS_JABS = {111, 112, 113, 114, 115, 121}

CMP_OPS = ("<", "<=", "==", "!=", ">", ">=")


# --------------------------------------------------------------------------
# marshal 解析（版本无关）
# --------------------------------------------------------------------------

@dataclass
class PyCode:
    name: str = ""
    qualname: str = ""
    filename: str = ""
    firstlineno: int = 0
    argcount: int = 0
    flags: int = 0
    nlocals: int = 0
    stacksize: int = 0
    code: bytes = b""
    consts: Tuple = ()
    names: Tuple = ()
    varnames: Tuple = ()
    freevars: Tuple = ()
    cellvars: Tuple = ()
    localspluskinds: bytes = b""
    children: List["PyCode"] = field(default_factory=list)

    @property
    def argnames(self) -> Tuple[str, ...]:
        return tuple(self.varnames[: self.argcount])

    def walk(self) -> Iterable["PyCode"]:
        yield self
        for child in self.children:
            yield from child.walk()


class MarshalError(ValueError):
    pass


class _Null:
    """TYPE_NULL（'0'）—— 只用于字典终止符，和 None 区分开。"""

    def __repr__(self) -> str:                     # pragma: no cover
        return "<NULL>"


NULL = _Null()


class _Reader:
    def __init__(self, data: bytes, version: str = "3.10"):
        self.data = data
        self.pos = 0
        self.refs: List[object] = []
        self.version = version

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise MarshalError("数据截断")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise MarshalError("数据截断")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def i32(self) -> int:
        return struct.unpack("<i", self.read(4))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.read(8))[0]

    def short(self) -> int:
        return self.byte()

    def string(self) -> bytes:
        return self.read(self.i32())

    def short_string(self) -> bytes:
        return self.read(self.short())

    def unicode(self) -> str:
        return self.read(self.i32()).decode("utf-8", "replace")

    # -- 主体：带 FLAG_REF 的类型分发 ----------------------------------
    def object(self):
        raw = self.byte()
        ref = bool(raw & 0x80)                     # marshal 的 FLAG_REF
        return self._typed(bytes([raw & 0x7F]), ref)

    def _reserve(self):
        self.refs.append(None)
        return len(self.refs) - 1

    def _fill(self, index: int, value):
        self.refs[index] = value
        return value

    def _typed(self, ch: bytes, ref: bool = False):
        """按 marshal 类型分发。

        注意（踩过的坑）：CPython 的 ``w_object`` 对**任何**对象都会先试 ``w_ref``，
        也就是说 ``FLAG_REF`` 不只出现在容器上——共享的小整数（0/1/26…）、
        字符串、bytes、float 都可能带 FLAG_REF 并占用 ref 槽。
        漏掉这些槽位会导致后面的 ``TYPE_REF`` 索引整体错位。
        """
        def keep(value):
            if ref:
                self.refs.append(value)
            return value

        if ch == b"0":
            return NULL
        if ch == b"N":
            return None
        if ch == b"F":
            return False
        if ch == b"T":
            return True
        if ch == b"S":
            return StopIteration
        if ch == b".":
            return Ellipsis
        if ch == b"i":
            return keep(self.i32())
        if ch == b"I":
            return keep(self.i64())
        if ch == b"l":
            size = self.i32()
            if size < 0:
                raise MarshalError("long 长度为负")
            digits = [struct.unpack("<H", self.read(2))[0] for _ in range(abs(size))]
            value = 0
            for i, d in enumerate(digits):
                value += d << (15 * i)
            return keep(-value if size < 0 else value)
        if ch == b"g":
            return keep(struct.unpack("<d", self.read(8))[0])
        if ch == b"f":
            return keep(float(self.read(self.byte()).decode("ascii", "replace")))
        if ch == b"y":
            return keep(complex(struct.unpack("<d", self.read(8))[0],
                                struct.unpack("<d", self.read(8))[0]))
        if ch == b"x":
            real = float(self.read(self.byte()).decode("ascii", "replace"))
            imag = float(self.read(self.byte()).decode("ascii", "replace"))
            return keep(complex(real, imag))
        if ch in (b"s", b"t"):
            value = self.string()
            if ref or ch == b"t":
                self.refs.append(value)
            return value
        if ch == b"u":
            value = self.unicode()
            if ref:
                self.refs.append(value)
            return value
        if ch in (b"a", b"A"):
            value = self.string().decode("ascii", "replace")
            if ref or ch == b"A":
                self.refs.append(value)
            return value
        if ch in (b"z", b"Z"):
            value = self.short_string().decode("ascii", "replace")
            if ref or ch == b"Z":
                self.refs.append(value)
            return value
        if ch == b"r":
            idx = self.i32()
            if idx < 0 or idx >= len(self.refs):
                raise MarshalError(f"引用越界：{idx}（当前 ref 表 {len(self.refs)} 项）")
            value = self.refs[idx]
            if value is None:
                raise MarshalError(f"引用 {idx} 为空槽（解析顺序不对）")
            return value
        if ch in (b"(", b")"):
            return self._tuple(self.i32() if ch == b"(" else self.short(), ref)
        if ch == b"[":
            return self._list(self.i32(), ref)
        if ch == b"{":
            return self._dict(ref)
        if ch == b"<":
            size = self.i32()
            index = self._reserve() if ref else -1
            value = {self.object() for _ in range(max(0, size))}
            return self._fill(index, value) if ref else value
        if ch == b">":
            size = self.i32()
            index = self._reserve() if ref else -1
            value = frozenset(self.object() for _ in range(max(0, size)))
            return self._fill(index, value) if ref else value
        if ch == b"c":
            return self._code(ref)
        raise MarshalError(f"未知 marshal 类型 {ch!r}（位置 {self.pos - 1}）")

    def _tuple(self, size: int, ref: bool = False) -> Tuple:
        if size < 0 or size > 1_000_000:
            raise MarshalError("元组长度异常")
        # CPython 语义：先占位（自引用结构也能正确解析），再逐项填充
        index = self._reserve() if ref else -1
        items = tuple(self.object() for _ in range(size))
        return self._fill(index, items) if ref else items

    def _list(self, size: int, ref: bool = False) -> List:
        index = self._reserve() if ref else -1
        value = [self.object() for _ in range(max(0, size))]
        return self._fill(index, value) if ref else value

    def _dict(self, ref: bool = False) -> Dict:
        value: Dict = {}
        index = self._reserve() if ref else -1
        while True:
            key = self.object()
            if key is NULL:
                break
            value[key] = self.object()
        return self._fill(index, value) if ref else value

    def _code(self, ref: bool = False) -> PyCode:
        ver = _vtuple(self.version)
        code = PyCode()
        index = self._reserve() if ref else -1
        code.argcount = self.i32()
        if ver >= (3, 8):
            self.i32()                                   # posonlyargcount
        code.kwonlyargcount = self.i32()
        if ver < (3, 11):
            code.nlocals = self.i32()
        code.stacksize = self.i32()
        code.flags = self.i32()
        code.code = self.object()
        code.consts = tuple(self.object() or ())
        code.names = tuple(self.object() or ())
        if ver >= (3, 11):
            # 3.11 起 co_varnames/freevars/cellvars 变成派生属性，
            # marshal 里换成 localsplusnames + localspluskinds
            code.varnames = tuple(self.object() or ())
            code.localspluskinds = self.object() or b""
        else:
            code.varnames = tuple(self.object() or ())
            code.freevars = tuple(self.object() or ())
            code.cellvars = tuple(self.object() or ())
        code.filename = self.object()
        code.name = self.object()
        if ver >= (3, 11):
            code.qualname = self.object()
        code.firstlineno = self.i32()
        self.object()                                    # lnotab / linetable
        if ver >= (3, 11):
            self.object()                                # exceptiontable
        for const in code.consts:
            if isinstance(const, PyCode):
                code.children.append(const)
        return self._fill(index, code) if ref else code


def load_code(blob: bytes, version: Optional[str] = None) -> PyCode:
    """读 .pyc（自动跳过头部）或裸 marshal 数据，返回顶层 code object。"""
    ver = version or pyc_version(blob) or "3.10"
    body = blob
    if pyc_version(blob):
        # 头部：3.7+ 是 16 字节（magic4 + flags4 + mtime/hash4 + size4），3.3~3.6 是 12 字节。
        # marshal 首字节可能带 FLAG_REF(0x80)，所以掩掉最高位再比类型码。
        for offset in (16, 12):
            if offset < len(blob) and (blob[offset] & 0x7F) in (0x63, 0x72):
                body = blob[offset:]
                break
    reader = _Reader(body, ver)
    root = reader.object()
    if not isinstance(root, PyCode):
        raise MarshalError(f"顶层对象不是 code object，而是 {type(root).__name__}")
    return root


# --------------------------------------------------------------------------
# 反汇编
# --------------------------------------------------------------------------

@dataclass
class Ins:
    offset: int
    opname: str
    opcode: int
    arg: Optional[int]
    argval: str = ""
    raw: bytes = b""

    def line(self) -> str:
        head = f"{self.offset:>5}  {self.opname:<24}"
        if self.arg is None:
            return head
        return f"{head}{self.arg:<6} {self.argval}"


def _argval(code: PyCode, opcode: int, arg: int) -> str:
    try:
        if opcode in HAS_CONST and 0 <= arg < len(code.consts):
            value = code.consts[arg]
            return f"({_brief(value)})"
        if opcode in HAS_NAME and 0 <= arg < len(code.names):
            return f"({code.names[arg]})"
        if opcode in HAS_LOCAL and 0 <= arg < len(code.varnames):
            return f"({code.varnames[arg]})"
        if opcode in HAS_FREE and 0 <= arg < len(code.cellvars) + len(code.freevars):
            return f"({arg})"
        if opcode in HAS_COMPARE and 0 <= arg < len(CMP_OPS):
            return f"({CMP_OPS[arg]})"
    except Exception:
        pass
    return ""


def _brief(value, limit: int = 60) -> str:
    if isinstance(value, PyCode):
        return f"<code {value.name}>"
    text = repr(value)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def disassemble(code: PyCode, opnames: Sequence[str] = None,
                opmap: Dict[str, int] = None) -> List[Ins]:
    """线性反汇编（3.10 指令流：2 字节定长 + EXTENDED_ARG）。"""
    names = opnames or OPNAME_310
    out: List[Ins] = []
    data = code.code or b""
    pos = 0
    extended = 0
    while pos < len(data):
        opcode = data[pos]
        arg = data[pos + 1] if pos + 1 < len(data) else 0
        raw = data[pos:pos + 2]
        pos += 2
        if opcode == 144:                     # EXTENDED_ARG
            extended = (extended << 8) | arg
            out.append(Ins(pos - 2, names[opcode] if opcode < 256 else "?", opcode, arg,
                           f"=> {extended}", raw))
            continue
        full = (extended << 8) | arg
        extended = 0
        name = names[opcode] if opcode < len(names) else f"<{opcode}>"
        out.append(Ins(pos - 2, name, opcode, arg if opcode >= 90 else None,
                       _argval(code, opcode, full), raw))
    return out


def dis_text(code: PyCode, indent: int = 0, version: str = "3.10") -> str:
    pad = " " * indent
    head = (f"{pad}── code object {code.name!r}  "
            f"(args={code.argnames}, nlocals={code.nlocals}, "
            f"stack={code.stacksize}, firstline={code.firstlineno})")
    lines = [head]
    if _vtuple(version) != (3, 10):
        lines.append(pad + "  （注意：反汇编用的是 Python 3.10 指令表；"
                          "3.11+ 指令编号有变化，指令名仅供参考，"
                          "常量/名字/字节码长度仍然准确）")
    for ins in disassemble(code):
        lines.append(pad + "  " + ins.line())
    for child in code.children:
        lines.append("")
        lines.append(dis_text(child, indent + 2, version))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# 便于"直接找线索"的摘要
# --------------------------------------------------------------------------

def summary(code: PyCode) -> Dict[str, object]:
    """把常量/名字/局部变量都摊平，方便一眼看出算法与密钥常量。"""
    consts: List[str] = []
    names: List[str] = []
    hexes: List[str] = []
    strings: List[str] = []

    def visit(node: PyCode) -> None:
        for name in node.names:
            if isinstance(name, str):
                names.append(name)
        for const in node.consts:
            if isinstance(const, PyCode):
                visit(const)
                continue
            if isinstance(const, bytes):
                if len(const) >= 8 and all(32 <= b < 127 for b in const):
                    text = const.decode("latin-1")
                    strings.append(text)
                    if all(c in "0123456789abcdefABCDEF" for c in text) and len(text) % 2 == 0:
                        hexes.append(text)
                else:
                    hexes.append(const.hex())
            elif isinstance(const, str):
                strings.append(const)
                if all(c in "0123456789abcdefABCDEF" for c in const) and len(const) >= 16 \
                        and len(const) % 2 == 0:
                    hexes.append(const)
            elif isinstance(const, (int, float, complex, tuple, frozenset)):
                consts.append(repr(const))

    visit(code)
    return {"names": sorted(set(names)), "strings": strings, "hex": hexes,
            "consts": consts, "codes": [c.name for c in code.walk()]}


def report(blob: bytes, want_dis: bool = False, as_json: bool = False) -> str:
    version = pyc_version(blob) or "未知"
    try:
        root = load_code(blob)
    except Exception as exc:
        return f"解析失败：{type(exc).__name__}: {exc}"
    info = summary(root)
    if as_json:
        return json.dumps({"version": version, "codes": info["codes"],
                           "names": info["names"], "strings": info["strings"][:80],
                           "hex": info["hex"][:40]}, ensure_ascii=False, indent=2)
    lines = [f"pyc 版本：Python {version}（magic {blob[:4].hex()}）",
             f"code object：{', '.join(info['codes'])}",
             f"名字池（{len(info['names'])}）：{', '.join(info['names'][:40])}"]
    if info["hex"]:
        lines.append(f"十六进制常量（{len(info['hex'])}）：")
        for item in info["hex"][:12]:
            lines.append(f"    {item}")
    if info["strings"]:
        lines.append(f"字符串常量（{len(info['strings'])}）：")
        for item in info["strings"][:24]:
            lines.append(f"    {item[:100]!r}")
    if want_dis:
        lines.append("")
        lines.append(dis_text(root, version=version))
    return "\n".join(lines)
