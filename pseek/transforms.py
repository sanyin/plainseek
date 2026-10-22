"""可插拔变换注册表：编码、压缩、位运算、古典密码、加密算法。

一个"变换"要回答四件事：

* ``detect``  这串数据**像不像**需要这个变换（0~1，用于搜索剪枝）
* ``params``  有哪些参数候选（密钥、常量、模式……）
* ``run``     实际执行（解码方向）
* ``encode``  逆变换（可选，用于"重新加密"复核）

这样"两三个加密叠在一起"就变成：对数据反复应用变换，用 oracles 打分，
能解对的那条链自然浮出来——不需要事先知道一共有几层。
"""

from __future__ import annotations

import base64 as _b64
import binascii
import bz2
import codecs
import gzip
import html
import io
import itertools
import json
import lzma
import re
import struct
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import alphabets, ciphers, oracles

# --------------------------------------------------------------------------
# 上下文与配方
# --------------------------------------------------------------------------


@dataclass
class Ctx:
    """搜索上下文：密钥、字符表、参考文件等外部信息。"""

    keys: List[bytes] = field(default_factory=list)
    key_transforms: Tuple[str, ...] = ("bitrev", "raw", "reverse", "bitrev_all")
    keystreams: List[bytes] = field(default_factory=list)   # 由"明文/密文对照"恢复的密钥流
    deep: bool = False
    max_fanout: int = 64
    tables: Dict[str, bytes] = field(default_factory=dict)   # 自定义字符表
    fmt: str = ""
    reference: Optional[bytes] = None
    known_spans: List[Tuple[int, bytes]] = field(default_factory=list)
    counters: Dict[str, int] = field(default_factory=dict)
    # crib = 已知明文/已知正则（CyberChef Magic 的 "crib" 思路）：
    # 设了它就只认命中的结果，等于把"解对了"的判断权直接交给用户。
    crib: Optional[bytes] = None
    crib_regex: Optional[object] = None
    log: Callable[[str], None] = lambda _m: None

    def allow(self, name: str, limit: int) -> bool:
        """给"很贵"的变换加调用次数上限，避免一次搜索把它反复跑满。"""
        used = self.counters.get(name, 0)
        if used >= limit:
            return False
        self.counters[name] = used + 1
        return True

    def note(self, name: str, message: str, limit: int = 2) -> None:
        """限频日志：同一条信息最多打印几次（大二进制上某些变换会命中上千次）。"""
        key = f"note:{name}"
        used = self.counters.get(key, 0)
        if used >= limit:
            return
        self.counters[key] = used + 1
        self.log(message + ("（后续同类信息省略）" if used + 1 == limit else ""))

    def key_list(self) -> List[bytes]:
        out = [k for k in self.keys if k]
        if not out:
            out = [b"key", b"password", b"secret", b"flag"]
        return out


@dataclass
class Step:
    name: str
    params: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        if not self.params:
            return self.name
        body = ",".join(f"{k}={_fmt_param(v)}" for k, v in self.params.items())
        return f"{self.name}:{body}"


def _fmt_param(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("ascii")
        except UnicodeDecodeError:
            return "0x" + value.hex()
    if isinstance(value, int) and not isinstance(value, bool):
        return hex(value) if value > 9 else str(value)
    return str(value)


# --------------------------------------------------------------------------
# 注册表
# --------------------------------------------------------------------------

REGISTRY: Dict[str, "Transform"] = {}
CATEGORIES: Dict[str, List[str]] = {}


class Transform:
    def __init__(self, name: str, fn: Callable, detect: Optional[Callable] = None,
                 params: Optional[Callable] = None, encode: Optional[Callable] = None,
                 category: str = "misc", help: str = ""):
        self.name = name
        self.fn = fn
        self.detect_fn = detect or (lambda data, ctx: 0.5)
        self.params_fn = params or (lambda data, ctx: [{}])
        self.encode_fn = encode
        self.category = category
        self.help = help

    def detect(self, data: bytes, ctx: Ctx) -> float:
        try:
            return float(self.detect_fn(data, ctx))
        except Exception:
            return 0.0

    def params(self, data: bytes, ctx: Ctx) -> List[Dict[str, Any]]:
        try:
            out = list(self.params_fn(data, ctx))
        except Exception:
            return []
        if not ctx.deep and len(out) > ctx.max_fanout:
            out = out[: ctx.max_fanout]
        return out

    def run(self, data: bytes, params: Dict[str, Any], ctx: Ctx) -> bytes:
        out = self.fn(data, params, ctx)
        if not isinstance(out, (bytes, bytearray)):
            raise TypeError(f"{self.name} 返回了非字节类型")
        return bytes(out)

    def encode(self, data: bytes, params: Dict[str, Any], ctx: Ctx) -> bytes:
        if self.encode_fn is None:
            raise NotImplementedError(f"{self.name} 没有逆变换")
        return bytes(self.encode_fn(data, params, ctx))


def register(name: str, detect: Optional[Callable] = None, params: Optional[Callable] = None,
             encode: Optional[Callable] = None, category: str = "misc", help: str = ""):
    def deco(fn):
        t = Transform(name, fn, detect, params, encode, category, help)
        REGISTRY[name] = t
        CATEGORIES.setdefault(category, []).append(name)
        return fn
    return deco


def get_transform(name: str) -> Transform:
    if name not in REGISTRY:
        raise KeyError(f"未知变换：{name}（可用：{', '.join(sorted(REGISTRY))}）")
    return REGISTRY[name]


def all_transforms() -> List[Transform]:
    return list(REGISTRY.values())


# --------------------------------------------------------------------------
# 参数解析
# --------------------------------------------------------------------------

def parse_value(text: str, ctx: Optional[Ctx] = None) -> Any:
    text = text.strip()
    if text.startswith("@"):
        idx = int(text[1:])
        keys = ctx.key_list() if ctx else []
        return keys[idx] if idx < len(keys) else b""
    if text.startswith("'") and text.endswith("'") and len(text) >= 2:
        return text[1:-1].encode()
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        return text[1:-1].encode()
    low = text.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("none", "null", ""):
        return None
    try:
        if low.startswith("0x"):
            return int(low, 16)
        return int(low)
    except ValueError:
        pass
    if text.startswith("hex:"):
        return bytes.fromhex(text[4:])
    return text


def parse_recipe(text: str, ctx: Optional[Ctx] = None) -> List[Step]:
    """把 ``"rev,hex,xor:0x5a"`` 这种配方解析成步骤列表。"""
    steps: List[Step] = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if ":" in chunk:
            name, body = chunk.split(":", 1)
            params: Dict[str, Any] = {}
            if "=" in body:
                for pair in body.split(","):
                    if not pair.strip():
                        continue
                    k, _, v = pair.partition("=")
                    params[k.strip()] = parse_value(v, ctx)
            else:
                params = {"value": parse_value(body, ctx)}
            steps.append(Step(name.strip(), params))
        else:
            steps.append(Step(chunk))
    return steps


def recipe_str(steps: Sequence[Step]) -> str:
    return ",".join(str(s) for s in steps)


def apply_recipe(data: bytes, steps: Sequence[Step], ctx: Optional[Ctx] = None) -> bytes:
    ctx = ctx or Ctx()
    for step in steps:
        data = get_transform(step.name).run(data, dict(step.params), ctx)
    return data


# --------------------------------------------------------------------------
# 位 / 字节级变换
# --------------------------------------------------------------------------

_BITREV_TABLE = bytes(int(f"{b:08b}"[::-1], 2) for b in range(256))
_NIBSWAP_TABLE = bytes(((b & 0x0F) << 4) | (b >> 4) for b in range(256))
_NOT_TABLE = bytes(b ^ 0xFF for b in range(256))


@register("reverse", detect=lambda d, c: 0.3, encode=lambda d, p, c: d[::-1],
          category="bit", help="整串字节倒序")
def _reverse(data, params, ctx):
    return data[::-1]


@register("bitrev", detect=lambda d, c: 0.3, encode=lambda d, p, c: d.translate(_BITREV_TABLE),
          category="bit", help="每个字节的 8 个 bit 倒序（DES 变体题常见）")
def _bitrev(data, params, ctx):
    return data.translate(_BITREV_TABLE)


@register("nibswap", detect=lambda d, c: 0.25, encode=lambda d, p, c: d.translate(_NIBSWAP_TABLE),
          category="bit", help="每个字节高低 4 位互换")
def _nibswap(data, params, ctx):
    return data.translate(_NIBSWAP_TABLE)


@register("not", detect=lambda d, c: 0.25, encode=lambda d, p, c: d.translate(_NOT_TABLE),
          category="bit", help="按位取反")
def _not(data, params, ctx):
    return data.translate(_NOT_TABLE)


def _swap_endian(data: bytes, width: int) -> bytes:
    n = len(data) - len(data) % width
    out = bytearray()
    for i in range(0, n, width):
        out += data[i:i + width][::-1]
    return bytes(out) + data[n:]


@register("endian16", detect=lambda d, c: 0.2, encode=lambda d, p, c: _swap_endian(d, 2),
          category="bit", help="16 位字节序翻转")
def _endian16(data, params, ctx):
    return _swap_endian(data, 2)


@register("endian32", detect=lambda d, c: 0.2, encode=lambda d, p, c: _swap_endian(d, 4),
          category="bit", help="32 位字节序翻转")
def _endian32(data, params, ctx):
    return _swap_endian(data, 4)


@register("endian64", detect=lambda d, c: 0.2, encode=lambda d, p, c: _swap_endian(d, 8),
          category="bit", help="64 位字节序翻转")
def _endian64(data, params, ctx):
    return _swap_endian(data, 8)


_MAGIC_BYTES = [
    b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"PK\x03\x04", b"GIF89a", b"GIF87a", b"\x1f\x8b\x08",
    b"%PDF-", b"\x7fELF", b"MZ", b"BM", b"RIFF", b"SQLite format 3\x00", b"BZh9",
    b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07\x00",
]


def xor_key_guesses(data: bytes, limit: int = 8) -> List[int]:
    """用已知文件头反推单字节 XOR 常量（比无脑 256 次枚举高效得多）。"""
    out: List[int] = []
    head = data[:16]
    for magic in _MAGIC_BYTES:
        if len(head) < min(len(magic), 4):
            continue
        for size in (min(len(magic), 8), 4, 3, 2):
            if len(head) < size:
                continue
            guess = {head[i] ^ magic[i] for i in range(size)}
            if len(guess) == 1:
                v = guess.pop()
                if 0 <= v <= 255 and v not in out:
                    out.append(v)
    return out[:limit]


_COMMON_XOR = [0x00, 0x01, 0x0A, 0x0D, 0x13, 0x20, 0x37, 0x41, 0x42, 0x55, 0x5A, 0x5F,
               0x63, 0x66, 0x69, 0x72, 0x7F, 0x80, 0xAA, 0xAB, 0xCC, 0xDD, 0xDE, 0xEF,
               0xF0, 0xFF]


def _xor_params(data: bytes, ctx: Ctx) -> List[Dict[str, Any]]:
    vals: List[int] = list(xor_key_guesses(data))
    for v in _COMMON_XOR:
        if v not in vals:
            vals.append(v)
    if ctx.deep:
        vals = list(range(256))
    return [{"value": v} for v in vals]


@register("xor", category="xor", detect=lambda d, c: 0.45, params=_xor_params,
          encode=lambda d, p, c: bytes(b ^ p.get("value", 0) for b in d),
          help="单字节 XOR（会先用文件头反推常量）")
def _xor(data, params, ctx):
    v = params.get("value", 0)
    return bytes(b ^ v for b in data)


def _repeat_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _xor_repeat_params(data: bytes, ctx: Ctx) -> List[Dict[str, Any]]:
    """重复密钥 XOR 只认真实密钥来源。

    注意：这里**故意不用文件头 magic 反推密钥**——那样会让输出必然以该 magic 开头，
    等于用评分标准本身造答案（假 PNG/假 SQLite 会刷屏，把正确分支挤掉）。
    """
    out: List[Dict[str, Any]] = []
    for k in list(ctx.keys) + list(ctx.keystreams):
        if k and 1 <= len(k) <= 64 and k not in [p["key"] for p in out]:
            out.append({"key": k})
    return out[:32]


@register("xorrepeat", category="xor", detect=lambda d, c: 0.4, params=_xor_repeat_params,
          encode=lambda d, p, c: _repeat_xor(d, p.get("key", b"")),
          help="重复密钥 XOR")
def _xorrepeat(data, params, ctx):
    return _repeat_xor(data, params.get("key", b""))


@register("add", category="bit", detect=lambda d, c: 0.2,
          params=lambda d, c: [{"value": v} for v in range(256)] if c.deep else
          [{"value": v} for v in (1, 2, 3, 5, 7, 0x10, 0x20, 0x30, 0x40, 0x80, 0xFF)],
          help="每个字节减去常量（加解密的逆）")
def _add(data, params, ctx):
    v = params.get("value", 0)
    return bytes((b - v) & 0xFF for b in data)


@register("rol", category="bit", detect=lambda d, c: 0.2,
          params=lambda d, c: [{"value": n} for n in range(1, 8)] if c.deep else
          [{"value": n} for n in (1, 2, 3, 4, 5, 6, 7)],
          help="循环左移 n 位（解码=循环右移）")
def _rol(data, params, ctx):
    n = params.get("value", 1) % 8
    out = bytearray()
    for b in data:
        out.append(((b >> n) | (b << (8 - n))) & 0xFF)
    return bytes(out)


@register("ror", category="bit", detect=lambda d, c: 0.2,
          params=lambda d, c: [{"value": n} for n in range(1, 8)],
          help="循环右移 n 位（解码=循环左移）")
def _ror(data, params, ctx):
    n = params.get("value", 1) % 8
    out = bytearray()
    for b in data:
        out.append(((b << n) | (b >> (8 - n))) & 0xFF)
    return bytes(out)


@register("delta", category="xor", detect=lambda d, c: 0.3, encode=None,
          help="相邻字节累加异或的逆（b[i] ^= b[i-1]）")
def _delta(data, params, ctx):
    if not data:
        return data
    out = bytearray(data)
    for i in range(1, len(out)):
        out[i] ^= out[i - 1]
    return bytes(out)


# --------------------------------------------------------------------------
# 编码
# --------------------------------------------------------------------------

@register("hex", category="encoding", detect=lambda d, c: _detect_hex(d),
          params=lambda d, c: [{}], encode=lambda d, p, c: binascii.hexlify(d),
          help="十六进制文本")
def _hex(data, params, ctx):
    text = re.sub(rb"[\s:]", b"", data)
    text = re.sub(rb"^0x", b"", text)
    if len(text) % 2:
        text = text[:-1]
    if not text or not re.fullmatch(rb"[0-9a-fA-F]+", text):
        raise ValueError("不是合法 hex")
    return binascii.unhexlify(text)


def _detect_hex(data: bytes) -> float:
    text = re.sub(rb"[\s:]", b"", data[:4096])
    if len(text) < 6:
        return 0.0
    if re.fullmatch(rb"[0-9a-fA-F]+", text):
        return 0.85
    return 0.0


@register("b64", category="encoding", detect=lambda d, c: _detect_b64(d),
          params=lambda d, c: [{"alphabet": "base64"}] if not c.deep else
          [{"alphabet": "base64"}, {"alphabet": "base64url"}],
          encode=lambda d, p, c: _b64.b64encode(d), help="标准 Base64")
def _b64_decode(data, params, ctx):
    text = re.sub(rb"[\s]", b"", data)
    if params.get("alphabet") == "base64url":
        text = text.replace(b"-", b"+").replace(b"_", b"/")
    pad = (-len(text)) % 4
    return _b64.b64decode(text + b"=" * pad, validate=False)


def _detect_b64(data: bytes) -> float:
    text = re.sub(rb"[\s]", b"", data[:4096])
    if len(text) < 8:
        return 0.0
    chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if set(text) <= chars:
        return 0.55
    chars_url = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
    if set(text) <= chars_url:
        return 0.5
    return 0.0


def _b64solve_params(data: bytes, ctx: Ctx) -> List[Dict[str, Any]]:
    out = [{"table": t} for t in ctx.tables.values()]
    out.append({})
    return out


@register("b64solve", category="encoding", detect=lambda d, c: _detect_custom_b64(d),
          params=_b64solve_params, help="字符表被打乱的 Base64（自动解表）")
def _b64solve(data, params, ctx):
    table = params.get("table")
    if table:
        custom = bytes(table)
        mapping = {custom[v]: v for v in range(len(custom))}
        return alphabets.decode_with_mapping(data, mapping, alphabets.alphabet_from_charset(custom))
    # 快速通道：先用标准字符表试解；只有解出来的东西确实像样才走这条
    # （字符表被打乱时，标准解码不会报错，只会得到垃圾——不能盲信）
    text = re.sub(rb"[\s]", b"", data)
    try:
        std = _b64.b64decode(text + b"=" * ((-len(text)) % 4), validate=True)
        verdicts = oracles.evaluate(std)
        if verdicts and verdicts[0].score >= 0.5:
            return std
    except Exception:
        pass
    if not ctx.allow("b64solve", 3):
        raise ValueError("b64solve 调用预算已用完")
    known = list(ctx.known_spans)
    if not known:
        magic = alphabets.FORMAT_MAGIC.get(alphabets.normalize_format(ctx.fmt), b"")
        if magic:
            known = [(0, magic)]
    if not known and not ctx.tables:
        raise ValueError("没有已知明文也没有结构提示，解表无从下手（可用 --fmt/--pair 提供）")
    ref = alphabets.reference_segments(ctx.fmt, ctx.reference) \
        if alphabets.normalize_format(ctx.fmt) == "jpeg" else None
    streams = [alphabets.Stream("data", data, fmt=ctx.fmt or "",
                                known_spans=known,
                                oracle=lambda b, p: oracles.best(b, partial=p),
                                ref_segments=ref,
                                ref_spans=alphabets.reference_spans(ref))]
    solver = alphabets.TableSolver(streams, log=ctx.log, require_success=True, time_budget=6.0)
    sols = solver.run()
    if not sols:
        raise ValueError("字符表求解失败")
    ctx.tables[sols[0].table().decode("latin-1")] = sols[0].table()
    return sols[0].plaintexts["data"]


def _detect_custom_b64(data: bytes) -> float:
    text = re.sub(rb"[\s]", b"", data)
    if len(text) < 24 or len(text) % 4:
        return 0.0
    guesses = alphabets.detect_alphabets(data)
    for g in guesses:
        if g.alphabet.bits == 6 and not g.outside:
            seen = set(text) - set(g.alphabet.padding)
            if len(seen) >= 40:
                return 0.9
            if len(seen) >= 20:
                return 0.6
    return 0.0


@register("b32", category="encoding", detect=lambda d, c: _detect_charset(d, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=", 0.8),
          encode=lambda d, p, c: _b64.b32encode(d), help="Base32")
def _b32(data, params, ctx):
    text = re.sub(rb"[\s]", b"", data).upper()
    pad = (-len(text)) % 8
    return _b64.b32decode(text + b"=" * pad)


@register("b32hex", category="encoding",
          detect=lambda d, c: _detect_charset(d, b"0123456789ABCDEFGHIJKLMNOPQRSTUV=", 0.7),
          encode=lambda d, p, c: _b64.b32hexencode(d), help="Base32hex")
def _b32hex(data, params, ctx):
    text = re.sub(rb"[\s]", b"", data).upper()
    pad = (-len(text)) % 8
    return _b64.b32hexdecode(text + b"=" * pad)


def _detect_charset(data: bytes, charset: bytes, score: float) -> float:
    text = re.sub(rb"[\s]", b"", data[:2048])
    if len(text) < 8:
        return 0.0
    return score if set(text) <= set(charset) else 0.0


_B58_BTC = alphabets.alphabet_by_name("base58btc").chars
_B58_FLICKR = alphabets.alphabet_by_name("base58flickr").chars


def _b58_decode(data: bytes, chars: bytes) -> bytes:
    text = re.sub(rb"[\s]", b"", data)
    num = 0
    for ch in text:
        idx = chars.find(bytes([ch]))
        if idx < 0:
            raise ValueError("非法 base58 字符")
        num = num * 58 + idx
    out = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = 0
    for ch in text:
        if ch == chars[0]:
            pad += 1
        else:
            break
    return b"\x00" * pad + out


@register("b58", category="encoding",
          detect=lambda d, c: _detect_charset(d, _B58_BTC, 0.75) or _detect_charset(d, _B58_FLICKR, 0.7),
          params=lambda d, c: [{"alphabet": "base58btc"}, {"alphabet": "base58flickr"}],
          help="Base58")
def _b58(data, params, ctx):
    chars = _B58_FLICKR if params.get("alphabet") == "base58flickr" else _B58_BTC
    return _b58_decode(data, chars)


@register("b85", category="encoding", detect=lambda d, c: _detect_b85(d),
          params=lambda d, c: [{"variant": "ascii85"}, {"variant": "base85"}],
          help="Ascii85 / Base85")
def _b85(data, params, ctx):
    text = re.sub(rb"[\s]", b"", data)
    if params.get("variant") == "base85":
        return _b64.b85decode(text)
    return _b64.a85decode(text, adobe=False)


def _detect_b85(data: bytes) -> float:
    text = re.sub(rb"[\s]", b"", data[:2048])
    if len(text) < 8:
        return 0.0
    if text.startswith(b"<~"):
        return 0.85
    if set(text) <= set(bytes(range(0x21, 0x76))):
        return 0.35
    return 0.0


@register("a85adobe", category="encoding", detect=lambda d, c: 0.9 if d[:2] == b"<~" else 0.0,
          help="Adobe Ascii85（<~ ~> 包裹）")
def _a85adobe(data, params, ctx):
    return _b64.a85decode(data, adobe=True)


@register("uu", category="encoding", detect=lambda d, c: 0.8 if d[:11] == b"begin " or d[:6] == b"begin " else 0.0,
          help="uuencode")
def _uu(data, params, ctx):
    import binascii as _b
    return _b.a2b_uu(b"\n".join(data.splitlines()[1:-1]))


@register("url", category="encoding", detect=lambda d, c: 0.7 if b"%" in d[:512] else 0.0,
          encode=lambda d, p, c: urllib.parse.quote_from_bytes(d, safe="").encode(),
          help="URL 百分号编码")
def _url(data, params, ctx):
    return urllib.parse.unquote_to_bytes(data.decode("latin-1"))


@register("html", category="encoding",
          detect=lambda d, c: 0.7 if b"&#" in d[:1024] or b"&amp;" in d[:1024] else 0.0,
          encode=lambda d, p, c: html.escape(d.decode("latin-1")).encode(),
          help="HTML 实体")
def _html(data, params, ctx):
    return html.unescape(data.decode("latin-1")).encode("latin-1")


@register("unicode", category="encoding",
          detect=lambda d, c: 0.75 if re.search(rb"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", d[:1024]) else 0.0,
          help=r"\uXXXX / \xNN 转义")
def _unicode(data, params, ctx):
    return codecs.decode(data, "unicode_escape").encode("latin-1")


@register("qp", category="encoding",
          detect=lambda d, c: 0.7 if re.search(rb"=[0-9A-F]{2}", d[:1024]) else 0.0,
          encode=lambda d, p, c: binascii.b2a_qp(d), help="Quoted-Printable")
def _qp(data, params, ctx):
    return binascii.a2b_qp(data)


@register("dec", category="encoding", detect=lambda d, c: _detect_digits(d, 3),
          params=lambda d, c: [{"width": 3, "sep": True}, {"width": 3, "sep": False}]
          if not _has_sep(d) else [{"width": 3, "sep": True}, {"width": 3, "sep": False}],
          help="十进制度数（'102 108' 或定宽 3 位）")
def _dec(data, params, ctx):
    text = data.decode("latin-1").strip()
    width = int(params.get("width", 3))
    if params.get("sep", True) and re.search(r"[\s,;]", text):
        parts = [p for p in re.split(r"[\s,;]+", text) if p.isdigit()]
        return bytes(int(p) & 0xFF for p in parts)
    digits = re.sub(r"\D", "", text)
    groups = [digits[i:i + width] for i in range(0, len(digits) - width + 1, width)]
    return bytes(int(g) & 0xFF for g in groups if int(g) < 256)


def _has_sep(data: bytes) -> bool:
    return bool(re.search(rb"[\s,;]", data[:2048]))


def _detect_digits(data: bytes, width: int) -> float:
    text = data[:2048].decode("latin-1").strip()
    if len(text) < 6:
        return 0.0
    if re.fullmatch(r"[\d\s,;]+", text):
        return 0.6
    return 0.0


@register("bin", category="encoding", detect=lambda d, c: _detect_bin(d),
          params=lambda d, c: [{"width": 8}], help="二进制 01 串")
def _bin(data, params, ctx):
    text = re.sub(rb"[^01]", b"", data)
    n = len(text) - len(text) % 8
    return bytes(int(text[i:i + 8], 2) for i in range(0, n, 8))


def _detect_bin(data: bytes) -> float:
    text = re.sub(rb"[^01]", b"", data[:512])
    if len(text) < 16:
        return 0.0
    raw = data[:512].strip()
    return 0.7 if text and len(text) / max(1, len(raw)) > 0.9 else 0.0


@register("oct", category="encoding", detect=lambda d, c: _detect_oct(d),
          params=lambda d, c: [{"width": 3}], help="八进制")
def _oct(data, params, ctx):
    text = re.sub(r"\D", "", data.decode("latin-1"))
    groups = [text[i:i + 3] for i in range(0, len(text) - 2, 3)]
    return bytes(int(g, 8) & 0xFF for g in groups)


def _detect_oct(data: bytes) -> float:
    text = re.sub(rb"[\s,;]", b"", data[:2048])
    if len(text) < 6:
        return 0.0
    return 0.6 if re.fullmatch(rb"[0-7]+", text) else 0.0


_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G",
    "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N",
    "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U",
    "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5",
    "-....": "6", "--...": "7", "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", "-.-.--": "!", "-..-.": "/",
}


@register("morse", category="classic",
          detect=lambda d, c: 0.8 if re.fullmatch(rb"[.\-/\s]+", d[:512]) and b"." in d[:512] else 0.0,
          help="摩尔斯电码")
def _morse(data, params, ctx):
    text = data.decode("latin-1").strip()
    out = []
    for word in re.split(r"\s*/\s*|\s{3,}", text):
        for code in word.split():
            out.append(_MORSE.get(code, "?"))
        out.append(" ")
    return "".join(out).strip().encode("latin-1")


@register("bacon", category="classic",
          detect=lambda d, c: 0.7 if set(re.sub(rb"[\s]", b"", d[:512]).upper()) <= set(b"AB") else 0.0,
          help="培根密码（A/B 两种字形）")
def _bacon(data, params, ctx):
    text = re.sub(rb"[\s]", b"", data).upper()
    out = bytearray()
    for i in range(0, len(text) - 4, 5):
        v = 0
        for ch in text[i:i + 5]:
            v = (v << 1) | (0 if ch == ord("A") else 1)
        out.append(ord("A") + v)
    return bytes(out)


@register("rot13", category="classic", detect=lambda d, c: 0.4,
          encode=lambda d, p, c: codecs.encode(d.decode("latin-1"), "rot13").encode(),
          help="ROT13")
def _rot13(data, params, ctx):
    return codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1")


@register("rot47", category="classic", detect=lambda d, c: 0.4, help="ROT47")
def _rot47(data, params, ctx):
    return bytes(33 + ((b - 33 + 47) % 94) if 33 <= b <= 126 else b for b in data)


@register("caesar", category="classic", detect=lambda d, c: 0.35,
          params=lambda d, c: [{"shift": n} for n in range(1, 26)] if c.deep else
          [{"shift": n} for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 25, 24, 23)],
          help="凯撒位移")
def _caesar(data, params, ctx):
    shift = int(params.get("shift", 0)) % 26
    out = bytearray()
    for b in data:
        if 65 <= b <= 90:
            out.append((b - 65 - shift) % 26 + 65)
        elif 97 <= b <= 122:
            out.append((b - 97 - shift) % 26 + 97)
        else:
            out.append(b)
    return bytes(out)


@register("atbash", category="classic", detect=lambda d, c: 0.3,
          encode=lambda d, p, c: bytes(
              155 - b if 65 <= b <= 90 else (219 - b if 97 <= b <= 122 else b) for b in d),
          help="Atbash 字母表反转")
def _atbash(data, params, ctx):
    return bytes(155 - b if 65 <= b <= 90 else (219 - b if 97 <= b <= 122 else b) for b in data)


@register("utf16", category="encoding", detect=lambda d, c: 0.5 if len(d) > 4 and len(d) % 2 == 0 and
          sum(1 for i in range(0, min(len(d), 200), 2) if d[i] == 0) > 20 else 0.0,
          params=lambda d, c: [{"endian": "little"}, {"endian": "big"}], help="UTF-16")
def _utf16(data, params, ctx):
    enc = "utf-16-le" if params.get("endian", "little") == "little" else "utf-16-be"
    return data.decode(enc, errors="ignore").encode("utf-8", errors="ignore")


@register("gbk", category="encoding", detect=lambda d, c: 0.3,
          params=lambda d, c: [{"codec": "gbk"}, {"codec": "big5"}, {"codec": "latin-1"}],
          help="GBK/Big5 等编码转换")
def _gbk(data, params, ctx):
    return data.decode(params.get("codec", "gbk"), errors="strict").encode("utf-8")


# --------------------------------------------------------------------------
# 压缩
# --------------------------------------------------------------------------

@register("zlib", category="compress",
          detect=lambda d, c: 0.9 if (len(d) > 2 and d[0] == 0x78 and d[1] in (0x01, 0x5E, 0x9C, 0xDA))
          else _try_decompress(d, lambda x: zlib.decompress(x)),
          encode=lambda d, p, c: zlib.compress(d), help="zlib 解压")
def _zlib(data, params, ctx):
    return zlib.decompress(data)


@register("rawdeflate", category="compress",
          detect=lambda d, c: _try_decompress(d, lambda x: zlib.decompressobj(-15).decompress(x)),
          encode=lambda d, p, c: zlib.compressobj(-1, zlib.DEFLATED, -15).compress(d) +
          zlib.compressobj(-1, zlib.DEFLATED, -15).flush(),
          help="裸 deflate 解压")
def _rawdeflate(data, params, ctx):
    out = zlib.decompressobj(-15).decompress(data)
    if not out:
        raise ValueError("deflate 解压无输出")
    return out


@register("gzip", category="compress", detect=lambda d, c: 0.95 if d[:3] == b"\x1f\x8b\x08" else 0.0,
          encode=lambda d, p, c: gzip.compress(d), help="gzip 解压")
def _gzip(data, params, ctx):
    return gzip.decompress(data)


@register("bz2", category="compress", detect=lambda d, c: 0.95 if d[:3] == b"BZh" else 0.0,
          encode=lambda d, p, c: bz2.compress(d), help="bzip2 解压")
def _bz2(data, params, ctx):
    return bz2.decompress(data)


@register("lzma", category="compress",
          detect=lambda d, c: 0.95 if d[:6] == b"\xfd7zXZ\x00" else
          _try_decompress(d, lambda x: lzma.decompress(x, format=lzma.FORMAT_ALONE)),
          encode=lambda d, p, c: lzma.compress(d), help="LZMA/XZ 解压")
def _lzma(data, params, ctx):
    for fmt in (lzma.FORMAT_AUTO, lzma.FORMAT_ALONE, lzma.FORMAT_XZ):
        try:
            return lzma.decompress(data, format=fmt)
        except Exception:
            continue
    raise ValueError("lzma 解压失败")


def _try_decompress(data: bytes, fn: Callable[[bytes], bytes]) -> float:
    if len(data) < 16 or len(data) > 8 << 20:
        return 0.0
    try:
        out = fn(data[: min(len(data), 1 << 20)])
    except Exception:
        return 0.0
    return 0.7 if out else 0.0


# --------------------------------------------------------------------------
# 加密算法
# --------------------------------------------------------------------------

def _rc4_params(data: bytes, ctx: Ctx) -> List[Dict[str, Any]]:
    out = []
    for k in ctx.key_list():
        out.append({"key": k, "mask": 0, "p1": 0, "p2": 0})
    if ctx.deep:
        for k in ctx.key_list():
            for c1 in range(256):
                for c2 in range(256):
                    out.append({"key": k, "mask": 1, "p1": c1, "p2": c2})
    else:
        for k in ctx.key_list():
            for c1 in _COMMON_XOR:
                out.append({"key": k, "mask": 1, "p1": c1, "p2": 0x37})
    return out


@register("rc4", category="cipher", detect=lambda d, c: 0.4 if c.keys else 0.25,
          params=_rc4_params, help="RC4（标准）")
def _rc4(data, params, ctx):
    return ciphers.rc4(data, params.get("key", b""), mask_id=int(params.get("mask", 0)),
                       p1=int(params.get("p1", 0)), p2=int(params.get("p2", 0)),
                       ksa_id=int(params.get("ksa", 0)), drop=int(params.get("drop", 0)))


def _rc4v_params(data: bytes, ctx: Ctx) -> List[Dict[str, Any]]:
    """改造版 RC4：枚举掩码公式 + 常量，用密钥候选。"""
    out: List[Dict[str, Any]] = []
    keys = [k for k in ctx.key_list() if k]
    for k in keys:
        for mask in range(10):
            if mask == 0:
                out.append({"key": k, "mask": 0})
                continue
            out.append({"key": k, "mask": mask, "p1": 0x72, "p2": 0x37})
            out.append({"key": k, "mask": mask, "p1": 0, "p2": 0})
            if ctx.deep:
                for c1 in range(256):
                    out.append({"key": k, "mask": mask, "p1": c1, "p2": 0x37})
    return out


@register("rc4v", category="cipher", detect=lambda d, c: 0.35 if c.keys else 0.2,
          params=_rc4v_params, help="改造版 RC4（掩码公式/常量可枚举）")
def _rc4v(data, params, ctx):
    return ciphers.rc4(data, params.get("key", b""), mask_id=int(params.get("mask", 1)),
                       p1=int(params.get("p1", 0)), p2=int(params.get("p2", 0)),
                       ksa_id=int(params.get("ksa", 0)), drop=int(params.get("drop", 0)))


def _des_params(data: bytes, ctx: Ctx) -> List[Dict[str, Any]]:
    out = []
    for k in ctx.key_list():
        for tf in ctx.key_transforms:
            for mode in ("ecb",):
                out.append({"key": k, "transform": tf, "mode": mode})
    return out


@register("des", category="cipher", detect=lambda d, c: 0.45 if c.keys and len(d) % 8 == 0 else 0.2,
          params=_des_params, help="DES（ECB，含密钥位反转变体）")
def _des(data, params, ctx):
    if len(data) % 8:
        raise ValueError("DES 数据长度必须是 8 的倍数")
    return ciphers.des_crypt(data, params.get("key", b""), mode=params.get("mode", "ecb"),
                             transform=params.get("transform", "raw"))


@register("des3", category="cipher", detect=lambda d, c: 0.4 if c.keys and len(d) % 8 == 0 else 0.15,
          params=lambda d, c: [{"key": k, "transform": tf} for k in c.key_list()
                               for tf in c.key_transforms],
          help="3DES")
def _des3(data, params, ctx):
    if len(data) % 8:
        raise ValueError("3DES 数据长度必须是 8 的倍数")
    return ciphers.des3_crypt(data, params.get("key", b""), transform=params.get("transform", "raw"))


def _aes_params(data: bytes, ctx: Ctx) -> List[Dict[str, Any]]:
    out = []
    for k in ctx.key_list():
        for mode in ("ecb", "cbc", "ctr"):
            out.append({"key": k, "mode": mode, "iv": b"\x00" * 16})
    return out


@register("aes", category="cipher",
          detect=lambda d, c: 0.45 if c.keys and len(d) % 16 == 0 else 0.2,
          params=_aes_params, help="AES（ECB/CBC/CTR）")
def _aes(data, params, ctx):
    if len(data) % 16:
        raise ValueError("AES 数据长度必须是 16 的倍数")
    out = ciphers.aes_crypt(data, params.get("key", b""), mode=params.get("mode", "ecb"),
                            iv=params.get("iv", b"\x00" * 16))
    return ciphers.pkcs7_unpad(out)


@register("xtea", category="cipher", detect=lambda d, c: 0.35 if c.keys and len(d) % 8 == 0 else 0.15,
          params=lambda d, c: [{"key": k, "endian": e} for k in c.key_list()
                               for e in ("<", ">")], help="XTEA")
def _xtea(data, params, ctx):
    return ciphers.xtea_crypt(data, params.get("key", b""), endian=params.get("endian", "<"))


@register("xxtea", category="cipher", detect=lambda d, c: 0.35 if c.keys else 0.15,
          params=lambda d, c: [{"key": k, "endian": e} for k in c.key_list()
                               for e in ("<", ">")], help="XXTEA")
def _xxtea(data, params, ctx):
    return ciphers.xxtea_crypt(data, params.get("key", b""), endian=params.get("endian", "<"))


@register("tea", category="cipher", detect=lambda d, c: 0.3 if c.keys else 0.15,
          params=lambda d, c: [{"key": k, "endian": e} for k in c.key_list()
                               for e in ("<", ">")], help="TEA")
def _tea(data, params, ctx):
    return ciphers.tea_crypt(data, params.get("key", b""), endian=params.get("endian", "<"))


@register("chacha20", category="cipher", detect=lambda d, c: 0.35 if c.keys else 0.15,
          params=lambda d, c: [{"key": k} for k in c.key_list()], help="ChaCha20")
def _chacha20(data, params, ctx):
    from Crypto.Cipher import ChaCha20
    key = (params.get("key", b"") + b"\x00" * 32)[:32]
    return ChaCha20.new(key=key, nonce=b"\x00" * 8).decrypt(data)


@register("salsa20", category="cipher", detect=lambda d, c: 0.3 if c.keys else 0.15,
          params=lambda d, c: [{"key": k} for k in c.key_list()], help="Salsa20")
def _salsa20(data, params, ctx):
    from Crypto.Cipher import Salsa20
    key = (params.get("key", b"") + b"\x00" * 32)[:32]
    return Salsa20.new(key=key, nonce=b"\x00" * 8).decrypt(data)


@register("mt19937", category="prng", detect=lambda d, c: 0.2,
          params=lambda d, c: [{"seed": s} for s in (0, 1, 12345, 2024, 2025, 2026, 0xDEADBEEF)]
          if not c.deep else [{"seed": s} for s in range(0, 4096)],
          help="MT19937 密钥流异或")
def _mt19937(data, params, ctx):
    ks = ciphers.mt19937_keystream(int(params.get("seed", 0)), len(data))
    return ciphers.apply_keystream(data, ks)


@register("lcg", category="prng", detect=lambda d, c: 0.15,
          params=lambda d, c: [{"seed": s, "a": 1103515245, "c": 12345, "m": 1 << 31}
                               for s in (0, 1, 12345, 2024, 2025, 2026)],
          help="LCG 密钥流异或")
def _lcg(data, params, ctx):
    ks = ciphers.lcg_keystream(int(params.get("seed", 0)), len(data), int(params.get("a", 1103515245)),
                               int(params.get("c", 12345)), int(params.get("m", 1 << 31)),
                               width=int(params.get("width", 1)))
    return ciphers.apply_keystream(data, ks)


@register("keystream", category="cipher",
          detect=lambda d, c: 0.6 if (c.keystreams or c.keys) else 0.1,
          params=lambda d, c: [{"key": k} for k in (c.keystreams or c.key_list())],
          help="用已恢复的密钥流异或（明文/密文对照得来，可复用到同密钥的其它文件）")
def _keystream(data, params, ctx):
    return ciphers.apply_keystream(data, params.get("key", b""))


def _looks_like_ciphertext(data: bytes) -> bool:
    """判断"像不像被流加密打过的数据"：高熵、不像文本、没有已知文件头。"""
    if len(data) < 24:
        return False
    head = data[:16]
    for magic, _score, _name in oracles._MAGICS:
        if magic and head.startswith(magic):
            return False
    probe = data[:512]
    if oracles.entropy(probe) < 6.5:
        return False
    printable = 1.0 - len(probe.translate(None, oracles._ALLOWED_TEXT)) / len(probe)
    return printable < 0.9


@register("rc4family", category="cipher",
          detect=lambda d, c: 0.6 if (c.keys and _looks_like_ciphertext(d)) else 0.0,
          params=lambda d, c: [{"charset": "base64"}, {"charset": "printable"}],
          help="改造版 RC4 家族：用字符集约束自动试出掩码常量（0x72/0x37 之类）")
def _rc4family(data, params, ctx):
    from . import recover as _rec
    if not ctx.allow("rc4family", 6):          # 这个变换很贵，一次搜索最多试 6 次
        raise ValueError("rc4family 调用预算已用完")
    charset = str(params.get("charset", "base64"))
    allowed = _rec.charset_for(charset, None)
    # 只认真实密钥来源（命令行/文件/二进制里抓到的），不用默认占位密钥
    keys = [k for k in ctx.keys if len(k) >= 4][:8]
    if not keys:
        raise ValueError("没有真实密钥候选")
    hits = _rec.rc4_family_search(data, keys, allowed=allowed,
                                  check=_rec.charset_check_len(allowed), time_budget=3.0)
    if not hits:
        raise ValueError("没有找到匹配的 RC4 家族参数")
    best = hits[0]
    found = dict(best["params"])
    params.clear()
    params.update(found)
    params["charset"] = charset
    ctx.note("rc4family", f"  [rc4family] 命中掩码={found['mask']} p1={hex(found['p1'])} "
            f"p2={hex(found['p2'])} 密钥={found['key'][:24]!r}")
    return best["plain"]


@register("lenprefix", category="byte", detect=lambda d, c: 0.35 if len(d) > 8 else 0.1,
          params=lambda d, c: [{"size": 4, "endian": "little"}, {"size": 4, "endian": "big"},
                               {"size": 2, "endian": "little"}, {"size": 2, "endian": "big"}],
          help="去掉开头的长度前缀并按长度截断（很多恶意程序/自写格式会加）")
def _lenprefix(data, params, ctx):
    size = int(params.get("size", 4))
    if len(data) < size:
        raise ValueError("数据太短")
    length = int.from_bytes(data[:size], params.get("endian", "little"))
    if length <= 0 or length > len(data) - size:
        raise ValueError("长度字段不合理")
    return data[size:size + length]


@register("xormulti", category="xor",
          detect=lambda d, c: 0.6 if (len(d) >= 32 and _looks_like_ciphertext(d)) else 0.0,
          params=lambda d, c: [{"index": i} for i in range(3)],
          help="多字节 XOR 自动分析（等字符计数猜长度 + 频率/列质量猜密钥）")
def _xormulti(data, params, ctx):
    from . import xoranalysis as _xa
    results = _xa.auto_xor(data, max_length=32 if ctx.deep else 16)
    if not results:
        raise ValueError("没有解出可用的 XOR 候选")
    idx = min(int(params.get("index", 0)), len(results) - 1)
    best = results[idx]
    params.clear()
    params.update({"key": best.key, "length": best.key_length, "method": best.method})
    ctx.note("xormulti", f"  [xormulti] 密钥长度={best.key_length} 密钥={best.key!r}（{best.method}）")
    return best.plaintext


@register("basemagic", category="encoding",
          detect=lambda d, c: _detect_base_layer(d),
          params=lambda d, c: [{"index": i} for i in range(3)],
          help="递归多层 Base 解码（basecrack 的 magic 模式）")
def _basemagic(data, params, ctx):
    from . import baseN
    results = baseN.magic_decode(data, max_depth=8 if ctx.deep else 5)
    if not results:
        raise ValueError("没有可用的 Base 解码链")
    idx = min(int(params.get("index", 0)), len(results) - 1)
    best = results[idx]
    params.clear()
    params["chain"] = "->".join(best.chain)
    ctx.note("basemagic", f"  [basemagic] {' → '.join(best.chain)}")
    return best.data


def _detect_base_layer(data: bytes) -> float:
    from . import baseN
    text = re.sub(rb"[\s]", b"", data[:4096])
    if len(text) < 8:
        return 0.0
    for codec in baseN.CODECS:
        if codec.charset and set(text) <= set(codec.charset):
            return 0.5
    return 0.0


def _looks_like_classical_text(data: bytes) -> bool:
    from . import langscore
    if len(data) < 24 or len(data) > 200000:
        return False
    sample = data[:4096]
    if langscore.printable_ratio(sample) < 0.95:
        return False
    letters = sum(1 for b in sample if 65 <= b <= 90 or 97 <= b <= 122)
    if letters / len(sample) < 0.6:
        return False
    return langscore.score_bytes(sample).score < 0.35      # 还不像人话 → 值得破解


@register("classical", category="classic",
          detect=lambda d, c: 0.5 if _looks_like_classical_text(d) else 0.0,
          params=lambda d, c: [{"index": i} for i in range(3)],
          help="古典密码自动破解（凯撒/仿射/维吉尼亚/单表替换/栅栏）")
def _classical(data, params, ctx):
    from . import crack as _crack
    results = _crack.crack_all(data, deep=ctx.deep)
    if not results:
        raise ValueError("古典密码破解没有结果")
    idx = min(int(params.get("index", 0)), len(results) - 1)
    best = results[idx]
    params.clear()
    params["kind"] = best.kind
    params["found"] = best.params.replace(",", ";")
    ctx.note("classical", f"  [classical] {best.kind} {best.params}")
    return best.plaintext


def _register_base_codecs() -> None:
    """把 baseN 里的各种 base 注册成独立变换，让链式搜索也能直接用。"""
    from . import baseN
    existing = set(REGISTRY)
    for codec in baseN.CODECS:
        name = codec.name.replace("-", "").replace("_", "")
        if name in existing or name in ("base64", "base64url", "base32", "base32hex", "base16",
                                        "base85", "ascii85", "base64solve"):
            continue
        _register_codec_transform(codec, name)


def _register_codec_transform(codec, name: str) -> None:
    charset = bytes(codec.charset)

    def detect(data: bytes, ctx: Ctx, _charset=charset) -> float:
        text = re.sub(rb"[\s]", b"", data[:4096])
        if len(text) < 8 or not _charset:
            return 0.0
        return 0.65 if set(text) <= set(_charset) else 0.0

    def run(data: bytes, params: Dict[str, Any], ctx: Ctx, _codec=codec) -> bytes:
        out = _codec.decode(data)
        if not out:
            raise ValueError(f"{_codec.name} 解出空数据")
        return out

    def encode(data: bytes, params: Dict[str, Any], ctx: Ctx, _codec=codec) -> bytes:
        if _codec.encode is None:
            raise NotImplementedError
        return _codec.encode(data)

    register(name, detect=detect, params=lambda d, c: [{}], encode=encode,
             category="encoding", help=f"{codec.name} 解码")(run)


@register("a1z26", category="classic", detect=lambda d, c: 0.5 if re.fullmatch(
    rb"[\s,;\-]*(\d{1,2}[\s,;\-]+)+\d{1,2}[\s,;\-]*", d[:512]) else 0.0,
    help="A1Z26（数字 1-26 映射到字母）")
def _a1z26(data, params, ctx):
    nums = [int(n) for n in re.findall(rb"\d{1,2}", data)]
    if not nums or any(n < 1 or n > 26 for n in nums):
        raise ValueError("不是 A1Z26")
    return bytes(64 + n for n in nums)


@register("polybius", category="classic", detect=lambda d, c: 0.5 if re.fullmatch(
    rb"[\s]*[1-5]{2}([\s]+[1-5]{2})*[\s]*", d[:512]) else 0.0,
    help="波利比奥斯方阵（1-5 坐标）")
def _polybius(data, params, ctx):
    pairs = re.findall(rb"[1-5]{2}", data)
    if not pairs:
        raise ValueError("不是波利比奥斯坐标")
    table = "abcdefghikmnopqrstuvwxyz"      # 经典 5x5（i/j 合并）
    out = bytearray()
    for p in pairs:
        r, c = int(p[:1]) - 1, int(p[1:]) - 1
        out.append(ord(table[r * 5 + c]))
    return bytes(out)


@register("rot8000", category="classic", detect=lambda d, c: 0.2,
          help="ROT8000（Unicode 码点 +0x8000）")
def _rot8000(data, params, ctx):
    text = data.decode("utf-8", "ignore")
    return "".join(chr(ord(ch) ^ 0x8000) if ord(ch) > 0x1F else ch for ch in text).encode("utf-8")


@register("railfence", category="classic",
          detect=lambda d, c: 0.35 if _looks_like_classical_text(d) else 0.15,
          params=lambda d, c: [{"rails": n} for n in range(2, 9)],
          help="栅栏密码（按栏数解密）")
def _railfence(data, params, ctx):
    from . import crack as _crack
    rails = int(params.get("rails", 3))
    out = _crack.railfence_decrypt(data.decode("latin-1"), rails).encode("latin-1")
    return out


_register_base_codecs()


@register("substitute", category="byte", detect=lambda d, c: 0.4 if c.tables else 0.0,
          params=lambda d, c: [{"table": t} for t in c.tables.values()],
          help="整字节替换表（256 项）")
def _substitute(data, params, ctx):
    table = bytes(params.get("table", b""))
    if len(table) < 256:
        raise ValueError("替换表需要 256 项")
    return data.translate(table)


# --------------------------------------------------------------------------
# 逆变换（用于"重新加密复核"）
# --------------------------------------------------------------------------

def encode_recipe(data: bytes, steps: Sequence[Step], ctx: Optional[Ctx] = None) -> bytes:
    """按配方的**逆序**重新加密，用于验证解密结果。

    只有实现了 encode 的变换才能复核；遇到没有逆变换的步骤会抛异常。
    """
    ctx = ctx or Ctx()
    for step in reversed(list(steps)):
        data = get_transform(step.name).encode(data, dict(step.params), ctx)
    return data


def recipe_description(steps: Sequence[Step]) -> str:
    parts = []
    for s in steps:
        t = REGISTRY.get(s.name)
        parts.append(f"{s}（{t.help if t else '?'}）")
    return " → ".join(parts)
