"""Base 家族编解码 + 递归多层解码（basecrack 的 "magic mode" 思路）。

basecrack 的价值在于两点：

1. **支持一大票进制/字符表**（base16/32/32hex/32z/36/45/58/62/64/85/91/92/z85…），
   CTF 里换一种 base 就能卡住人；
2. **magic 模式递归解码**：Base64(Base32(Base16(…))) 这种嵌套自动剥完，
   同时要有护栏（不连续用同一种、结果太短就停、见过的不重复解）。

这里补齐了 base36/45/58/62/85/z85/91/32z/crockford，并把递归解码做成
"每步挑最可信的编码 + 语言/结构打分决定是否继续"。
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import langscore, oracles

# --------------------------------------------------------------------------
# 字符表
# --------------------------------------------------------------------------

B16 = b"0123456789abcdef"
B16U = b"0123456789ABCDEF"
B32 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B32HEX = b"0123456789ABCDEFGHIJKLMNOPQRSTUV"
B32Z = b"ybndrfg8ejkmcpqxot1uwisza345h769"
B32CROCKFORD = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
B36 = b"0123456789abcdefghijklmnopqrstuvwxyz"
B36U = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
B45 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
B58BTC = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58FLICKR = b"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
B58RIPPLE = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
B62 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B62ALT = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
Z85 = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
B91 = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
       b"!#$%&()*+,./:;<=>?@[]^_`{|}~\"")


class DecodeError(ValueError):
    pass


# --------------------------------------------------------------------------
# 大数型 base（base36/58/62）
# --------------------------------------------------------------------------

def _bigint_decode(text: bytes, chars: bytes, name: str) -> bytes:
    index = {c: i for i, c in enumerate(chars)}
    num = 0
    for ch in text:
        if ch not in index:
            raise DecodeError(f"{name}: 非法字符 {chr(ch)!r}")
        num = num * len(chars) + index[ch]
    out = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = 0
    for ch in text:
        if ch == chars[0]:
            pad += 1
        else:
            break
    return b"\x00" * pad + out


def _bigint_encode(data: bytes, chars: bytes) -> bytes:
    num = int.from_bytes(data, "big")
    if num == 0:
        out = chars[:1]
    else:
        buf = bytearray()
        while num:
            num, rem = divmod(num, len(chars))
            buf.append(chars[rem])
        out = bytes(reversed(buf))
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return chars[:1] * pad + out


def b36decode(text: bytes) -> bytes:
    return _bigint_decode(text.strip().lower(), B36, "base36")


def b58decode(text: bytes, alphabet: bytes = B58BTC) -> bytes:
    return _bigint_decode(text.strip(), alphabet, "base58")


def b62decode(text: bytes, alphabet: bytes = B62) -> bytes:
    return _bigint_decode(text.strip(), alphabet, "base62")


# --------------------------------------------------------------------------
# base45（RFC 9285）
# --------------------------------------------------------------------------

def b45decode(text: bytes) -> bytes:
    text = text.strip()
    index = {c: i for i, c in enumerate(B45)}
    values = []
    for ch in text:
        if ch not in index:
            raise DecodeError(f"base45: 非法字符 {chr(ch)!r}")
        values.append(index[ch])
    out = bytearray()
    i = 0
    while i < len(values):
        if i + 2 < len(values):
            v = values[i] + values[i + 1] * 45 + values[i + 2] * 45 * 45
            out += bytes([(v >> 8) & 0xFF, v & 0xFF])
            i += 3
        elif i + 1 < len(values):
            v = values[i] + values[i + 1] * 45
            if v > 255:
                raise DecodeError("base45: 尾部数值越界")
            out.append(v)
            i += 2
        else:
            raise DecodeError("base45: 长度非法")
    return bytes(out)


def b45encode(data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data) - 1, 2):
        v = data[i] * 256 + data[i + 1]
        out.append(B45[v % 45])
        out.append(B45[(v // 45) % 45])
        out.append(B45[v // (45 * 45)])
    if len(data) % 2:
        v = data[-1]
        out.append(B45[v % 45])
        out.append(B45[v // 45])
    return bytes(out)


# --------------------------------------------------------------------------
# 32 位字型 base（z85）
# --------------------------------------------------------------------------

def z85decode(text: bytes) -> bytes:
    text = text.strip()
    if len(text) % 5:
        raise DecodeError("z85: 长度必须是 5 的倍数")
    index = {c: i for i, c in enumerate(Z85)}
    out = bytearray()
    for i in range(0, len(text), 5):
        value = 0
        for ch in text[i:i + 5]:
            if ch not in index:
                raise DecodeError(f"z85: 非法字符 {chr(ch)!r}")
            value = value * 85 + index[ch]
        out += value.to_bytes(4, "big")
    return bytes(out)


def z85encode(data: bytes) -> bytes:
    out = bytearray()
    padded = data + b"\x00" * ((-len(data)) % 4)      # Z85 要求长度是 4 的倍数
    for i in range(0, len(padded), 4):
        value = int.from_bytes(padded[i:i + 4], "big")
        chunk = bytearray(5)
        for j in range(4, -1, -1):
            value, rem = divmod(value, 85)
            chunk[j] = Z85[rem]
        out += chunk
    return bytes(out)


# --------------------------------------------------------------------------
# base91（13 位分组，按参考实现）
# --------------------------------------------------------------------------

def b91decode(text: bytes) -> bytes:
    index = {c: i for i, c in enumerate(B91)}
    out = bytearray()
    value = -1
    queue = 0
    bits = 0
    for ch in text:
        if ch not in index:
            raise DecodeError(f"base91: 非法字符 {chr(ch)!r}")
        c = index[ch]
        if value < 0:
            value = c
        else:
            value += c * 91
            queue |= value << bits
            bits += 13 if (value & 8191) > 88 else 14
            while True:
                out.append(queue & 0xFF)
                queue >>= 8
                bits -= 8
                if bits <= 7:
                    break
            value = -1
    if value + 1:
        out.append((queue | value << bits) & 0xFF)
    return bytes(out)


def b91encode(data: bytes) -> bytes:
    out = bytearray()
    queue = 0
    bits = 0
    for byte in data:
        queue |= byte << bits
        bits += 8
        if bits > 13:
            value = queue & 8191
            if value > 88:
                queue >>= 13
                bits -= 13
            else:
                value = queue & 16383
                queue >>= 14
                bits -= 14
            out.append(B91[value % 91])
            out.append(B91[value // 91])
    if bits:
        out.append(B91[queue % 91])
        if bits > 7 or queue > 90:
            out.append(B91[queue // 91])
    return bytes(out)


# --------------------------------------------------------------------------
# base32 变体 / 其它
# --------------------------------------------------------------------------

def _bitstream_decode(data: bytes, chars: bytes, bits_per: int, name: str) -> bytes:
    index = {c: i for i, c in enumerate(chars)}
    acc = 0
    nbits = 0
    out = bytearray()
    for ch in data:
        if ch in (0x3D, 0x20, 0x0A, 0x0D):        # = 与空白
            continue
        if ch not in index:
            raise DecodeError(f"{name}: 非法字符 {chr(ch)!r}")
        acc = (acc << bits_per) | index[ch]
        nbits += bits_per
        while nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
    return bytes(out)


def _bitstream_encode(data: bytes, chars: bytes, bits_per: int) -> bytes:
    acc = 0
    nbits = 0
    out = bytearray()
    for b in data:
        acc = (acc << 8) | b
        nbits += 8
        while nbits >= bits_per:
            nbits -= bits_per
            out.append(chars[(acc >> nbits) & ((1 << bits_per) - 1)])
    if nbits:
        out.append(chars[(acc << (bits_per - nbits)) & ((1 << bits_per) - 1)])
    return bytes(out)


def b32decode(text: bytes, chars: bytes = B32) -> bytes:
    cleaned = re.sub(rb"[\s=]", b"", text)
    cleaned = cleaned.lower() if chars is B32Z else cleaned.upper()
    return _bitstream_decode(cleaned, chars, 5, "base32")


def b32zdecode(text: bytes) -> bytes:
    return _bitstream_decode(text.strip().lower(), B32Z, 5, "z-base-32")


def b32crockford(text: bytes) -> bytes:
    cleaned = re.sub(rb"[\s-]", b"", text.strip().upper())
    return _bitstream_decode(cleaned, B32CROCKFORD, 5, "Crockford base32")


def b16decode(text: bytes) -> bytes:
    cleaned = re.sub(rb"[\s:]", b"", text.strip())
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    return binascii.unhexlify(cleaned)


@dataclass
class Codec:
    name: str
    decode: Callable[[bytes], bytes]
    encode: Optional[Callable[[bytes], bytes]] = None
    charset: bytes = b""
    bit_aligned: bool = False


CODECS: List[Codec] = [
    Codec("base64", lambda d: base64.b64decode(re.sub(rb"[\s]", b"", d) +
                                               b"=" * (-len(re.sub(rb"[\s]", b"", d)) % 4)),
          base64.b64encode,
          b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", True),
    Codec("base64url", lambda d: base64.urlsafe_b64decode(re.sub(rb"[\s]", b"", d) +
                                                          b"=" * (-len(re.sub(rb"[\s]", b"", d)) % 4)),
          base64.urlsafe_b64encode,
          b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=", True),
    Codec("base32", b32decode, lambda d: _bitstream_encode(d, B32, 5), B32 + b"=", True),
    Codec("base32hex", lambda d: b32decode(d, B32HEX),
          lambda d: _bitstream_encode(d, B32HEX, 5), B32HEX + b"=", True),
    Codec("z-base-32", b32zdecode, lambda d: _bitstream_encode(d, B32Z, 5), B32Z, True),
    Codec("base32crockford", b32crockford,
          lambda d: _bitstream_encode(d, B32CROCKFORD, 5), B32CROCKFORD, True),
    Codec("base16", b16decode, binascii.hexlify, B16 + B16U, True),
    Codec("base36", b36decode, lambda d: _bigint_encode(d, B36), B36 + B36U),
    Codec("base45", b45decode, b45encode, B45, True),
    Codec("base58btc", lambda d: b58decode(d, B58BTC), lambda d: _bigint_encode(d, B58BTC),
          B58BTC),
    Codec("base58flickr", lambda d: b58decode(d, B58FLICKR),
          lambda d: _bigint_encode(d, B58FLICKR), B58FLICKR),
    Codec("base58ripple", lambda d: b58decode(d, B58RIPPLE),
          lambda d: _bigint_encode(d, B58RIPPLE), B58RIPPLE),
    Codec("base62", lambda d: b62decode(d, B62), lambda d: _bigint_encode(d, B62), B62),
    Codec("base62alt", lambda d: b62decode(d, B62ALT), lambda d: _bigint_encode(d, B62ALT),
          B62ALT),
    Codec("base85", base64.b85decode, base64.b85encode),
    Codec("ascii85", lambda d: base64.a85decode(d, adobe=False), base64.a85encode),
    Codec("z85", z85decode, z85encode, Z85),
    Codec("base91", b91decode, b91encode, B91, True),
]

_BY_NAME: Dict[str, Codec] = {}
for _c in CODECS:
    _BY_NAME[_c.name] = _c
_BY_NAME["base32z"] = _BY_NAME["z-base-32"]
_BY_NAME["base58"] = _BY_NAME["base58btc"]
_BY_NAME["base85adobe"] = _BY_NAME["ascii85"]


def codec_by_name(name: str) -> Codec:
    key = name.lower().strip()
    if key not in _BY_NAME:
        raise KeyError(f"未知编码：{name}（可用：{', '.join(sorted(_BY_NAME))}）")
    return _BY_NAME[key]


def decode(text: bytes, name: str) -> bytes:
    return codec_by_name(name).decode(text)


def encode(data: bytes, name: str) -> bytes:
    codec = codec_by_name(name)
    if codec.encode is None:
        raise DecodeError(f"{name} 不支持反向编码")
    return codec.encode(data)


# --------------------------------------------------------------------------
# 递归多层解码（magic 模式）
# --------------------------------------------------------------------------

@dataclass
class MagicStep:
    codec: str
    output: bytes
    note: str = ""

    def __str__(self) -> str:
        return f"{self.codec} → {len(self.output)} 字节"


@dataclass
class MagicResult:
    chain: List[str] = field(default_factory=list)
    data: bytes = b""
    score: float = 0.0
    note: str = ""

    def line(self) -> str:
        preview = self.data[:64]
        try:
            text = preview.decode("utf-8").replace("\n", "\\n")
        except UnicodeDecodeError:
            text = preview.hex(" ")
        return f"{' → '.join(self.chain)}  [{self.score:.2f}] {text}"


def _plausible_intermediate(new: bytes) -> bool:
    """中间层"看起来不像人话"也可能还得继续剥（这正是多层解码的用途），
    但得给出一个继续往下走的理由，避免无意义地无限展开。"""
    if len(new) < 3:
        return False
    stripped = re.sub(rb"[\s]", b"", new)
    if len(stripped) >= 8:
        for codec in CODECS:
            if codec.charset and set(stripped) <= set(codec.charset):
                return True
    verdicts = oracles.evaluate(new)
    if verdicts and verdicts[0].score >= 0.85:
        return True
    if langscore.score_bytes(new).score >= 0.35:
        return True
    return langscore.printable_ratio(new) > 0.9


def magic_decode(text: bytes, max_depth: int = 8,
                 allow: Optional[Sequence[str]] = None,
                 node_budget: int = 300) -> List[MagicResult]:
    """递归剥掉多层编码，返回所有可能的链路（按最终得分排序）。"""
    results: List[MagicResult] = []
    codecs = [codec_by_name(n) for n in allow] if allow else CODECS
    state = {"nodes": 0}

    def walk(data: bytes, chain: List[str], seen: set, depth: int) -> None:
        if depth >= max_depth or state["nodes"] > node_budget:
            return
        for codec in codecs:
            if state["nodes"] > node_budget:
                return
            if chain and chain[-1] == codec.name:
                continue                       # 不连续用同一种（避免 ROT13→ROT13 之类死循环）
            stripped = re.sub(rb"[\s]", b"", data)
            if codec.charset and not set(stripped) <= set(codec.charset):
                continue
            state["nodes"] += 1
            try:
                out = codec.decode(data)
            except Exception:
                continue
            if not out or out == data or len(out) < 3:
                continue
            digest = hashlib_sha1(out)
            if digest in seen:
                continue
            score = langscore.score_bytes(out).score
            verdicts = oracles.evaluate(out)
            if verdicts:
                score = max(score, verdicts[0].score)
            new_chain = chain + [codec.name]
            results.append(MagicResult(new_chain, out, score))
            if _plausible_intermediate(out):
                walk(out, new_chain, seen | {digest}, depth + 1)

    walk(text, [], {hashlib_sha1(text)}, 0)
    results.sort(key=lambda r: (-r.score, len(r.chain)))
    return results


def hashlib_sha1(data: bytes) -> str:
    import hashlib
    return hashlib.sha1(data).hexdigest()


def magic_decode_best(text: bytes, max_depth: int = 8,
                      allow: Optional[Sequence[str]] = None) -> Optional[MagicResult]:
    results = magic_decode(text, max_depth, allow)
    return results[0] if results else None
