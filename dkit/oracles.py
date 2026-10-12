"""格式验证器（Oracle）——整套"一条龙"自动化的核心。

解密对不对不靠人眼判断，而靠结构校验：
magic、长度字段、CRC32、UTF-8 合法性、flag 正则……

每个 oracle 返回 0~1 的置信度：
    1.00  完全结构校验通过（CRC 全对 / 完整容器）
    0.85  以上视为"解对了"（SUCCESS_SCORE）
    0.50  前缀合法（用于搜索过程中的部分校验）
    0.00  不适用

设计要点
--------
* ``quick`` 先行廉价判断（magic 比较），避免搜索时大量无谓解析。
* 所有解析器都做边界检查，绝不抛异常（搜索会喂它任意垃圾数据）。
* ``partial=True`` 时允许数据被截断，用于"边解密边校验"的增量搜索。
"""

from __future__ import annotations

import bz2
import json
import lzma
import re
import struct
import zlib
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

SUCCESS_SCORE = 0.85
PREFIX_SCORE = 0.55


@dataclass(frozen=True)
class Verdict:
    score: float
    label: str
    detail: str = ""

    def __str__(self) -> str:
        text = f"{self.label} {self.score:.2f}"
        return f"{text} ({self.detail})" if self.detail else text


@dataclass
class Oracle:
    name: str
    check: Callable[[bytes, bool], Optional[Verdict]]
    quick: Callable[[bytes], bool]
    cost: int = 1
    partial_capable: bool = False


ORACLES: List[Oracle] = []
_BY_NAME = {}


def oracle(name: str, quick: Optional[Callable[[bytes], bool]] = None, cost: int = 1,
           partial_capable: bool = False):
    def deco(fn):
        o = Oracle(name, fn, quick or (lambda d: True), cost, partial_capable)
        ORACLES.append(o)
        _BY_NAME[name] = o
        return fn
    return deco


def get_oracle(name: str) -> Oracle:
    return _BY_NAME[name]


def oracle_names() -> List[str]:
    return [o.name for o in ORACLES]


def evaluate(data: bytes, partial: bool = False, only: Optional[Sequence[str]] = None,
             cap: int = 262144) -> List[Verdict]:
    """跑所有 oracle，按分数降序返回命中的结果。"""
    out: List[Verdict] = []
    if not data:
        return out
    sample = data[:cap] if cap and len(data) > cap else data
    for o in ORACLES:
        if only and o.name not in only:
            continue
        try:
            if not o.quick(sample):
                continue
            v = o.check(sample, partial)
        except Exception:
            v = None
        if v and v.score > 0:
            out.append(v)
    out.sort(key=lambda v: -v.score)
    return out


def best(data: bytes, partial: bool = False, cap: int = 262144) -> Verdict:
    vs = evaluate(data, partial=partial, cap=cap)
    return vs[0] if vs else Verdict(0.0, "unknown")


# --------------------------------------------------------------------------
# 廉价预打分：搜索时用来给候选排序，不做完整解析
# --------------------------------------------------------------------------

_MAGICS: Sequence[tuple] = (
    (b"\x89PNG\r\n\x1a\n", 0.95, "png"),
    (b"\xff\xd8\xff", 0.9, "jpeg"),
    (b"PK\x03\x04", 0.9, "zip"),
    (b"PK\x05\x06", 0.85, "zip"),
    (b"GIF87a", 0.9, "gif"),
    (b"GIF89a", 0.9, "gif"),
    (b"\x1f\x8b\x08", 0.9, "gzip"),
    (b"BZh", 0.85, "bzip2"),
    (b"\xfd7zXZ\x00", 0.9, "xz"),
    (b"%PDF-", 0.9, "pdf"),
    (b"\x7fELF", 0.9, "elf"),
    (b"MZ", 0.45, "pe"),
    (b"BM", 0.6, "bmp"),
    (b"II*\x00", 0.85, "tiff"),
    (b"MM\x00*", 0.85, "tiff"),
    (b"RIFF", 0.8, "riff"),
    (b"OggS", 0.85, "ogg"),
    (b"ID3", 0.8, "mp3"),
    (b"SQLite format 3\x00", 0.95, "sqlite"),
    (b"7z\xbc\xaf\x27\x1c", 0.9, "7z"),
    (b"Rar!\x1a\x07", 0.9, "rar"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0.9, "ole"),
    (b"WEBP", 0.0, "webp"),
    (b"ustar", 0.0, "tar"),
)

_FLAG_WORDS = (rb"flag|ctf|key|pass|pwd|secret|anser|answer|token|pico|htb|thm|xctf|dasctf|"
               rb"nssctf|iscc|hgame|moectf|n1ctf|actf|buuctf|root|admin|code|level")
_FLAG_RE = re.compile(rb"(?<![A-Za-z0-9_])(?:" + _FLAG_WORDS + rb")[{(\[][!-~]{3,120}[})\]]", re.I)
# 宽松规则只用来排序，不给满分：随机可打印数据里偶尔也会出现 xxx{yyy}
_FLAG_LOOSE_RE = re.compile(rb"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_]{2,20}[{(\[][!-~]{8,120}[})\]]")

_ALLOWED_TEXT = bytes(range(0x20, 0x7F)) + b"\t\n\r\f\b\x1b"


def quick_score(data: bytes) -> float:
    """不做完整解析的快速打分，用于搜索树的候选排序。"""
    if not data:
        return 0.0
    head = data[:16]
    s = 0.0
    for magic, score, _name in _MAGICS:
        if magic and head.startswith(magic) and score > s:
            s = score
    if len(data) > 16 and data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA):
        s = max(s, 0.9)                     # zlib 头（完整校验仍会在 evaluate 里做）
    if _FLAG_RE.search(data[:4096]):
        return 1.0
    if s == 0.0:
        sample = data[:2048]
        bad = len(sample.translate(None, _ALLOWED_TEXT))
        ratio = 1.0 - bad / len(sample)
        if ratio > 0.97:
            s = 0.55 + min(0.1, len(sample) / 40000)
    # 分组密码密文特征：长度是 8/16 的整数倍、字节分布很散
    # （这类中间结果本身"不像任何东西"，但极可能是正确路径上的一层；
    #   分数刻意给得比"可打印文本"低，只保证不被彻底丢掉）
    n = len(data)
    if n >= 32 and n % 8 == 0:
        probe = data[:512]
        distinct = len(set(probe)) / min(256, len(probe))
        if distinct > 0.8:
            s = max(s, 0.5 if n % 16 == 0 else 0.45)
    return s


# --------------------------------------------------------------------------
# 文本类
# --------------------------------------------------------------------------

@oracle("flag", quick=lambda d: b"{" in d[:8192] or b"}" in d[:8192], cost=1)
def _flag(data: bytes, partial: bool) -> Optional[Verdict]:
    m = _FLAG_RE.search(data)
    if m:
        return Verdict(1.0, "FLAG", m.group(0).decode("latin-1")[:120])
    m = _FLAG_LOOSE_RE.search(data)
    if m:
        # 必须整体像文本，否则不给高分（避免随机数据里的 xxx{yyy} 误报）
        sample = data[:65536]
        printable = 1.0 - len(sample.translate(None, _ALLOWED_TEXT)) / len(sample)
        if printable > 0.9:
            return Verdict(0.8, "FLAG?", m.group(0).decode("latin-1")[:120])
    return None


@oracle("lenprefix_flag", cost=2)
def _lenprefix_flag(data: bytes, partial: bool) -> Optional[Verdict]:
    """「长度前缀 + flag 文本」结构。

    这是逆问题里很常见的一种自写格式：前 4（或 2）字节是明文长度，
    后面紧跟 flag，再往后是零填充。有了这条判据，只要密钥对，
    解出来的东西立刻能自证——不需要知道 flag 长什么样。
    """
    for endian, size in (("<", 4), (">", 4), ("<", 2), (">", 2)):
        if len(data) < size + 6:
            continue
        length = int.from_bytes(data[:size], endian)
        if not (6 <= length <= len(data) - size):
            continue
        payload = data[size:size + length]
        if len(payload) < 6:
            continue
        bad = len(payload.translate(None, _ALLOWED_TEXT))
        if bad / len(payload) > 0.05:
            continue
        if not (_FLAG_RE.search(payload) or _FLAG_LOOSE_RE.search(payload)):
            continue
        return Verdict(0.95, "长度前缀+flag",
                       f"{'小端' if endian == '<' else '大端'}{size * 8} 位长度={length}")
    return None


@oracle("text", cost=1)
def _text(data: bytes, partial: bool) -> Optional[Verdict]:
    if len(data) < 8:
        return None
    sample = data[:65536]
    bad = len(sample.translate(None, _ALLOWED_TEXT))
    printable = 1.0 - bad / len(sample)
    try:
        text = data[:200000].decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None:
        cjk = sum(1 for ch in text[:20000] if "\u4e00" <= ch <= "\u9fff")
        if cjk >= 6 and cjk / max(1, len(text[:20000])) > 0.15:
            return Verdict(0.78, "中文文本", f"CJK={cjk}")
        if printable > 0.995 and len(data) >= 16:
            return Verdict(0.72, "UTF-8 文本", f"可打印率={printable:.3f}")
        if printable > 0.95:
            return Verdict(0.6, "UTF-8(含不可打印)", f"可打印率={printable:.3f}")
        return None
    if printable > 0.995 and len(data) >= 16:
        return Verdict(0.7, "ASCII 文本", f"可打印率={printable:.3f}")
    if printable > 0.95:
        return Verdict(0.58, "疑似文本", f"可打印率={printable:.3f}")
    return None


_EN_FREQ = {
    "e": 12.70, "t": 9.06, "a": 8.17, "o": 7.51, "i": 6.97, "n": 6.75, "s": 6.33,
    "h": 6.09, "r": 5.99, "d": 4.25, "l": 4.03, "c": 2.78, "u": 2.76, "m": 2.41,
    "w": 2.36, "f": 2.23, "g": 2.02, "y": 1.97, "p": 1.93, "b": 1.29, "v": 0.98,
    "k": 0.77, "j": 0.15, "x": 0.15, "q": 0.10, "z": 0.07, " ": 18.0,
}


@oracle("english", cost=1)
def _english(data: bytes, partial: bool) -> Optional[Verdict]:
    if len(data) < 24:
        return None
    sample = data[:8192].lower()
    letters = [b for b in sample if 97 <= b <= 122 or b == 32]
    if len(letters) < len(sample) * 0.6:
        return None
    counts = {}
    for b in letters:
        ch = chr(b)
        counts[ch] = counts.get(ch, 0) + 1
    total = len(letters)
    chi = 0.0
    for ch, freq in _EN_FREQ.items():
        expected = total * freq / 100.0
        observed = counts.get(ch, 0)
        chi += (observed - expected) ** 2 / expected
    score = max(0.0, 0.8 - chi / 400.0)
    if score > 0.45:
        return Verdict(min(score, 0.8), "英文文本", f"chi2={chi:.0f}")
    return None


@oracle("json", quick=lambda d: d[:1] in (b"{", b"["), cost=2)
def _json(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:1] not in (b"{", b"["):
        return None
    try:
        json.loads(data.decode("utf-8"))
        return Verdict(0.9, "JSON", f"{len(data)} 字节")
    except Exception:
        return None


@oracle("xml", quick=lambda d: d[:1] == b"<", cost=2)
def _xml(data: bytes, partial: bool) -> Optional[Verdict]:
    head = data[:512].lstrip()
    if not head.startswith(b"<"):
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if re.match(r"\s*<(\?xml|!DOCTYPE|html|svg|root|data)", text, re.I) and ">" in text:
        return Verdict(0.8, "XML/HTML", text[:60].replace("\n", " "))
    return None


# --------------------------------------------------------------------------
# 图片
# --------------------------------------------------------------------------

@oracle("png", quick=lambda d: d[:8] == b"\x89PNG\r\n\x1a\n", cost=3, partial_capable=True)
def _png(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    pos, chunks, verified, saw_ihdr, saw_iend = 8, 0, 0, False, False
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        if length > 0x7FFFFFFF or not ctype.isalpha():
            return None
        end = pos + 12 + length
        if end > len(data):
            if partial and verified >= 2:
                return Verdict(0.5 + min(0.35, verified * 0.05), "png 前缀",
                               f"{verified} 块 CRC 通过")
            return None
        stored = struct.unpack(">I", data[pos + 8 + length:end])[0]
        if (zlib.crc32(data[pos + 4:pos + 8 + length]) & 0xFFFFFFFF) != stored:
            return None
        verified += 1
        if ctype == b"IHDR":
            if length != 13:
                return None
            w, h, bd, ct, comp, filt, inter = struct.unpack(">IIBBBBB", data[pos + 8:pos + 21])
            valid = {(1, 0), (2, 0), (4, 0), (8, 0), (16, 0), (8, 2), (8, 3), (8, 4), (8, 6),
                     (16, 2), (16, 4), (16, 6), (1, 3), (2, 3), (4, 3)}
            if w == 0 or h == 0 or (bd, ct) not in valid or comp != 0 or filt != 0 or inter not in (0, 1):
                return None
            if w > 1 << 20 or h > 1 << 20:
                return None
            saw_ihdr = True
        if ctype == b"IEND":
            saw_iend = True
        chunks += 1
        pos = end
        if saw_iend:
            break
    if not saw_ihdr or verified < 2:
        return None
    score = min(0.95, 0.72 + verified * 0.06) + (0.05 if saw_iend else 0.0)
    detail = f"{chunks} 块，CRC 全通过" + ("" if saw_iend else "（无 IEND，可能被截断）")
    return Verdict(min(score, 1.0), "PNG", detail)


def jpeg_parse(data: bytes) -> tuple:
    """解析 JPEG 段结构。

    返回 ``(segments, status)``，status 取值：
      ``ok``        完整解析到 SOS/SOI 结尾
      ``truncated`` 数据在段中间被截断（可能是"还没解到那里"）
      ``bad``       结构非法（marker 错位、长度字段不合理）——基本可判定解错了
    """
    if data[:3] != b"\xff\xd8\xff":
        return [], "bad"
    pos = 2
    segs = []
    while True:
        if pos + 2 > len(data):
            return segs, "truncated"
        if data[pos] != 0xFF:
            return segs, "bad"
        marker = data[pos + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            segs.append((marker, b""))
            pos += 2
            continue
        if marker == 0xD9:
            segs.append((marker, b""))
            return segs, "ok"
        if pos + 4 > len(data):
            return segs, "truncated"
        length = int.from_bytes(data[pos + 2:pos + 4], "big")
        if length < 2:
            return segs, "bad"
        if pos + 2 + length > len(data):
            return segs, "truncated"
        payload = data[pos + 4:pos + 2 + length]
        segs.append((marker, payload))
        pos += 2 + length
        if marker == 0xDA:                                # SOS 之后是熵编码数据
            segs.append(("SCAN", data[pos:]))
            return segs, "ok"


def jpeg_segments(data: bytes) -> Optional[list]:
    """兼容接口：只在结构可解析时返回段列表。"""
    segs, status = jpeg_parse(data)
    return segs if status == "ok" else None


def dht_tables(data: bytes):
    """取出 JPEG 里所有 DHT 段，返回 [(tc_th, counts16, symbols), ...]。"""
    tables = []
    segs = jpeg_segments(data)
    if not segs:
        return tables
    for marker, payload in segs:
        if marker != 0xC4:
            continue
        i = 0
        while i < len(payload):
            tc_th = payload[i]
            i += 1
            if i + 16 > len(payload):
                return []
            counts = list(payload[i:i + 16])
            i += 16
            total = sum(counts)
            if i + total > len(payload):
                return []
            symbols = list(payload[i:i + total])
            i += total
            tables.append((tc_th, counts, symbols))
    return tables


def _dht_valid(payload: bytes) -> bool:
    i = 0
    while i < len(payload):
        tc_th = payload[i]
        i += 1
        tc, th = tc_th >> 4, tc_th & 0x0F
        if tc > 1 or th > 3:
            return False
        if i + 16 > len(payload):
            return False
        counts = payload[i:i + 16]
        i += 16
        total = sum(counts)
        if total == 0 or total > 256 or i + total > len(payload):
            return False
        # Kraft-McMillan：Σ counts[l]·2^(-l) ≤ 1（Huffman 码可以是"不完备"前缀码，
        # 标准 JPEG 的 DC 亮度表正好是 65408/65536，所以只能判上界）
        kraft = sum(c << (16 - l) for l, c in enumerate(counts, start=1) if c)
        if kraft > 1 << 16 or kraft == 0:
            return False
        symbols = payload[i:i + total]
        i += total
        if tc == 0 and any(s > 15 for s in symbols):   # DC 表 symbol 是类别号
            return False
    return i == len(payload)


def _dqt_valid(payload: bytes) -> bool:
    i = 0
    while i < len(payload):
        pq_tq = payload[i]
        i += 1
        pq, tq = pq_tq >> 4, pq_tq & 0x0F
        if pq > 1 or tq > 3:
            return False
        need = 64 * (2 if pq else 1)
        if i + need > len(payload):
            return False
        vals = payload[i:i + need]
        i += need
        if pq == 0 and any(v == 0 for v in vals):
            return False
    return i == len(payload)


@oracle("jpeg", quick=lambda d: d[:3] == b"\xff\xd8\xff", cost=3, partial_capable=True)
def _jpeg(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:3] != b"\xff\xd8\xff":
        return None
    segs, status = jpeg_parse(data)
    if status == "bad":
        return None
    if status == "truncated":
        if not partial:
            return None
        return Verdict(PREFIX_SCORE, "jpeg 前缀", f"已解析 {len(segs)} 段")
    saw_sof = saw_sos = saw_dht = saw_dqt = False
    for marker, payload in segs:
        if marker == "SCAN":
            saw_sos = True
            break
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            if len(payload) < 6:
                return None
            prec = payload[0]
            h, w = struct.unpack(">HH", payload[1:5])
            ncomp = payload[5]
            if prec != 8 or h == 0 or w == 0 or not 1 <= ncomp <= 4:
                return None
            if len(payload) != 6 + 3 * ncomp:
                return None
            saw_sof = True
        elif marker == 0xC4:
            if not _dht_valid(payload):
                return None
            saw_dht = True
        elif marker == 0xDB:
            if not _dqt_valid(payload):
                return None
            saw_dqt = True
        elif marker in (0xDD,):
            if len(payload) != 2:
                return None
    if saw_sof and saw_sos:
        detail = (f"{len(data)} 字节，段结构完整（DHT={'有' if saw_dht else '无'}, "
                  f"DQT={'有' if saw_dqt else '无'}）")
        return Verdict(1.0, "JPEG", detail)
    if partial and (saw_dht or saw_sof or len(segs) > 2):
        return Verdict(PREFIX_SCORE + 0.1, "jpeg 前缀", f"已解析 {len(segs)} 段")
    return None


@oracle("gif", quick=lambda d: d[:6] in (b"GIF87a", b"GIF89a"), cost=3)
def _gif(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    if len(data) < 14:
        return None
    w, h = struct.unpack("<HH", data[6:10])
    if w == 0 or h == 0:
        return None
    if data[-1:] != b"\x3b":
        if partial:
            return Verdict(PREFIX_SCORE, "gif 前缀", "缺 trailer")
        return None
    return Verdict(0.95, "GIF", f"{w}x{h}")


@oracle("bmp", quick=lambda d: d[:2] == b"BM", cost=2)
def _bmp(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:2] != b"BM" or len(data) < 54:
        return None
    size = struct.unpack("<I", data[2:6])[0]
    offset = struct.unpack("<I", data[10:14])[0]
    hdr = struct.unpack("<I", data[14:18])[0]
    if hdr not in (12, 40, 52, 56, 64, 108, 124):
        return None
    if offset < 26 or offset > len(data):
        return None
    ok = size == len(data)
    return Verdict(0.88 if ok else 0.55, "BMP", f"头={hdr} 大小={size}/{len(data)}")


@oracle("tiff", quick=lambda d: d[:4] in (b"II*\x00", b"MM\x00*"), cost=2)
def _tiff(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:4] not in (b"II*\x00", b"MM\x00*"):
        return None
    endian = "<" if data[:2] == b"II" else ">"
    ifd = struct.unpack(endian + "I", data[4:8])[0]
    if ifd < 8 or ifd >= len(data):
        return None
    return Verdict(0.6, "TIFF?", f"IFD@{ifd}（只看了头）")


@oracle("webp", quick=lambda d: d[:4] == b"RIFF" and d[8:12] == b"WEBP", cost=2)
def _webp(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None
    size = struct.unpack("<I", data[4:8])[0]
    ok = size + 8 == len(data)
    return Verdict(0.88 if ok else 0.55, "WEBP", f"{size + 8}/{len(data)}")


# --------------------------------------------------------------------------
# 压缩 / 归档
# --------------------------------------------------------------------------

@oracle("gzip", quick=lambda d: d[:3] == b"\x1f\x8b\x08", cost=3)
def _gzip(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:3] != b"\x1f\x8b\x08":
        return None
    try:
        out = __import__("gzip").decompress(data)
    except Exception:
        return Verdict(0.5, "gzip 前缀", "头部合法，解压失败") if partial else None
    return Verdict(1.0, "GZIP", f"解压 {len(out)} 字节，CRC+ISIZE 校验通过")


@oracle("zlib", quick=lambda d: len(d) > 2 and d[0] == 0x78 and d[1] in (0x01, 0x5E, 0x9C, 0xDA), cost=3)
def _zlib(data: bytes, partial: bool) -> Optional[Verdict]:
    if len(data) < 3 or data[0] != 0x78 or data[1] not in (0x01, 0x5E, 0x9C, 0xDA):
        return None
    try:
        out = zlib.decompress(data)
    except Exception:
        return None
    if not out:
        return None
    return Verdict(0.95, "ZLIB", f"解压 {len(out)} 字节")


@oracle("raw_deflate", cost=3)
def _raw_deflate(data: bytes, partial: bool) -> Optional[Verdict]:
    if len(data) < 16:
        return None
    try:
        out = zlib.decompressobj(-15).decompress(data)
    except Exception:
        return None
    if len(out) < 16:
        return None
    return Verdict(0.8, "deflate 裸流", f"解压 {len(out)} 字节")


@oracle("bzip2", quick=lambda d: d[:3] == b"BZh", cost=3)
def _bzip2(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:3] != b"BZh":
        return None
    try:
        out = bz2.decompress(data)
    except Exception:
        return None
    return Verdict(1.0, "BZIP2", f"解压 {len(out)} 字节")


@oracle("xz", quick=lambda d: d[:6] == b"\xfd7zXZ\x00", cost=3)
def _xz(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:6] != b"\xfd7zXZ\x00":
        return None
    try:
        out = lzma.decompress(data)
    except Exception:
        return None
    return Verdict(1.0, "XZ", f"解压 {len(out)} 字节")


@oracle("zip", quick=lambda d: d[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
        cost=4, partial_capable=True)
def _zip(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:4] not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return None
    pos, entries, verified = 0, 0, 0
    while pos + 30 <= len(data) and data[pos:pos + 4] == b"PK\x03\x04":
        try:
            (flags, method, _t, _d, crc, csize, usize, nlen, elen) = struct.unpack(
                "<HHHHIIIHH", data[pos + 4:pos + 30])
        except struct.error:
            return None
        name = data[pos + 30:pos + 30 + nlen]
        if nlen == 0 or b"\x00" in name or len(name) == 0:
            return None
        start = pos + 30 + nlen + elen
        end = start + csize
        if end > len(data):
            if partial and verified >= 1:
                return Verdict(0.6, "zip 前缀", f"{verified} 个条目 CRC 通过")
            return None
        blob = data[start:end]
        try:
            if method == 0:
                raw = blob
            elif method == 8:
                raw = zlib.decompressobj(-15).decompress(blob)
            else:
                raw = None
        except Exception:
            return None
        if raw is not None and (zlib.crc32(raw) & 0xFFFFFFFF) == crc and len(raw) == usize:
            verified += 1
        pos = end
        entries += 1
        if entries > 4096:
            break
    if verified == 0:
        return None
    eocd = data.rfind(b"PK\x05\x06")
    score = min(1.0, 0.65 + verified * 0.12) + (0.1 if eocd > 0 else 0.0)
    return Verdict(min(score, 1.0), "ZIP", f"{entries} 条目 / {verified} 个 CRC 通过")


@oracle("tar", cost=3, partial_capable=True)
def _tar(data: bytes, partial: bool) -> Optional[Verdict]:
    if len(data) < 512 or data[257:262] != b"ustar":
        return None
    try:
        stored = int(data[148:156].split(b"\x00")[0].strip() or b"0", 8)
    except ValueError:
        return None
    header = bytearray(data[:512])
    header[148:156] = b" " * 8
    calc = sum(header) & 0x1FFFF
    if calc != stored:
        return None
    return Verdict(0.95, "TAR", data[:100].split(b"\x00")[0].decode("latin-1"))


@oracle("sevenz", quick=lambda d: d[:6] == b"7z\xbc\xaf\x27\x1c", cost=2)
def _sevenz(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:6] != b"7z\xbc\xaf\x27\x1c":
        return None
    if len(data) < 32:
        return None
    # 7z 起始头自带 CRC32（覆盖第 12~32 字节），能真正校验
    try:
        (stored,) = struct.unpack("<I", data[8:12])
    except struct.error:
        return None
    calc = zlib.crc32(data[12:32]) & 0xFFFFFFFF
    if calc == stored:
        return Verdict(0.95, "7Z", "起始头 CRC 校验通过")
    return Verdict(0.5, "7z magic", "只有 magic，未通过 CRC")


@oracle("rar", quick=lambda d: d[:4] == b"Rar!\x1a\x07", cost=2)
def _rar(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:4] != b"Rar!\x1a\x07":
        return None
    if data[:7] == b"Rar!\x1a\x07\x01\x00" and len(data) > 16:
        # RAR5 头 CRC32 覆盖 header size 之后的内容
        try:
            (hsize,) = struct.unpack("<I", data[12:16])
        except struct.error:
            return None
        if 16 + hsize <= len(data):
            stored = struct.unpack("<I", data[8:12])[0]
            if zlib.crc32(data[12:16 + hsize]) & 0xFFFFFFFF == stored:
                return Verdict(0.95, "RAR5", "头 CRC 校验通过")
    return Verdict(0.5, "rar magic", "只有 magic，未通过 CRC")


# --------------------------------------------------------------------------
# 可执行 / 文档 / 其他
# --------------------------------------------------------------------------

@oracle("pdf", quick=lambda d: d[:5] == b"%PDF-", cost=2)
def _pdf(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:5] != b"%PDF-":
        return None
    tail = data[-2048:]
    has_eof = b"%%EOF" in tail
    has_obj = b" obj" in data[:200000] or b"/Type" in data[:200000]
    if has_eof and has_obj:
        return Verdict(0.97, "PDF", "含 xref/obj 与 %%EOF")
    if has_obj:
        return Verdict(0.75, "PDF?", "有对象但缺 %%EOF")
    return Verdict(PREFIX_SCORE, "pdf 前缀", "") if partial else None


@oracle("elf", quick=lambda d: d[:4] == b"\x7fELF", cost=2)
def _elf(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return None
    cls, _enc = data[4], data[5]
    if cls not in (1, 2) or data[6] != 1:
        return None
    endian = "<" if data[5] == 1 else ">"
    etype = struct.unpack(endian + "H", data[16:18])[0]
    if etype not in (1, 2, 3, 4):
        return None
    if cls == 2:
        phoff = struct.unpack(endian + "Q", data[32:40])[0]
    else:
        phoff = struct.unpack(endian + "I", data[28:32])[0]
    if phoff >= len(data):
        return None
    return Verdict(0.97, "ELF", f"{'64' if cls == 2 else '32'} 位 type={etype}")


@oracle("pe", quick=lambda d: d[:2] == b"MZ", cost=2)
def _pe(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    if lfanew + 24 > len(data) or data[lfanew:lfanew + 4] != b"PE\x00\x00":
        return None
    machine = struct.unpack("<H", data[lfanew + 4:lfanew + 6])[0]
    nsect = struct.unpack("<H", data[lfanew + 6:lfanew + 8])[0]
    if nsect == 0 or nsect > 96:
        return None
    return Verdict(0.97, "PE", f"machine=0x{machine:04x} 段数={nsect}")


@oracle("macho", quick=lambda d: d[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"), cost=2)
def _macho(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:4] not in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return None
    ncmds = struct.unpack("<I", data[16:20])[0]
    if ncmds == 0 or ncmds > 4096 or 32 + 4 * ncmds > len(data):
        return None
    return Verdict(0.7, "Mach-O?", f"{ncmds} 条 load command")


@oracle("sqlite", quick=lambda d: d[:16] == b"SQLite format 3\x00", cost=2)
def _sqlite(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:16] != b"SQLite format 3\x00":
        return None
    page = struct.unpack(">H", data[16:18])[0]
    if page == 0 or (page & (page - 1)) != 0 or page < 512:
        return None
    return Verdict(0.97, "SQLite", f"页大小={page}")


@oracle("ole", quick=lambda d: d[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", cost=2)
def _ole(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return None
    sector = 1 << struct.unpack("<H", data[30:32])[0]
    if sector not in (512, 4096):
        return None
    return Verdict(0.7, "OLE/Office?", f"扇区={sector}")


@oracle("riff", quick=lambda d: d[:4] == b"RIFF", cost=2)
def _riff(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:4] != b"RIFF" or len(data) < 12:
        return None
    size = struct.unpack("<I", data[4:8])[0]
    form = data[8:12]
    ok = size + 8 == len(data)
    label = {"WAVE": "WAV", "AVI ": "AVI", "WEBP": "WEBP"}.get(form.decode("latin-1"), "RIFF")
    return Verdict(0.88 if ok else 0.55, label, f"{form.decode('latin-1')} {size + 8}/{len(data)}")


@oracle("pcap", quick=lambda d: d[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                                           b"\x4d\x3c\xb2\xa1", b"\x0a\x0d\x0d\x0a"), cost=2)
def _pcap(data: bytes, partial: bool) -> Optional[Verdict]:
    if not any(data[:4] == m for m in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                                       b"\x0a\x0d\x0d\x0a")):
        return None
    return Verdict(0.6, "PCAP?", "只有 magic")


@oracle("mp3", quick=lambda d: d[:3] == b"ID3" or d[:2] in (b"\xff\xfb", b"\xff\xf3"), cost=2)
def _mp3(data: bytes, partial: bool) -> Optional[Verdict]:
    if data[:3] == b"ID3":
        if len(data) < 10:
            return None
        size = ((data[6] & 0x7F) << 21) | ((data[7] & 0x7F) << 14) | ((data[8] & 0x7F) << 7) | (data[9] & 0x7F)
        if size == 0:
            return None
        ok = 10 + size <= len(data)
        return Verdict(0.85 if ok else 0.55, "MP3/ID3", f"标签 {size} 字节")
    if data[:2] in (b"\xff\xfb", b"\xff\xf3") and len(data) > 4:
        return Verdict(0.6, "MP3 帧?", "")
    return None


# --------------------------------------------------------------------------
# 编码层
# --------------------------------------------------------------------------

_B64_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_B64URL_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
_HEX_CHARS = set(b"0123456789abcdefABCDEF \r\n\t")


@oracle("base64", cost=2)
def _base64(data: bytes, partial: bool) -> Optional[Verdict]:
    stripped = data.translate(None, b"\r\n\t ")
    if len(stripped) < 8 or len(stripped) % 4 != 0:
        return None
    if not set(stripped) <= _B64_CHARS:
        return None
    import base64 as _b64
    try:
        out = _b64.b64decode(stripped, validate=True)
    except Exception:
        return None
    inner = quick_score(out)
    return Verdict(0.55 + 0.3 * inner, "Base64 文本", f"解出 {len(out)} 字节")


@oracle("base64url", cost=2)
def _base64url(data: bytes, partial: bool) -> Optional[Verdict]:
    stripped = data.translate(None, b"\r\n\t ")
    if len(stripped) < 8 or len(stripped) % 4 != 0:
        return None
    if not set(stripped) <= _B64URL_CHARS:
        return None
    if b"+" in stripped or b"/" in stripped:
        return None
    import base64 as _b64
    try:
        out = _b64.urlsafe_b64decode(stripped)
    except Exception:
        return None
    inner = quick_score(out)
    return Verdict(0.5 + 0.3 * inner, "Base64URL 文本", f"解出 {len(out)} 字节")


@oracle("hex", quick=lambda d: len(d) >= 8 and set(d[:2048].translate(None, b"\r\n\t ")) <= _HEX_CHARS,
        cost=1)
def _hex(data: bytes, partial: bool) -> Optional[Verdict]:
    stripped = data.translate(None, b"\r\n\t ")
    if len(stripped) < 8 or len(stripped) % 2:
        return None
    if not set(stripped) <= _HEX_CHARS:
        return None
    try:
        out = bytes.fromhex(stripped.decode("ascii"))
    except Exception:
        return None
    inner = quick_score(out)
    return Verdict(0.5 + 0.3 * inner, "Hex 文本", f"解出 {len(out)} 字节")


@oracle("base32", cost=2)
def _base32(data: bytes, partial: bool) -> Optional[Verdict]:
    stripped = data.translate(None, b"\r\n\t ").upper()
    if len(stripped) < 8 or len(stripped) % 8:
        return None
    if not set(stripped) <= set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="):
        return None
    import base64 as _b64
    try:
        out = _b64.b32decode(stripped)
    except Exception:
        return None
    return Verdict(0.5 + 0.3 * quick_score(out), "Base32 文本", f"解出 {len(out)} 字节")


# --------------------------------------------------------------------------
# 侦察辅助
# --------------------------------------------------------------------------

def entropy(data: bytes) -> float:
    import math
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def describe(data: bytes) -> dict:
    """给 `scan` 用的文件画像。"""
    if not data:
        return {"len": 0}
    disp = data[:65536]
    bad = len(disp.translate(None, _ALLOWED_TEXT))
    verdicts = evaluate(data)
    return {
        "len": len(data),
        "entropy": round(entropy(disp), 3),
        "printable": round(1 - bad / len(disp), 3),
        "distinct_bytes": len(set(disp)),
        "mod4": len(data) % 4,
        "mod8": len(data) % 8,
        "mod16": len(data) % 16,
        "verdicts": [str(v) for v in verdicts[:6]],
        "head_hex": data[:16].hex(" "),
    }
