"""字符表（密码表）识别与还原。

这一模块解决的是题目里最烦人的情况：**加密程序把 Base64/进制字符表打乱了**，
标准库直接解不出来。本模块提供三条路：

1. ``detect_alphabets``    —— 先认出来这串东西属于哪个字符表家族（b64/b32/b58/...）。
2. ``mapping_from_pair``   —— 有"明文/密文"对照时，直接反推整张表。
3. ``TableSolver``         —— 没有完整对照时，用**结构约束**（文件 magic、
   段结构、Huffman 表、CRC、flag 前缀……）做约束求解 / 回溯搜索，把表补全。

``TableSolver`` 就是「密码表改了也能跑」的核心：它不假设字符表长什么样，
而是把未知字符当成变量，用"解出来的字节必须像某个文件"来约束。
"""

from __future__ import annotations

import base64 as _b64
import itertools
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import oracles
from .oracles import SUCCESS_SCORE, Verdict


# --------------------------------------------------------------------------
# 字符表库
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Alphabet:
    name: str
    chars: bytes
    bits: int
    group: int
    padding: bytes = b"="
    aliases: Tuple[str, ...] = ()

    @property
    def size(self) -> int:
        return len(self.chars)


ALPHABETS: Tuple[Alphabet, ...] = (
    Alphabet("base64", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 6, 4,
             b"=", ("b64", "std")),
    Alphabet("base64url", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", 6, 4,
             b"=", ("b64url", "urlsafe")),
    Alphabet("base32", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 5, 8, b"=", ("b32",)),
    Alphabet("base32hex", b"0123456789ABCDEFGHIJKLMNOPQRSTUV", 5, 8, b"=", ("b32hex",)),
    Alphabet("base58btc", b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", 0, 0, b"",
             ("b58", "btc")),
    Alphabet("base58flickr", b"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ", 0, 0, b"",
             ("flickr",)),
    Alphabet("base62", b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 0, 0, b"",
             ("b62",)),
    Alphabet("z85", b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#",
             0, 0, b"", ("z85",)),
    Alphabet("hex", b"0123456789abcdef", 4, 2, b"", ("base16", "b16")),
    Alphabet("hexupper", b"0123456789ABCDEF", 4, 2, b"", ("b16upper",)),
)
_BY_NAME: Dict[str, Alphabet] = {}
for _a in ALPHABETS:
    _BY_NAME[_a.name] = _a
    for _al in _a.aliases:
        _BY_NAME[_al] = _a

B64_STD = _BY_NAME["base64"]


def alphabet_by_name(name: str) -> Alphabet:
    key = (name or "").lower().strip()
    if key in _BY_NAME:
        return _BY_NAME[key]
    raise KeyError(f"未知字符表：{name}")


def alphabet_from_charset(chars: bytes, name: str = "custom") -> Alphabet:
    """用一段 64（或 32/16）字符的字符串构造字符表。"""
    chars = bytes(dict.fromkeys(chars))          # 去重保序
    bits = {64: 6, 32: 5, 16: 4}.get(len(chars), 0)
    group = {6: 4, 5: 8, 4: 2}.get(bits, 0)
    return Alphabet(name, chars, bits, group, b"=" if bits else b"")


# --------------------------------------------------------------------------
# 识别
# --------------------------------------------------------------------------

@dataclass
class AlphabetGuess:
    alphabet: Alphabet
    coverage: float                     # 数据里落在该表内的比例
    inside: set
    outside: set
    unknown: set                        # 表内但需要额外确认的字符（自定义表时无法判断）
    permuted: bool                      # 是否疑似"标准表被打乱"

    def __str__(self) -> str:
        tag = "（疑似被打乱的自定义表）" if self.permuted else ""
        return f"{self.alphabet.name} 覆盖={self.coverage:.2f}{tag}"


def detect_alphabets(data: bytes, sample: int = 8192) -> List[AlphabetGuess]:
    """识别数据属于哪个字符表家族。"""
    body = data[:sample]
    stripped = body.translate(None, b" \r\n\t")
    if not stripped:
        return []
    seen = set(stripped)
    out: List[AlphabetGuess] = []
    for a in ALPHABETS:
        if a.bits == 0:
            continue
        inside = seen & set(a.chars) | (seen & set(a.padding))
        outside = seen - set(a.chars) - set(a.padding)
        coverage = len(seen - outside) / len(seen)
        if coverage >= 0.9:
            permuted = False
            unknown = set()
            if a.name == "base64" and not outside and set(seen) - set(a.padding) != set(a.chars):
                # 全是 64 个字符、但不等于标准表 → 可能是自定义表
                chars_only = seen - set(a.padding)
                if len(chars_only) == 64:
                    permuted = True
                    unknown = set(chars_only)
            out.append(AlphabetGuess(a, coverage, inside, outside, unknown, permuted))
    out.sort(key=lambda g: (-g.coverage, g.alphabet.bits))
    return out


def guess_alphabet(data: bytes) -> Optional[AlphabetGuess]:
    guesses = detect_alphabets(data)
    return guesses[0] if guesses else None


# --------------------------------------------------------------------------
# 已知明文 → 字符表映射
# --------------------------------------------------------------------------

class TableConflict(Exception):
    pass


def _tokens(data: bytes, alphabet: Alphabet) -> bytes:
    """去掉空白与填充符，得到纯字符表 token 序列。"""
    keep = set(alphabet.chars)
    return bytes(b for b in data if b in keep)


def group_constraints(chars: Sequence[int], plain: bytes) -> List[Tuple[int, int]]:
    """Base64 分组方程：4 个 6bit 值 → 3 字节。返回 [(char_index, value), ...]。

    只有当一组里 3 个明文字节都已知时才能完全定出 4 个字符的值；
    只知部分字节时返回该组能确定的字符。
    """
    out: List[Tuple[int, int]] = []
    n = len(chars) - len(chars) % 4
    for g in range(0, n, 4):
        base = g // 4 * 3
        known = {}
        for k in range(3):
            if base + k < len(plain):
                known[k] = plain[base + k]
        if len(known) == 3:
            b0, b1, b2 = known[0], known[1], known[2]
            out.append((g + 0, b0 >> 2))
            out.append((g + 1, ((b0 & 0x03) << 4) | (b1 >> 4)))
            out.append((g + 2, ((b1 & 0x0F) << 2) | (b2 >> 6)))
            out.append((g + 3, b2 & 0x3F))
        else:
            # 部分已知：能直接给出的单个字符
            if 0 in known:
                out.append((g + 0, known[0] >> 2))
            if 0 in known and 1 in known:
                out.append((g + 1, ((known[0] & 3) << 4) | (known[1] >> 4)))
            if 1 in known and 2 in known:
                out.append((g + 2, ((known[1] & 0x0F) << 2) | (known[2] >> 6)))
            if 2 in known:
                out.append((g + 3, known[2] & 0x3F))
    return out


def mapping_from_pair(plain: bytes, cipher: bytes, alphabet: Alphabet = B64_STD) -> Dict[int, int]:
    """明文 + 自定义字符表密文 → {自定义字符: 标准表下标}。"""
    expected = _tokens(_b64.b64encode(plain), alphabet)
    actual = _tokens(cipher, alphabet)
    if len(expected) != len(actual):
        raise TableConflict(f"长度不一致：标准 {len(expected)} vs 密文 {len(actual)}")
    mapping: Dict[int, int] = {}
    for enc, std in zip(actual, expected):
        value = alphabet.chars.index(std)
        if enc in mapping and mapping[enc] != value:
            raise TableConflict(f"字符 {chr(enc)!r} 映射冲突")
        mapping[enc] = value
    return mapping


def _pad_count(data: bytes, alphabet: Alphabet) -> int:
    if not alphabet.padding:
        return 0
    return sum(1 for b in data if b in alphabet.padding)


def decode_with_mapping(data: bytes, mapping: Dict[int, int], alphabet: Alphabet = B64_STD,
                        strict: bool = True) -> bytes:
    """按映射把自定义字符表数据解成字节。未知字符在 strict=False 时跳过。"""
    tokens = _tokens(data, alphabet)
    values: List[int] = []
    for b in tokens:
        if b in mapping:
            values.append(mapping[b])
        elif strict:
            raise KeyError(f"字符表缺少 {chr(b)!r} 的映射")
    plain = _values_to_bytes(values, alphabet)
    return plain


def _values_to_bytes(values: Sequence[int], alphabet: Alphabet) -> bytes:
    """6/5/4 bit 位流 → 字节。

    只取完整字节：字节数 = floor(字符数 × 每字符位数 / 8)。
    这样 base64 的 2/3 字符尾组、base32 的 2/4/5/7 字符尾组都能自然处理，
    不需要再按 padding 数量手工扣字节。
    """
    if alphabet.bits in (6, 5):
        acc = 0
        bits = 0
        out = bytearray()
        for v in values:
            acc = (acc << alphabet.bits) | v
            bits += alphabet.bits
            while bits >= 8:
                bits -= 8
                out.append((acc >> bits) & 0xFF)
        return bytes(out)
    if alphabet.bits == 4:
        out = bytearray()
        for i in range(0, len(values) - 1, 2):
            out.append((values[i] << 4) | values[i + 1])
        return bytes(out)
    raise ValueError("该字符表不支持位流解码（如 base58 是大数编码）")


def decode_known_prefix(data: bytes, mapping: Dict[int, int], alphabet: Alphabet = B64_STD) -> bytes:
    """只解出"从头开始、字符全部已知"的那段（用于增量校验）。"""
    tokens = _tokens(data, alphabet)
    values: List[int] = []
    for b in tokens:
        if b not in mapping:
            break
        values.append(mapping[b])
    return _values_to_bytes(values, alphabet)


# --------------------------------------------------------------------------
# 约束求解：把缺失的字符表补全
# --------------------------------------------------------------------------

@dataclass
class Stream:
    """参与求解的一条数据流。"""

    name: str
    data: bytes
    alphabet: Alphabet = B64_STD
    # 已知明文片段 [(偏移, 字节)]，例如文件 magic、已知明文对照的前缀
    known_spans: List[Tuple[int, bytes]] = field(default_factory=list)
    # 校验函数（data, partial) -> Verdict|None
    oracle: Optional[Callable[[bytes, bool], Optional[Verdict]]] = None
    min_partial: float = 0.5
    fmt: str = ""
    # 参考文件（用于比对段结构，例如标准 JPEG 的 Huffman 表）
    ref_segments: Optional[list] = None
    # 参考文件里"可以照抄"的字段 [(偏移, 字节)]，搜索时当已知明文用
    ref_spans: List[Tuple[int, bytes]] = field(default_factory=list)
    # 前缀短于这个长度时不做 oracle 判断（太短了什么格式都看不出来）
    min_check_len: int = 8

    def known_prefix(self) -> bytes:
        if not self.known_spans:
            return b""
        offset = 0
        out = bytearray()
        for off, blob in sorted(self.known_spans):
            if off != offset:
                break
            out += blob
            offset += len(blob)
        return bytes(out)


@dataclass
class Solution:
    mapping: Dict[int, int]
    streams: List[Stream]
    score: float
    notes: List[str]
    plaintexts: Dict[str, bytes] = field(default_factory=dict)
    complete: bool = False

    def table(self, alphabet: Alphabet = B64_STD) -> bytes:
        """还原出的自定义字符表（标准顺序 → 自定义字符）。"""
        reverse = {v: k for k, v in self.mapping.items()}
        return bytes(reverse.get(i, ord("?")) for i in range(len(alphabet.chars)))


class TableSolver:
    """用已知明文 + 结构约束还原被改动的字符表。"""

    def __init__(self, streams: Sequence[Stream], alphabet: Alphabet = B64_STD,
                 budget: int = 400000, log: Optional[Callable[[str], None]] = None,
                 require_success: bool = True, permutation: bool = True,
                 max_solutions: int = 6, time_budget: float = 0.0):
        self.streams = list(streams)
        self.alphabet = alphabet
        self.budget = budget
        self.log = log or (lambda _m: None)
        self.require_success = require_success
        self.permutation = permutation
        self.max_solutions = max_solutions
        self.time_budget = time_budget
        self.nodes = 0
        self.solutions: List[Solution] = []
        self.conflicts: List[str] = []
        self._last_checked: Dict[int, bytes] = {}
        self._stop = False
        self.strict_ref = True
        self._deadline = 0.0

    # -- 已知明文 ---------------------------------------------------------
    def _seed_from_known(self, mapping: Dict[int, int]) -> bool:
        for s in self.streams:
            tokens = _tokens(s.data, self.alphabet)
            spans = list(s.known_spans)
            if self.strict_ref and s.ref_spans:
                # 参考文件的段字段直接当已知明文：未知字符立刻被钉死，
                # 不用等整段解完才知道对不对
                spans = spans + list(s.ref_spans)
            for off, blob in spans:
                if not blob:
                    continue
                if off % 3:
                    # 只有对齐到 Base64 分组的已知明文才能直接算字符值：截掉前面几个字节
                    skip = (3 - off % 3) % 3
                    off, blob = off + skip, blob[skip:]
                if len(blob) < 3:
                    continue
                pos = (off // 3) * self.alphabet.group
                for idx, value in group_constraints(tokens[pos:], blob):
                    ch = tokens[pos + idx]
                    if ch in mapping and mapping[ch] != value:
                        self.conflicts.append(
                            f"{s.name}: 已知明文/参考文件推出 {chr(ch)!r}={value}，"
                            f"与已有 {mapping[ch]} 冲突")
                        return False
                    mapping[ch] = value
        return True

    # -- 增量校验 ---------------------------------------------------------
    def _out_of_time(self) -> bool:
        import time as _time
        return bool(self._deadline) and _time.monotonic() > self._deadline

    def _check_stream(self, s: Stream, mapping: Dict[int, int], force: bool = False) -> bool:
        prefix = decode_known_prefix(s.data, mapping, self.alphabet)
        if not force and prefix == self._last_checked.get(id(s)):
            return True
        self._last_checked[id(s)] = prefix
        s._prefix = prefix                                        # type: ignore[attr-defined]
        if s.oracle is not None and len(prefix) >= s.min_check_len:
            try:
                v = s.oracle(prefix, True)
            except Exception:
                v = None
            if v is None or v.score < s.min_partial:
                return False
        if s.ref_segments and self.strict_ref:
            if not self._check_reference(s, prefix):
                return False
        return True

    def _check_reference(self, s: Stream, prefix: bytes) -> bool:
        """与参考文件比对已解出的段。

        这是最有力的剪枝依据：一旦某个候选字符值让段结构（marker 序列）
        或标准 Huffman 表对不上，整条分支立刻丢掉。
        """
        if normalize_format(s.fmt) != "jpeg" or not s.ref_segments:
            return True
        ok, _why = self.reference_alignment(prefix, s.ref_segments)
        return ok

    @staticmethod
    def reference_alignment(decoded: bytes, ref: list, complete: bool = False) -> Tuple[bool, str]:
        """把解出的字节与参考 JPEG 的段结构对照。

        ``complete=False`` 用于搜索过程中的前缀：数据被截断视为"还没解到这里"；
        ``complete=True`` 用于最终校验：截断/结构非法都算失败。
        """
        segs, status = oracles.jpeg_parse(decoded)
        if status == "bad":
            return False, "JPEG 段结构非法（marker 错位或长度字段不合理）"
        if status == "truncated":
            return (False, "数据在段中间截断") if complete else (True, "段尚未完整")
        if len(segs) > len(ref):
            return False, f"段数量 {len(segs)} 超过参考文件 {len(ref)}"
        if complete and len(segs) != len(ref):
            return False, f"段数量 {len(segs)} 与参考 {len(ref)} 不一致"
        for i, (marker, payload) in enumerate(segs):
            rmarker, rpayload = ref[i]
            if rmarker != marker:
                return False, f"第 {i} 段 marker 不一致：{marker} != {rmarker}"
            if marker == 0xC4 and payload != rpayload:
                return False, f"第 {i} 段 Huffman 表与标准表不一致"
        return True, "段结构与标准 JPEG 一致"

    # -- 回溯搜索 ---------------------------------------------------------
    def run(self) -> List[Solution]:
        """先按"标准表"严格比对；若一个解都没有，自动退回纯结构校验再试一遍。"""
        self.strict_ref = True
        sols = self._run_once()
        if not sols and any(s.ref_segments for s in self.streams):
            self.log("严格比对无解 → 关闭参考比对，退回结构校验重试")
            self.strict_ref = False
            sols = self._run_once()
        return sols

    def _run_once(self) -> List[Solution]:
        import time as _time
        self.solutions = []
        self.nodes = 0
        self._last_checked = {}
        self._stop = False
        self.conflicts = []
        self._deadline = _time.monotonic() + self.time_budget if self.time_budget else 0.0
        # 先拿"约束最强"的数据流去定未知字符：已知明文 → 有参考结构 → 标准格式 → 其它
        self.streams.sort(key=self._stream_priority)
        mapping: Dict[int, int] = {}
        if not self._seed_from_known(mapping):
            return []
        self.log(f"已知明文直接推出 {len(mapping)} 个字符映射")
        unknown = self._unknown_chars(mapping)
        self.log(f"待求解字符：{len(unknown)} 个"
                 f"{'（' + ''.join(chr(c) for c in unknown) + '）' if unknown else ''}")
        if not unknown:
            self._finish(mapping)
        else:
            self._dfs(mapping, unknown, 0)
        self.log(f"搜索节点 {self.nodes}，候选解 {len(self.solutions)} 个")
        self.solutions.sort(key=lambda s: -s.score)
        return self.solutions

    @staticmethod
    def _stream_priority(s: Stream) -> int:
        known = s.known_prefix()
        if len(known) >= 24:
            return 0
        if s.ref_spans or s.ref_segments:
            return 1
        if normalize_format(s.fmt) in ("jpeg", "png", "zip", "gzip", "gz", "bz2", "xz",
                                       "pdf", "elf", "pe", "sqlite"):
            return 2
        if known:
            return 3
        return 4

    def _unknown_chars(self, mapping: Dict[int, int]) -> List[int]:
        seen: List[int] = []
        for s in self.streams:
            for b in _tokens(s.data, self.alphabet):
                if b not in mapping and b not in seen:
                    seen.append(b)
        return seen

    def _dfs(self, mapping: Dict[int, int], unknown: List[int], depth: int) -> None:
        if self.nodes > self.budget or self._stop or self._out_of_time():
            return
        if depth == len(unknown):
            self._finish(mapping)
            if len(self.solutions) >= self.max_solutions:
                self._stop = True
            return
        ch = unknown[depth]
        used = set(mapping.values())
        for value in range(len(self.alphabet.chars)):
            if self.permutation and value in used:
                continue
            self.nodes += 1
            if self.nodes > self.budget:
                return
            mapping[ch] = value
            if self._check_all(mapping, ch):
                self._dfs(mapping, unknown, depth + 1)
            del mapping[ch]
            if self._stop:
                return

    def _check_all(self, mapping: Dict[int, int], changed: int) -> bool:
        for s in self.streams:
            if changed in _tokens(s.data, self.alphabet):
                if not self._check_stream(s, mapping):
                    return False
        return True

    def _finish(self, mapping: Dict[int, int]) -> None:
        notes: List[str] = []
        plaintexts: Dict[str, bytes] = {}
        total = 0.0
        best = 0.0
        for s in self.streams:
            try:
                plain = decode_with_mapping(s.data, mapping, self.alphabet)
            except KeyError:
                return
            if s.ref_segments and self.strict_ref:
                ok, why = self.reference_alignment(plain, s.ref_segments, complete=True)
                if not ok:
                    return
                notes.append(f"{s.name}: 参考比对通过（{why}）")
            plaintexts[s.name] = plain
            vs = oracles.evaluate(plain)
            score = vs[0].score if vs else 0.0
            if s.oracle is not None:
                v = s.oracle(plain, False)
                if v is not None:
                    score = max(score, v.score)
            if s.ref_segments and self.strict_ref:
                score = max(score, 0.9)
            best = max(best, score)
            total += score
            notes.append(f"{s.name}: {vs[0] if vs else '无结构特征'}")
        score = max(best, total / max(1, len(self.streams)))
        complete = best >= SUCCESS_SCORE
        if self.require_success and not complete:
            return
        self.solutions.append(Solution(dict(mapping), self.streams, score, notes, plaintexts, complete))


# --------------------------------------------------------------------------
# 参考文件（标准 Huffman 表）
# --------------------------------------------------------------------------

def pil_reference_jpeg(width: int = 64, height: int = 64) -> Optional[bytes]:
    """用 Pillow 生成一张参考 JPEG（标准 Huffman/量化表），用于比对段结构。"""
    try:
        import io
        from PIL import Image
    except Exception:
        return None
    buf = io.BytesIO()
    Image.new("RGB", (width, height)).save(buf, format="JPEG")
    return buf.getvalue()


def reference_segments(fmt: str, reference: Optional[bytes], size=(64, 64)) -> Optional[list]:
    if normalize_format(fmt) != "jpeg":
        return None
    data = reference
    if data is None:
        data = pil_reference_jpeg(*size)
    if not data:
        return None
    return oracles.jpeg_segments(data)


# 段结构里"可以照抄参考文件"的部分：
# marker + 长度字段永远可比；DHT（标准 Huffman 表）、SOF（尺寸）、SOS、DRI 的载荷也可比。
# DQT 载荷随 quality 变化，APPn 随编码器变化 —— 一律跳过。
_JPEG_SOF_MARKERS = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
_JPEG_COMPARE_PAYLOAD = _JPEG_SOF_MARKERS | {0xC4, 0xDA, 0xDD}


def reference_spans(segments: Optional[list]) -> List[Tuple[int, bytes]]:
    """把参考 JPEG 的段结构变成"已知明文字段" [(偏移, 字节)]。"""
    if not segments:
        return []
    spans: List[Tuple[int, bytes]] = []
    pos = 2                                   # 跳过 SOI
    for marker, payload in segments:
        if marker == "SCAN":
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            spans.append((pos, bytes([0xFF, marker])))
            pos += 2
            continue
        head = bytes([0xFF, marker]) + (len(payload) + 2).to_bytes(2, "big")
        spans.append((pos, head))
        if marker in _JPEG_SOF_MARKERS and len(payload) > 6:
            # SOF 载荷里"精度 + 分量信息"可比，但图像宽高必须跳过
            # （参考图尺寸未必和目标图一样）
            spans.append((pos + 4, payload[:1]))          # 精度
            spans.append((pos + 10, payload[6:]))         # 分量数 + 各分量参数
        elif marker in _JPEG_COMPARE_PAYLOAD and payload:
            spans.append((pos + 4, payload))
        pos += 4 + len(payload)
    return spans


# --------------------------------------------------------------------------
# 格式 magic（当作"已知明文前缀"用）
# --------------------------------------------------------------------------

FORMAT_MAGIC: Dict[str, bytes] = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "jpg": b"\xff\xd8\xff",
    "gif": b"GIF89a",
    "bmp": b"BM",
    "zip": b"PK\x03\x04",
    "gzip": b"\x1f\x8b\x08",
    "bz2": b"BZh9",
    "xz": b"\xfd7zXZ\x00",
    "pdf": b"%PDF-",
    "elf": b"\x7fELF",
    "pe": b"MZ",
    "exe": b"MZ",
    "sqlite": b"SQLite format 3\x00",
    "rar": b"Rar!\x1a\x07\x00",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "mp3": b"ID3",
    "wav": b"RIFF",
    "avi": b"RIFF",
    "tiff": b"II*\x00",
    "webp": b"RIFF",
    "txt": b"",
    "flag": b"flag{",
    "json": b"",
    "py": b"",
}


FORMAT_ALIASES = {
    "jpg": "jpeg", "jpe": "jpeg", "jfif": "jpeg", "exe": "pe", "dll": "pe", "sys": "pe",
    "tif": "tiff", "htm": "html", "bzip2": "bz2", "gzip": "gz", "7zip": "7z", "text": "txt",
    "log": "txt", "md": "txt", "csv": "txt", "xml": "txt", "py": "txt", "js": "txt", "c": "txt",
}


def normalize_format(fmt: str) -> str:
    """统一格式名（jpg → jpeg，exe → pe……），避免"看着像却没启用结构校验"。"""
    if not fmt:
        return ""
    low = fmt.lower().lstrip(".")
    return FORMAT_ALIASES.get(low, low)


def format_of_name(name: str) -> str:
    """从文件名猜格式（logo.jpg.enc → jpeg）。"""
    base = name.lower()
    for suffix in (".enc", ".encrypted", ".locked", ".crypt", ".crypto", ".data", ".out", ".bak"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    if "." in base:
        ext = base.rsplit(".", 1)[-1]
        if ext in FORMAT_MAGIC or ext in FORMAT_ALIASES:
            return normalize_format(ext)
    return ""


def magic_span(fmt: str) -> List[Tuple[int, bytes]]:
    magic = FORMAT_MAGIC.get(normalize_format(fmt), b"")
    return [(0, magic)] if magic else []
