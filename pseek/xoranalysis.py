"""多字节 XOR 自动分析（xortool 的思路 + 语言模型打分）。

xortool 的两个关键点值得借鉴：

1. **密钥长度靠"等字符计数"猜**：把数据与自身错位 key_len 比较，重复密钥会让
   相同位置的字节更频繁地相等；
2. **密钥靠"最高频字符"反推**：每个密钥字节位置单独看，出现最多的明文字节
   通常是 0x00（二进制文件）或 0x20（英文文本），于是
   ``key[i] = 密文第 i 列最高频字节 ^ 最高频明文字节``。

在此之上加了语言模型打分兜底：算出密钥后立刻给明文打分，谁能得到人话谁赢；
实在猜不到最高频字符时，还可以逐列暴力枚举可打印密钥字节。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import langscore, oracles


@dataclass
class XorResult:
    key: bytes
    plaintext: bytes
    key_length: int
    score: float
    method: str
    detail: str = ""

    def line(self) -> str:
        preview = self.plaintext[:64]
        try:
            text = preview.decode("utf-8").replace("\n", "\\n")
        except UnicodeDecodeError:
            text = preview.hex(" ")
        return (f"[{self.score:.2f}] 密钥长度 {self.key_length} 密钥={self.key!r} "
                f"({self.method}) → {text}")


# --------------------------------------------------------------------------
# 密钥长度
# --------------------------------------------------------------------------

def index_of_coincidence(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def equal_chars_score(data: bytes, key_length: int, sample: int = 8192) -> float:
    """xortool 的"等字符计数"：错位 key_length 后相同位置相等的比例。"""
    if key_length <= 0 or len(data) <= key_length + 1:
        return 0.0
    blob = data[:sample]
    same = 0
    total = 0
    for i in range(len(blob) - key_length):
        total += 1
        if blob[i] == blob[i + key_length]:
            same += 1
    return same / max(1, total)


def guess_key_lengths(data: bytes, max_length: int = 32, top: int = 6) -> List[Tuple[int, float]]:
    scores = [(n, equal_chars_score(data, n)) for n in range(1, max_length + 1)]
    scores.sort(key=lambda item: -item[1])
    return scores[:top]


# --------------------------------------------------------------------------
# 密钥恢复
# --------------------------------------------------------------------------

def _column_frequency(data: bytes, key_length: int) -> List[Dict[int, int]]:
    cols: List[Dict[int, int]] = [dict() for _ in range(key_length)]
    for i, b in enumerate(data):
        col = cols[i % key_length]
        col[b] = col.get(b, 0) + 1
    return cols


def recover_key_by_frequency(data: bytes, key_length: int,
                             most_common: int = 0x00) -> bytes:
    key = bytearray()
    for col in _column_frequency(data, key_length):
        if not col:
            key.append(0)
            continue
        top = max(col.items(), key=lambda kv: kv[1])[0]
        key.append(top ^ most_common)
    return bytes(key)


_PRINTABLE = bytes(range(0x20, 0x7F))
_LETTER_FREQ = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
                0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
                2.758, 0.978, 2.360, 0.150, 1.974, 0.074]


def column_quality(plain: bytes) -> float:
    """单列的"像不像英文"快速指标（比跑完整语言模型便宜几个数量级）。"""
    n = len(plain)
    if not n:
        return 0.0
    printable = 1.0 - len(plain.translate(None, _PRINTABLE)) / n
    counts = [0] * 26
    spaces = 0
    for b in plain:
        if 97 <= b <= 122:
            counts[b - 97] += 1
        elif 65 <= b <= 90:
            counts[b - 65] += 1
        elif b == 0x20:
            spaces += 1
    letters = sum(counts)
    chi_norm = 0.0
    if letters >= 8:
        chi = 0.0
        for i, pct in enumerate(_LETTER_FREQ):
            expected = letters * pct / 100.0
            chi += (counts[i] - expected) ** 2 / max(0.5, expected)
        chi_norm = max(0.0, min(1.0, 1.0 - chi / (2.2 * letters)))
    space_norm = min(1.0, (spaces / n) / 0.16)
    return 0.45 * printable + 0.35 * chi_norm + 0.2 * space_norm


def recover_key_by_score(data: bytes, key_length: int, sample: int = 4096,
                         alphabet: bytes = _PRINTABLE) -> bytes:
    """逐列暴力枚举可打印密钥字节，用列质量指标挑最好的（比频率法更稳）。"""
    blob = data[:sample]
    cols = _column_frequency(blob, key_length)
    key = bytearray()
    for col in cols:
        best_byte, best_score = 0, -1e9
        for cand in alphabet:
            plain = bytes(b ^ cand for b in col)
            s = column_quality(plain)
            if s > best_score:
                best_byte, best_score = cand, s
        key.append(best_byte)
    return bytes(key)


def xor_with(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# --------------------------------------------------------------------------
# 自动分析
# --------------------------------------------------------------------------

def single_byte_bruteforce(data: bytes, cap: int = 4096) -> List[XorResult]:
    sample = data[:cap]
    out: List[XorResult] = []
    for k in range(256):
        plain = bytes(b ^ k for b in sample)
        s = langscore.score_bytes(plain).score
        out.append(XorResult(bytes([k]), plain, 1, s, "单字节暴力"))
    out.sort(key=lambda r: -r.score)
    return out


def auto_xor(data: bytes, max_length: int = 32, top_keys: int = 6,
             most_common: Sequence[int] = (0x20, 0x00, 0xFF)) -> List[XorResult]:
    """自动猜密钥长度 + 恢复密钥 + 打分，返回按分数排序的候选。

    排序**以语言模型为主**：oracle 只在给出强结构证据（≥0.85，例如真解出文件头）
    时才参与，避免"看着像文本"的弱判定把错误密钥顶到前面。
    """
    results: List[XorResult] = []
    if len(data) < 8:
        return results

    lengths: List[int] = []
    for length, _score in guess_key_lengths(data, max_length, top=top_keys):
        lengths.append(length)
    for length in range(1, min(max_length, 24) + 1):
        if length not in lengths:
            lengths.append(length)

    for length in lengths:
        if length == 1:
            results.extend(single_byte_bruteforce(data)[:3])
            continue
        for mc in most_common:
            key = recover_key_by_frequency(data, length, mc)
            plain = xor_with(data, key)
            results.append(XorResult(key, plain, length,
                                     langscore.score_bytes(plain).score,
                                     f"频率法(最高频={mc:#04x})"))
        if length <= 16:
            key = recover_key_by_score(data, length)
            plain = xor_with(data, key)
            results.append(XorResult(key, plain, length,
                                     langscore.score_bytes(plain).score, "逐列质量搜索"))

    uniq: Dict[bytes, XorResult] = {}
    for r in results:
        old = uniq.get(r.key)
        if old is None or r.score > old.score:
            uniq[r.key] = r
    merged = list(uniq.values())

    # oracle 只加"强证据"：真文件头、真压缩流、flag 正则这类
    for r in merged:
        verdicts = oracles.evaluate(r.plaintext, cap=8192)
        if verdicts and verdicts[0].score >= 0.85:
            r.score = max(r.score, verdicts[0].score)
            r.detail = str(verdicts[0])
    # 分数接近时优先短密钥（奥卡姆剃刀）：长密钥往往是真密钥的整数倍，
    # 解出来"一半对一半错"也像人话——xortool 里提示的 "Key-length can be n*m" 就是这个坑。
    merged.sort(key=lambda r: (-round(r.score, 2), r.key_length))
    return merged[:12]


def xor_key_from_known_plaintext(plain: bytes, cipher: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(plain, cipher))


def trim_repeating(stream: bytes, max_period: int = 64) -> Optional[bytes]:
    for period in range(1, min(max_period, max(1, len(stream) // 3)) + 1):
        if all(stream[i] == stream[i % period] for i in range(len(stream))):
            return stream[:period]
    return None


# --------------------------------------------------------------------------
# 已知明文恢复周期 XOR 密钥（借鉴看雪 r0crawl-skills 的 ctf-key-recovery）
# --------------------------------------------------------------------------

@dataclass
class PeriodKeyResult:
    """周期 XOR 密钥的恢复结果。**关键是那个一致性检查**。"""

    key: bytes
    period: int
    offset: int
    votes: List[int]                       # 每个密钥槽位被"独立验证"了几次
    consistent: bool
    detail: str = ""

    @property
    def every_slot_checked(self) -> bool:
        return all(v > 0 for v in self.votes)

    @property
    def min_votes(self) -> int:
        return min(self.votes) if self.votes else 0

    def line(self) -> str:
        text = self.key.decode("utf-8", "replace") if self.key else ""
        return (f"周期={self.period} 密钥={self.key!r}"
                + (f" ({text})" if text.isprintable() else "")
                + f"  每槽位投票={self.votes} 一致={self.consistent}"
                + (f"  {self.detail}" if self.detail else ""))


def recover_period_key(cipher: bytes, known_plain: bytes, period: int,
                       offset: int = 0) -> Optional[PeriodKeyResult]:
    """用**已知明文**恢复周期 XOR 密钥，并做严格一致性检查。

    这是 CTF 里最便宜、也最可靠的一招（看雪 r0crawl-skills 的 ``ctf-key-recovery``
    就是先找最便宜的可逆关系）。原理一句话：

        ``cipher[i] = plain[i] ^ key[i % period]``
        → ``key[i % period] = cipher[i] ^ plain[i]``

    **为什么一定要做一致性检查**：同一个密钥槽位会被已知明文的多个位置覆盖，
    如果这些位置算出来的密钥字节**互不相同**，说明假设本身错了（周期不对、明文不对、
    或者根本不是周期 XOR）。只看"密钥是不是可打印"就下结论，会得到看似合理实则错误
    的结果——这正是逆向里最常见的假阳性来源之一。

    ``offset`` 是已知明文对应的密文起始偏移（明文的第 0 字节对应 ``cipher[offset]``）。
    返回 ``None`` 表示已知明文不够填满所有槽位，或者约束自相矛盾。
    """
    if period <= 0 or not cipher or not known_plain:
        return None
    slots: List[Optional[int]] = [None] * period
    votes = [0] * period
    consistent = True
    for i, plain_byte in enumerate(known_plain):
        pos = offset + i
        if pos >= len(cipher):
            break
        value = cipher[pos] ^ plain_byte
        slot = pos % period
        if slots[slot] is None:
            slots[slot] = value
        elif slots[slot] != value:
            consistent = False
            break
        votes[slot] += 1
    if not consistent:
        return None
    if any(v is None for v in slots):
        return None
    key = bytes(v for v in slots if v is not None)
    covered = sum(votes)
    detail = (f"已知明文 {len(known_plain)} 字节覆盖了每个槽位 "
              f"{min(votes)}~{max(votes)} 次；每题位一致 → 不是靠可打印性猜的")
    if covered < period * 2:
        detail = ("⚠ 已知明文偏短（每槽位不足 2 次投票），结论仅供下一步验证 "
                  + detail)
    return PeriodKeyResult(key=key, period=period, offset=offset, votes=votes,
                           consistent=True, detail=detail)


def guess_period_from_keystream(stream: bytes, max_period: int = 64) -> Optional[int]:
    """已知密钥流（= 密文 ^ 明文）时，直接看出它的周期。"""
    key = trim_repeating(stream, max_period=max_period)
    return len(key) if key else None


def recover_key_from_candidates(cipher: bytes, plains: Sequence[bytes],
                                period: int, offset: int = 0,
                                ) -> List[Tuple[bytes, bytes, PeriodKeyResult]]:
    """给一堆"可能原文"（例如题目里那个 dummy 函数的原始字节码），逐个试。

    返回 ``[(密钥, 命中的原文, 结果)]``。**只有当某条原文能让所有槽位约束一致时**
    才会被返回——这比"解出来是可打印的就当成功"严格得多。
    """
    out: List[Tuple[bytes, bytes, PeriodKeyResult]] = []
    for plain in plains:
        if not plain:
            continue
        res = recover_period_key(cipher, plain, period, offset=offset)
        if res is not None:
            out.append((res.key, plain, res))
    return out
