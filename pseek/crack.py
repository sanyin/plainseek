"""古典密码自动破解（quipqiup / dcode / cryptography 教材那一套）。

* **凯撒 / 仿射**：直接枚举（26 / 312 种），用语言模型挑最好的；
* **维吉尼亚**：先用重合指数定密钥长度（Kasiski 的现代做法），逐列用卡方解凯撒，
  再逐列微调（每列试 26 个字母，用整段文本的语言分数择优）；
* **单表替换**：爬山法（Hill Climbing）+ 多次随机重启，打分 = n-gram + 词覆盖率；
* **栅栏 / 列置换**：小密钥空间直接枚举打分；
* **单字节 XOR**：交给 xoranalysis。

打分函数统一：语言模型分数 + flag 正则（命中直接满分）。
"""

from __future__ import annotations

import itertools
import random
import re
import string
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import langscore, oracles, xoranalysis

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase
_FREQ_ORDER = "etaoinshrdlucmfwypvbgkjqxz"


@dataclass
class CrackResult:
    kind: str
    params: str
    plaintext: bytes
    score: float
    note: str = ""

    def line(self) -> str:
        preview = self.plaintext[:72]
        try:
            text = preview.decode("utf-8", "replace").replace("\n", "\\n")
        except Exception:
            text = preview.hex(" ")
        return f"[{self.score:.2f}] {self.kind} {self.params}（{self.note}）→ {text}"


def _score(pt: bytes, model: langscore.LanguageModel) -> float:
    if not pt:
        return 0.0
    if oracles._FLAG_RE.search(pt):
        return 1.0
    try:
        text = pt.decode("utf-8")
    except UnicodeDecodeError:
        text = pt.decode("latin-1")
    return langscore.score_text(text, model).score


def _letters_only(text: str) -> str:
    return "".join(ch for ch in text if ch.isalpha())


def _letters_spaces_ratio(text: str) -> float:
    """"字母 + 空格"占比：古典密码文本应接近 1；base64/hex 明显偏低。"""
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isalpha() or ch == " ")
    return good / len(text)


# --------------------------------------------------------------------------
# 凯撒 / 仿射
# --------------------------------------------------------------------------

def caesar(text: str, shift: int, decode: bool = True) -> str:
    k = shift if not decode else -shift
    out = []
    for ch in text:
        if ch in _UPPER:
            out.append(_UPPER[(_UPPER.index(ch) + k) % 26])
        elif ch in _LOWER:
            out.append(_LOWER[(_LOWER.index(ch) + k) % 26])
        else:
            out.append(ch)
    return "".join(out)


def crack_caesar(data: bytes, model: Optional[langscore.LanguageModel] = None,
                 top: int = 5) -> List[CrackResult]:
    m = model or langscore.model()
    text = data.decode("latin-1")
    out = []
    for shift in range(26):
        pt = caesar(text, shift).encode("latin-1")
        out.append(CrackResult("凯撒", f"位移={shift}", pt, _score(pt, m), "枚举 26 种"))
    out.sort(key=lambda r: -r.score)
    return out[:top]


_AFFINE_A = [a for a in range(1, 26) if __import__("math").gcd(a, 26) == 1]


def crack_affine(data: bytes, model: Optional[langscore.LanguageModel] = None,
                 top: int = 5) -> List[CrackResult]:
    m = model or langscore.model()
    text = data.decode("latin-1")
    out = []
    for a in _AFFINE_A:
        inv = pow(a, -1, 26)
        for b in range(26):
            chars = []
            for ch in text:
                if ch in _UPPER:
                    chars.append(_UPPER[(inv * (_UPPER.index(ch) - b)) % 26])
                elif ch in _LOWER:
                    chars.append(_LOWER[(inv * (_LOWER.index(ch) - b)) % 26])
                else:
                    chars.append(ch)
            pt = "".join(chars).encode("latin-1")
            out.append(CrackResult("仿射", f"a={a},b={b}", pt, _score(pt, m), "枚举可逆组合"))
    out.sort(key=lambda r: -r.score)
    return out[:top]


# --------------------------------------------------------------------------
# 维吉尼亚
# --------------------------------------------------------------------------

def _column_text(letters: str, key_length: int, offset: int) -> str:
    return letters[offset::key_length]


def crack_vigenere(data: bytes, max_key_length: int = 16,
                   model: Optional[langscore.LanguageModel] = None,
                   top: int = 5) -> List[CrackResult]:
    m = model or langscore.model()
    text = data.decode("latin-1")
    letters = _letters_only(text).lower()
    if len(letters) < 80 or _letters_spaces_ratio(text) < 0.85:
        return []

    # 1) 用重合指数（IC）定密钥长度
    candidates: List[int] = []
    ic_scores: List[Tuple[int, float]] = []
    for klen in range(1, min(max_key_length, max(2, len(letters) // 8)) + 1):
        ics = []
        for i in range(klen):
            col = _column_text(letters, klen, i)
            if len(col) >= 2:
                ics.append(_ic(col))
        ic_scores.append((klen, sum(ics) / max(1, len(ics))))
    ic_scores.sort(key=lambda item: -item[1])
    candidates = [k for k, _ in ic_scores[:6]]
    for k in range(2, 9):
        if k not in candidates:
            candidates.append(k)

    out: List[CrackResult] = []
    for klen in candidates:
        # 2) 逐列用卡方解凯撒得到初始密钥
        key = []
        for i in range(klen):
            col = _column_text(letters, klen, i)
            best_shift, best = 0, 1e18
            for shift in range(26):
                shifted = "".join(_LOWER[(_LOWER.index(c) - shift) % 26] for c in col)
                chi = _chi_letters(shifted)
                if chi < best:
                    best, best_shift = chi, shift
            key.append(best_shift)
        # 3) 逐列微调：每列试 26 个字母，用整段文本的语言分数择优
        best_key = list(key)
        best_score = _score(_vig_decrypt(text, best_key).encode("latin-1"), m)
        improved = True
        rounds = 0
        while improved and rounds < 3:
            improved = False
            rounds += 1
            for i in range(klen):
                for cand in range(26):
                    if cand == best_key[i]:
                        continue
                    trial = list(best_key)
                    trial[i] = cand
                    s = _score(_vig_decrypt(text, trial).encode("latin-1"), m)
                    if s > best_score + 1e-6:
                        best_score, best_key, improved = s, trial, True
        key_str = "".join(_LOWER[k] for k in best_key)
        pt = _vig_decrypt(text, best_key).encode("latin-1")
        out.append(CrackResult("维吉尼亚", f"密钥={key_str}",
                               pt, best_score, f"IC 定长 {klen} + 逐列卡方/微调"))
    out.sort(key=lambda r: -r.score)
    return out[:top]


def _ic(text: str) -> float:
    if len(text) < 2:
        return 0.0
    counts = [0] * 26
    for ch in text:
        if ch in _LOWER:
            counts[_LOWER.index(ch)] += 1
    n = sum(counts)
    if n < 2:
        return 0.0
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def _chi_letters(text: str) -> float:
    counts = [0] * 26
    for ch in text:
        if ch in _LOWER:
            counts[_LOWER.index(ch)] += 1
    n = sum(counts)
    if n == 0:
        return 1e18
    chi = 0.0
    for i, pct in enumerate(langscore.ENGLISH_LETTER_FREQ.values()):
        expected = n * pct / 100.0
        chi += (counts[i] - expected) ** 2 / max(0.5, expected)
    return chi


def _vig_decrypt(text: str, key: Sequence[int]) -> str:
    out = []
    idx = 0
    for ch in text:
        if ch in _LOWER:
            out.append(_LOWER[(_LOWER.index(ch) - key[idx % len(key)]) % 26])
            idx += 1
        elif ch in _UPPER:
            out.append(_UPPER[(_UPPER.index(ch) - key[idx % len(key)]) % 26])
            idx += 1
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------
# 单表替换（爬山法）
# --------------------------------------------------------------------------

def _apply_mapping(text: str, mapping: Dict[str, str]) -> str:
    return "".join(mapping.get(ch, ch) for ch in text)


def crack_substitution(data: bytes, restarts: int = 5, iterations: int = 30000,
                       model: Optional[langscore.LanguageModel] = None,
                       top: int = 3, sample_letters: int = 600) -> List[CrackResult]:
    """单表替换：爬山法 + 随机重启。

    为了跑得动，打分只在**前若干字母**上做（爬山只需要一个稳定可比的分数），
    最后再用完整文本重新打分排名。映射用 ``str.translate`` 应用（C 层速度）。
    """
    m = model or langscore.model()
    text = data.decode("latin-1")
    letters = _letters_only(text).lower()
    if len(letters) < 40:
        return []
    sample = letters[:sample_letters]
    rng = random.Random(20260101)
    results: Dict[str, CrackResult] = {}

    def apply_and_score(mapping: Dict[str, str], target: str) -> float:
        table = str.maketrans({c: mapping.get(c, c) for c in _LOWER})
        return m.ngram_score_letters(target.translate(table))

    for restart in range(max(1, restarts)):
        if restart == 0:
            freq = sorted(set(sample), key=lambda c: -sample.count(c))
            mapping = {c: _FREQ_ORDER[i] for i, c in enumerate(freq) if i < 26}
            for c in _LOWER:
                mapping.setdefault(c, c)
        else:
            shuffled = list(_LOWER)
            rng.shuffle(shuffled)
            mapping = dict(zip(_LOWER, shuffled))
        current = apply_and_score(mapping, sample)
        for _ in range(max(200, iterations)):
            a, b = rng.sample(_LOWER, 2)
            mapping[a], mapping[b] = mapping[b], mapping[a]
            score = apply_and_score(mapping, sample)
            if score >= current:
                current = score
            else:
                mapping[a], mapping[b] = mapping[b], mapping[a]
        key = "".join(mapping.get(c, c) for c in _LOWER)
        pt = _apply_mapping(text, mapping).encode("latin-1")
        full = _score(pt, m)
        old = results.get(key)
        if old is None or full > old.score:
            results[key] = CrackResult("单表替换", f"映射={key}", pt, full,
                                       "爬山法（字母频率初值 + 随机重启）")
    out = sorted(results.values(), key=lambda r: -r.score)
    return out[:top]


# --------------------------------------------------------------------------
# 置换类
# --------------------------------------------------------------------------

def railfence_decrypt(text: str, rails: int) -> str:
    if rails < 2:
        return text
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    n = len(text)
    idx = [pattern[i % len(pattern)] for i in range(n)]
    counts = [idx.count(r) for r in range(rails)]
    chunks, pos = [], 0
    for c in counts:
        chunks.append(list(text[pos:pos + c]))
        pos += c
    out = []
    cursors = [0] * rails
    for r in idx:
        out.append(chunks[r][cursors[r]])
        cursors[r] += 1
    return "".join(out)


def crack_railfence(data: bytes, max_rails: int = 10,
                    model: Optional[langscore.LanguageModel] = None,
                    top: int = 5) -> List[CrackResult]:
    m = model or langscore.model()
    text = data.decode("latin-1")
    out = []
    for rails in range(2, max_rails + 1):
        pt = railfence_decrypt(text, rails).encode("latin-1")
        out.append(CrackResult("栅栏密码", f"栏数={rails}", pt, _score(pt, m), "枚举栏数"))
    out.sort(key=lambda r: -r.score)
    return out[:top]


def columnar_decrypt(text: str, order: Sequence[int]) -> str:
    """order[i] = 第 i 个密文列在原明文中的位置。"""
    n = len(text)
    cols = len(order)
    rows = (n + cols - 1) // cols
    short = rows * cols - n
    lengths = [rows - 1 if i >= cols - short else rows for i in range(cols)]
    chunks, pos = [], 0
    for length in lengths:
        chunks.append(list(text[pos:pos + length]))
        pos += length
    out = []
    for r in range(rows):
        for i in range(cols):
            if r < len(chunks[i]):
                out.append(chunks[i][r])
    return "".join(out)


def crack_columnar(data: bytes, max_columns: int = 6,
                   model: Optional[langscore.LanguageModel] = None,
                   top: int = 5) -> List[CrackResult]:
    m = model or langscore.model()
    text = data.decode("latin-1")
    out: List[CrackResult] = []
    for cols in range(2, max_columns + 1):
        if len(text) < cols * 2:
            continue
        for perm in itertools.permutations(range(cols)):
            pt = columnar_decrypt(text, perm).encode("latin-1")
            score = _score(pt, m)
            out.append(CrackResult("列置换", f"列数={cols} 顺序={perm}", pt, score, "枚举列排列"))
    out.sort(key=lambda r: -r.score)
    return out[:top]


# --------------------------------------------------------------------------
# 总入口
# --------------------------------------------------------------------------

def crack_all(data: bytes, model: Optional[langscore.LanguageModel] = None,
              deep: bool = False, top: int = 5) -> List[CrackResult]:
    m = model or langscore.model()
    text = data.decode("latin-1", "ignore")
    letters = _letters_only(text)
    textness = _letters_spaces_ratio(text)
    out: List[CrackResult] = []
    out += crack_caesar(data, m, top=2)
    out += crack_affine(data, m, top=2)
    if len(letters) >= 24 and textness > 0.8:
        out += crack_railfence(data, 10 if deep else 8, m, top=2)
    if len(letters) >= 80 and textness > 0.85:
        out += crack_vigenere(data, 20 if deep else 12, m, top=3)
    if len(letters) >= 60 and textness > 0.9:
        out += crack_substitution(data, restarts=6 if deep else 3, model=m, top=2)
    if deep and len(text) <= 512 and textness > 0.8:
        out += crack_columnar(data, 6, m, top=2)
    for r in xoranalysis.single_byte_bruteforce(data, cap=4096)[:2]:
        out.append(CrackResult("单字节 XOR", f"密钥={r.key.hex()}", r.plaintext, r.score,
                               "枚举 256 种"))
    out.sort(key=lambda r: -r.score)
    return out[: max(top, 5)]


def describe(data: bytes) -> str:
    results = crack_all(data)
    if not results:
        return "没有可用的破解结果（文本太短或不是字母文本）"
    lines = [r.line() for r in results]
    return "\n".join(lines)
