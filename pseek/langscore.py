"""自然语言打分（Ciphey 的 language checker / quipqiup 的 n-gram 打分思路）。

用途：古典密码破解、XOR 暴力枚举、以及判断"解出来的东西像不像人话"。
没有凭空编造的统计表——数据来源有两处，都是真实的：

1. 包内 ``data/english_words.txt``：Google 10k 英文词表的前 3000 个（按使用频率排序），
   用来做"词覆盖率"打分，并在载入时训练字母/二元组/三元组统计；
2. 可选 ``data/english_quadgrams.txt``：如果你自己放一份 quadgram 统计
   （例如 practicalcryptography.com 的 english_quadgrams.txt），会自动优先使用，
   打分更准。

另外支持中文（CJK 字符占比）与"可打印率"作为兜底。
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_WORDS_FILE = os.path.join(DATA_DIR, "english_words.txt")
_QUADGRAM_FILE = os.path.join(DATA_DIR, "english_quadgrams.txt")

_LETTERS = "abcdefghijklmnopqrstuvwxyz"
_LETTER_INDEX = {c: i for i, c in enumerate(_LETTERS)}

# 英语字母频率（百分比），用于卡方检验
ENGLISH_LETTER_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228,
    "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025,
    "m": 2.406, "n": 6.749, "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987,
    "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150,
    "y": 1.974, "z": 0.074,
}

# 常见二元组（真人手写的小表，只用于粗排）
COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te",
    "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng", "se", "ha", "as", "ou",
    "io", "le", "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea", "ra", "ce",
    "li", "ch", "ll", "be", "ma", "si", "om", "ur", "ca", "el", "ta", "la", "ns", "di",
    "fo", "ho", "pe", "ec", "pr", "no", "ct", "us", "ac", "ot", "il", "tr", "ly", "nc",
    "et", "ut", "ss", "so", "rs", "un", "lo", "wa", "ge", "ie", "wh", "ee", "wi", "em",
    "ad", "ol", "rt", "po", "we", "na", "ul", "ni", "ts", "mo", "ow", "pa", "im", "mi",
    "ai", "sh", "ir", "su", "id", "os", "iv", "ia", "am", "fi", "ci", "vi", "pl", "ig",
}


@dataclass
class LanguageScore:
    score: float            # 0~1
    kind: str               # english / chinese / printable / binary
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.kind} {self.score:.2f}" + (f" ({self.detail})" if self.detail else "")


class LanguageModel:
    """英文语言模型：词表 + 字母/二元/三元统计（可选 quadgram）。"""

    def __init__(self, words_file: str = _WORDS_FILE, quadgram_file: str = _QUADGRAM_FILE):
        self.words: List[str] = []
        self.word_rank: Dict[str, int] = {}
        self.unigram: Dict[str, float] = {}
        self.bigram: Dict[str, float] = {}
        self.trigram: Dict[str, float] = {}
        self.quadgram: Dict[str, float] = {}
        self.quadgram_floor: float = -10.0
        self._load_words(words_file)
        self._load_quadgrams(quadgram_file)

    # -- 载入 -------------------------------------------------------------
    def _load_words(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                raw = [line.strip().lower() for line in fh]
        except OSError:
            raw = ["the", "of", "and", "to", "in", "is", "that", "for", "it", "with"]
        self.words = [w for w in raw if w.isalpha()]
        self.word_rank = {w: i for i, w in enumerate(self.words)}
        # 用词表训练 n-gram（按频率排名加权：越靠前的词权重越高）
        for n, table in ((1, self.unigram), (2, self.bigram), (3, self.trigram)):
            counts: Dict[str, float] = {}
            total = 0.0
            for rank, word in enumerate(self.words):
                weight = 1.0 / math.log(rank + 2.2)           # Zipf 近似
                padded = "^" + word + "$"
                for i in range(len(padded) - n + 1):
                    gram = padded[i:i + n]
                    counts[gram] = counts.get(gram, 0.0) + weight
                    total += weight
            for gram, c in counts.items():
                table[gram] = math.log10(c / total) if total else -9.0
        self.unigram_floor = min(self.unigram.values()) - 1 if self.unigram else -9.0
        self.bigram_floor = min(self.bigram.values()) - 1 if self.bigram else -9.0
        self.trigram_floor = min(self.trigram.values()) - 1 if self.trigram else -9.0
        # 自适应标定：用一段标准英文与一段乱字母定出 ngram 分数的上下界，
        # 这样不管底层是 quadgram 还是词表训练的 tri/bi-gram，归一化尺度都一致。
        ref = ("the quick brown fox jumps over the lazy dog and it was a good day "
               "for all of them to read this message and think about it")
        noise = ("zqxjvbkpmwfhgtdrnyslcaoeiu zqxjvbkpmwfhgtdrnyslcaoeiu "
                 "qwertyuiopasdfghjklzxcvbnm qwertyuiopasdfghjklzxcvbnm")
        self.ngram_hi = self.ngram_score(ref)
        self.ngram_lo = self.ngram_score(noise)

    def _load_quadgrams(self, path: str) -> None:
        if not os.path.exists(path):
            return
        counts: Dict[str, float] = {}
        total = 0.0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    parts = line.replace(",", " ").split()
                    if len(parts) != 2:
                        continue
                    gram, num = parts[0].lower(), parts[1]
                    if len(gram) != 4 or not gram.isalpha():
                        continue
                    try:
                        value = float(num)
                    except ValueError:
                        continue
                    counts[gram] = value
                    total += value
        except OSError:
            return
        if not counts or total <= 0:
            return
        for gram, c in counts.items():
            self.quadgram[gram] = math.log10(c / total)
        self.quadgram_floor = min(self.quadgram.values()) - 1.5

    @property
    def has_quadgrams(self) -> bool:
        return bool(self.quadgram)

    # -- 打分 -------------------------------------------------------------
    def ngram_score(self, text: str) -> float:
        """n-gram 对数似然（每字符平均），越大越像英文。"""
        letters = re.sub(r"[^a-z]", "", text.lower())
        if len(letters) < 4:
            return -99.0
        if self.quadgram:
            padded = "^" + letters + "$"
            total = 0.0
            n = 0
            for i in range(len(padded) - 3):
                gram = padded[i:i + 4]
                total += self.quadgram.get(gram, self.quadgram_floor)
                n += 1
            return total / max(1, n)
        # 没有 quadgram 时用词表训练的 trigram/bigram 混合
        padded = "^" + letters + "$"
        total = 0.0
        n = 0
        for i in range(len(padded) - 2):
            gram = padded[i:i + 3]
            total += self.trigram.get(gram, self.trigram_floor)
            n += 1
        for i in range(len(padded) - 1):
            gram = padded[i:i + 2]
            total += 0.5 * self.bigram.get(gram, self.bigram_floor)
            n += 1
        return total / max(1, n)

    def ngram_score_letters(self, letters: str) -> float:
        """快速版：假定传入的已经是纯小写字母（爬山法里每轮都要打分，省掉正则）。"""
        if len(letters) < 4:
            return -99.0
        padded = "^" + letters + "$"
        total = 0.0
        n = 0
        if self.quadgram:
            for i in range(len(padded) - 3):
                total += self.quadgram.get(padded[i:i + 4], self.quadgram_floor)
                n += 1
        else:
            for i in range(len(padded) - 2):
                total += self.trigram.get(padded[i:i + 3], self.trigram_floor)
                n += 1
            for i in range(len(padded) - 1):
                total += 0.5 * self.bigram.get(padded[i:i + 2], self.bigram_floor)
                n += 1
        return total / max(1, n)

    def word_coverage(self, text: str) -> float:
        """词覆盖率（按词频排名加权）：真实英文句子会明显更高。"""
        tokens = re.findall(r"[a-zA-Z']+", text.lower())
        if not tokens:
            return 0.0
        hits = 0.0
        for token in tokens:
            token = token.strip("'")
            if not token:
                continue
            if token in self.word_rank:
                hits += 1.0 / math.log(self.word_rank[token] + 2.5)
            elif len(token) > 3:
                # 词形变化（-s/-ed/-ing）宽松匹配
                for suffix in ("s", "es", "ed", "ing", "ly", "d", "r"):
                    if token.endswith(suffix) and token[: -len(suffix)] in self.word_rank:
                        hits += 0.6 / math.log(self.word_rank[token[: -len(suffix)]] + 2.5)
                        break
        return hits / len(tokens)

    def chi_square(self, text: str) -> float:
        letters = [c for c in text.lower() if c in _LETTER_INDEX]
        if len(letters) < 8:
            return 1e9
        counts = {c: 0 for c in ENGLISH_LETTER_FREQ}
        for c in letters:
            counts[c] += 1
        total = len(letters)
        chi = 0.0
        for c, freq in ENGLISH_LETTER_FREQ.items():
            expected = total * freq / 100.0
            chi += (counts[c] - expected) ** 2 / expected
        return chi


_MODEL: Optional[LanguageModel] = None


def model() -> LanguageModel:
    global _MODEL
    if _MODEL is None:
        _MODEL = LanguageModel()
    return _MODEL


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    allowed = bytes(range(0x20, 0x7F)) + b"\t\n\r\f"
    return 1.0 - len(data[:65536].translate(None, allowed)) / min(len(data), 65536)


def cjk_ratio(text: str) -> float:
    if not text:
        return 0.0
    cjk = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff" or "\u3040" <= ch <= "\u30ff")
    return cjk / len(text)


def score_text(text: str, model_: Optional[LanguageModel] = None) -> LanguageScore:
    """给一段文本打分（0~1）。中文、英文、可打印兜底。"""
    if not text:
        return LanguageScore(0.0, "empty")
    m = model_ or model()
    cjk = cjk_ratio(text)
    if cjk > 0.3:
        return LanguageScore(min(1.0, 0.6 + cjk), "chinese", f"CJK={cjk:.2f}")
    ngram = m.ngram_score(text)
    coverage = m.word_coverage(text)
    chi = m.chi_square(text)
    # 用模型自带的上下界把 ngram 分数归一化到 0~1
    span = max(0.5, m.ngram_hi - m.ngram_lo)
    ngram_norm = max(0.0, min(1.0, (ngram - m.ngram_lo) / span))
    chi_norm = max(0.0, min(1.0, 1.0 - chi / 400.0))
    score = 0.5 * ngram_norm + 0.35 * min(1.0, coverage * 2.0) + 0.15 * chi_norm
    return LanguageScore(score, "english",
                         f"ngram={ngram:.2f} 词覆盖={coverage:.2f} chi2={chi:.0f}")


def score_bytes(data: bytes, model_: Optional[LanguageModel] = None) -> LanguageScore:
    # 先按 UTF-8 解（中文/日文文本的字节不是"可打印 ASCII"，不能一上来就判二进制）
    text: Optional[str] = None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None:
        cjk = cjk_ratio(text)
        if cjk > 0.15:
            return LanguageScore(min(1.0, 0.6 + cjk), "chinese", f"CJK={cjk:.2f}")
    ratio = printable_ratio(data)
    if ratio < 0.75:
        return LanguageScore(0.0, "binary", f"可打印率={ratio:.2f}")
    if text is None:
        text = data.decode("latin-1")
    result = score_text(text, model_)
    if ratio < 0.95:
        result = LanguageScore(result.score * ratio, result.kind,
                              result.detail + f" 可打印率={ratio:.2f}")
    return result


def rank_candidates(candidates: Sequence[Tuple[object, bytes]],
                    model_: Optional[LanguageModel] = None) -> List[Tuple[object, bytes, LanguageScore]]:
    m = model_ or model()
    out = [(label, data, score_bytes(data, m)) for label, data in candidates]
    out.sort(key=lambda item: -item[2].score)
    return out


def describe_model() -> str:
    m = model()
    return (f"词表 {len(m.words)} 词；"
            + ("quadgram 已载入" if m.has_quadgrams
               else "quadgram 未提供（用词表训练的 tri/bi-gram 代替；"
                    "可放 data/english_quadgrams.txt 提升准确度）"))
