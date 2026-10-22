"""逐字节线性公式反推 —— "已知开头几个字符 + 一串目标字节"就能还原全文。

为什么需要它
------------
字节级混淆题里最常见的校验就是这种形状：

    target[i] = ROL((a * f[i] + b * i + c) & 0xFF, r) ^ k

（``f[i]`` 是 flag 第 i 个字节，``a/b/c/r/k`` 是出题人随手写的常量）
Python 字节码、C 代码、Go 代码里都是这个套路，人眼看得懂但手算很烦。

本模块用**已知前缀（crib）**把公式解出来：
未知量只有 a/b/c（各 1 字节）+ 旋转 r(0-7) + 异或 k(1 字节)。
枚举 (r, k) 后，用前两个已知字节就能解出 b、c，再用第三个字节筛掉，
最后用整个前缀验证；一旦成立就反过来算出全部字节，并用语言模型/flag 判据排序。

配套 ``derive_blobs()``：目标字节常常不是直接给出的，而是"两团数据异或再异或一个常量"
得来的（R10 就是 ``A ^ B ^ 90``）。所以这里会把十六进制常量两两异或、
再各自与"小整数常量 / 单字节值"异或，作为候选目标。
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import langscore, oracles


def _rol(b: int, r: int) -> int:
    r &= 7
    return ((b << r) | (b >> (8 - r))) & 0xFF if r else b & 0xFF


def _ror(b: int, r: int) -> int:
    r &= 7
    return ((b >> r) | (b << (8 - r))) & 0xFF if r else b & 0xFF


@dataclass
class Formula:
    a: int = 1
    b: int = 0
    c: int = 0
    r: int = 0
    k: int = 0
    offset: int = 0

    def forward(self, plain: bytes, offset: int = 0) -> bytes:
        out = bytearray()
        for i, ch in enumerate(plain):
            idx = i + offset
            v = (self.a * ch + self.b * idx + self.c) & 0xFF
            out.append(_rol(v, self.r) ^ self.k)
        return bytes(out)

    def invert(self, target: bytes, offset: int = 0) -> bytes:
        """按公式反推明文。``a`` 必须是奇数（模 256 可逆），否则返回空串。"""
        if self.a % 2 == 0:
            return b""
        inv = pow(self.a, -1, 256)
        out = bytearray()
        for i, t in enumerate(target):
            idx = i + offset
            v = _ror(t ^ self.k, self.r)
            diff = (v - self.c - self.b * idx) % 256
            out.append((diff * inv) & 0xFF)
        return bytes(out)

    def __str__(self) -> str:
        text = f"target[i] = ({self.a}*f[i] + {self.b}*i + {self.c}) & 0xFF"
        if self.r:
            text += f" 再循环左移 {self.r}"
        if self.k:
            text += f" 再异或 {self.k}"
        if self.offset:
            text += f"  (i 从 {self.offset} 起)"
        return text


@dataclass
class FormulaHit:
    formula: Formula
    target: bytes = b""
    plaintext: bytes = b""
    score: float = 0.0
    note: str = ""
    dupes: int = 0          # 与它解出同一明文、但参数不同的等价解个数

    def line(self) -> str:
        try:
            text = self.plaintext.decode("utf-8", "replace")
        except Exception:
            text = self.plaintext.hex(" ")
        tail = f"  （另有 {self.dupes} 组等价参数）" if self.dupes else ""
        return f"[{self.score:.2f}] {self.formula}  →  {text[:96]}{tail}"


def _solve_a(f0: int, f1: int, f2: int, v0: int, v1: int, t2: int, r: int, k: int,
             offset: int) -> List[int]:
    """用前三个已知字节直接解出候选 ``a``（解同余方程，而不是枚举 128 个奇数）。

    推导（i0=0, i1=1, i2=2，crib 是连续的）：
        c = v0 - a*f0
        b = (v1 - v0) - a*(f1 - f0)
        v2 = a*f2 + 2b + c = a*(f2 - 2f1 + f0) + 2*v1 - v0
    再套上循环移位与异或：``ROR(t2 ^ k, r) == (a*K1 + K2) & 0xFF``，
    也就是 ``a*K1 ≡ RHS (mod 256)`` —— 一次 gcd 就能解出全部候选 a。
    """
    import math
    target_v2 = _ror(t2 ^ k, r)
    k1 = (f2 - 2 * f1 + f0) % 256
    k2 = (2 * v1 - v0) % 256
    rhs = (target_v2 - k2) % 256
    if k1 == 0:
        return [] if rhs else [a for a in range(1, 256, 2)]
    g = math.gcd(k1, 256)
    if rhs % g:
        return []
    m = 256 // g
    base = (rhs // g) * pow((k1 // g) % m, -1, m) % m
    out = []
    for t in range(g):
        a = base + t * m
        if a % 2 == 1:                      # a 必须为奇数（模 256 可逆）
            out.append(a)
    return out


def solve_linear(target: bytes, crib: bytes, offset: int = 0,
                 rotations: Sequence[int] = (0,), xors: Sequence[int] = (0,),
                 ) -> List[Formula]:
    """用 crib 解出线性公式：target[offset+i] = ROL((a*f[i] + b*(offset+i) + c)&0xff, r) ^ k。

    每个 (r, k) 组合只需要一次同余求解就能定出候选 a，再用剩余已知字节验证，
    因此可以把 (r, k) 全空间扫完也不用几毫秒（纯暴力枚举 a 会慢上千倍）。
    """
    if len(crib) < 3 or len(target) < offset + len(crib):
        return []
    hits: List[Formula] = []
    f0, f1, f2 = crib[0], crib[1], crib[2]
    rest = crib[3:]
    base_index = offset + 3
    for r in rotations:
        for k in xors:
            v0 = _ror(target[offset] ^ k, r)
            v1 = _ror(target[offset + 1] ^ k, r)
            for a in _solve_a(f0, f1, f2, v0, v1, target[offset + 2], r, k, offset):
                b = ((v1 - v0) - a * (f1 - f0)) & 0xFF
                c = (v0 - a * f0 - b * offset) & 0xFF
                ok = True
                idx = base_index
                for ch in rest:
                    v = (a * ch + b * idx + c) & 0xFF
                    if (_rol(v, r) ^ k) != target[idx]:
                        ok = False
                        break
                    idx += 1
                if ok:
                    hits.append(Formula(a=a, b=b, c=c, r=r, k=k, offset=offset))
    return hits


def search_phases(target: bytes, crib: bytes, offset: int = 0,
                  budget_seconds: float = 8.0) -> List[Formula]:
    """分阶段搜索 (r, k)：

    1. ``r=0, k=0``：最常见的情况（纯线性 + 索引项），几乎瞬间出结果；
    2. "十字"范围：``(r, 0)`` 与 ``(0, k)``，覆盖"只加循环移位"或"只加异或"；
    3. 完整叉积：只有前面都没结果、且调用方愿意给时间才做。
    """
    import time
    deadline = time.time() + budget_seconds
    hits = solve_linear(target, crib, offset, rotations=(0,), xors=(0,))
    if hits:
        return hits
    hits = solve_linear(target, crib, offset,
                        rotations=tuple(range(8)), xors=(0,))
    hits += solve_linear(target, crib, offset, rotations=(0,), xors=tuple(range(1, 256)))
    if hits:
        return hits
    if time.time() > deadline:
        return []
    return solve_linear(target, crib, offset, rotations=tuple(range(1, 8)),
                        xors=tuple(range(1, 256)))


def derive_blobs(hex_blobs: Sequence[bytes], ints: Sequence[int] = (),
                 include_all_bytes: bool = True, limit: int = 4096) -> List[Tuple[str, bytes]]:
    """由"十六进制常量 + 小整数常量"派生出候选目标字节串。

    * 两两异或（``A ^ B``）
    * 再与每一个小整数常量异或（``A ^ B ^ 90`` 这种）
    * 如果候选不多，再与 0..255 每个单字节值异或一遍（兜底）
    """
    out: List[Tuple[str, bytes]] = []
    seen: Set[bytes] = set()

    def add(note: str, blob: bytes) -> None:
        if blob and blob not in seen and len(blob) >= 6:
            seen.add(blob)
            out.append((note, blob))

    for i, blob in enumerate(hex_blobs):
        add(f"常量#{i}", blob)
    for i, j in itertools.combinations(range(len(hex_blobs)), 2):
        add(f"常量#{i}^#{j}", bytes(x ^ y for x, y in zip(hex_blobs[i], hex_blobs[j])))
    base = list(out)
    keys: List[int] = [v & 0xFF for v in ints if 0 < (v & 0xFF) < 256]
    if include_all_bytes and len(base) <= 8:
        keys = sorted(set(keys) | set(range(1, 256)))
    for note, blob in base:
        for k in keys:
            add(f"{note}^{k}", bytes(x ^ k for x in blob))
    return out[:limit]


_CRIB_RE = re.compile(r"([A-Za-z][A-Za-z0-9_]{1,20})\{")


def guess_crib(strings: Sequence[str], extra: Sequence[bytes] = ()) -> Optional[bytes]:
    """从字符串常量里猜 flag 前缀（形如 ``XJUSEC{``、``flag{``）。"""
    for text in strings:
        m = _CRIB_RE.search(text or "")
        if m:
            return (m.group(1) + "{").encode()
    for item in extra:
        m = _CRIB_RE.search(item.decode("latin-1", "replace"))
        if m:
            return (m.group(1) + "{").encode()
    return None


def solve_blob(target: bytes, crib: bytes, top: int = 5,
               offset: int = 0, budget_seconds: float = 8.0) -> List[FormulaHit]:
    """对一个候选目标字节串解公式并还原全文，按可信度排序。"""
    hits: List[FormulaHit] = []
    for formula in search_phases(target, crib, offset=offset, budget_seconds=budget_seconds):
        plain = formula.invert(target, offset=offset)
        if not plain:
            continue
        try:
            text = plain.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if not _looks_like_flag_text(plain, crib):
            continue
        score = langscore.score_text(text).score
        verdicts = oracles.evaluate(plain)
        if verdicts:
            score = max(score, verdicts[0].score)
        # crib 是"外部给定/从附件自身猜出"的已知前缀，完整命中且闭合花括号 → 强证据
        if plain.startswith(crib) and plain.endswith(b"}") and len(plain) > len(crib) + 2:
            score = max(score, 0.95)
        hits.append(FormulaHit(formula, target, plain, score,
                               str(verdicts[0]) if verdicts else "crib 前缀 + 闭合花括号"))
    hits.sort(key=lambda h: -h.score)
    return [h for _, h in _dedup([(str(h.formula), h) for h in hits])][:top]


def _dedup(entries: List[Tuple[str, FormulaHit]]) -> List[Tuple[str, FormulaHit]]:
    """同一个明文可能对应很多组等价参数（目标字节被小整数异或"吸收"进公式的 k，
    或 ``c`` 与 ``k`` 恰好互补）。人只需要看一条，其余只在 dupes 里计数。

    保留时优先"派生步骤最少"的那条（note 里 ``^`` 最少），便于人复述。
    """
    uniq: List[Tuple[str, FormulaHit]] = []
    index: Dict[bytes, int] = {}
    for note, hit in entries:
        key = hit.plaintext
        if key in index:
            pos = index[key]
            keep_note, keep = uniq[pos]
            keep.dupes += 1
            if note.count("^") < keep_note.count("^"):
                hit.dupes = keep.dupes
                uniq[pos] = (note, hit)
            continue
        index[key] = len(uniq)
        uniq.append((note, hit))
    return uniq


def _looks_like_flag_text(plain: bytes, crib: bytes) -> bool:
    if not plain.startswith(crib):
        return False
    body = plain[len(crib):]
    if not body:
        return False
    printable = sum(1 for b in body if 32 <= b < 127) / len(body)
    return printable > 0.9


def crack(target: bytes, crib: bytes, offset: int = 0,
          budget_seconds: float = 8.0) -> List[FormulaHit]:
    return solve_blob(target, crib, offset=offset, budget_seconds=budget_seconds)


def crack_pyc_constants(hex_blobs: Sequence[bytes], strings: Sequence[str],
                        ints: Sequence[int] = (), crib: Optional[bytes] = None,
                        top: int = 5, budget_seconds: float = 30.0) -> List[Tuple[str, FormulaHit]]:
    """.pyc 场景一站式：派生候选目标 → 猜 crib → 分阶段解公式。

    先用"低成本阶段"扫**所有**候选目标（r=0,k=0），没结果再对少量候选放宽到
    循环移位/异或，避免候选一多就跑到天荒地老。
    """
    import time
    if crib is None:
        crib = guess_crib(strings)
    if not crib:
        return []
    deadline = time.time() + budget_seconds
    blobs = derive_blobs(hex_blobs, ints)
    found: List[Tuple[str, FormulaHit]] = []
    for note, blob in blobs:
        for hit in solve_blob(blob, crib, top=1, budget_seconds=0.5):
            found.append((note, hit))
    if not found:
        # 放宽：只挑最可能的少数候选做"十字 + 完整叉积"
        priority = [item for item in blobs if "^" in item[0]][:48] or blobs[:16]
        for note, blob in priority:
            if time.time() > deadline:
                break
            for hit in solve_blob(blob, crib, top=1, budget_seconds=6.0):
                found.append((note, hit))
    found.sort(key=lambda item: -item[1].score)
    return _dedup(found)[:top]
