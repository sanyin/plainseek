"""flag 片段收集与拼接（逆向题里"flag 被拆成几段、各段用不同方式存"这一类）。

这类题的共同点：flag 不是一整串，而是被拆成若干段，分别用明文 / hex / base64 /
base32 / 反转 等方式藏在程序里，甚至顺序也是乱的。人肉翻 strings 很累，但这件事
完全可以自动化：

1. **收集**：在数据里找所有"能还原成 flag 字符集文本"的片段（明文片段、hex 解码、
   base64 解码、base32 解码、反转）；
2. **拼接**：以含 ``{`` 的片段为起点，不断把其它片段接到末尾（也支持**重叠拼接**），
   中间状态必须保持"像 flag"（只有一个 ``{``、``}`` 只能在结尾、字符集合法），
   拼到 ``}`` 结尾且整体匹配 flag 形态就认为找到了。

真实投稿题 R01 就靠这一步拼出来：
``XJUSEC{``（明文） + ``the_firs``（hex） + ``t_step_is_the_hardest}``（base64）
= ``XJUSEC{the_first_step_is_the_hardest}``。
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import oracles

_FLAG_CHARS = re.compile(rb"[A-Za-z0-9_{}\-!@#$%^&*()+=:;,.?/\[\]]+")
_CONTENT_CHARS = re.compile(rb"[A-Za-z0-9_{}\-!@#$%^&*()+=:;,.?/\[\]]+")
_FLAG_SHAPE = re.compile(rb"[A-Za-z0-9_]{2,24}\{[ -~]{4,160}\}")
_HAS_WORD = re.compile(rb"[a-z_]{3,}")


@dataclass
class Fragment:
    kind: str              # raw / hex / base64 / base32 / reversed
    text: bytes            # 还原后的文本
    encoded: bytes         # 原始形态（报告用）
    offset: int = -1

    def __str__(self) -> str:
        enc = self.encoded if len(self.encoded) <= 40 else self.encoded[:37] + b"..."
        return f"{self.kind:8s} @{self.offset:<8d} {self.text!r}  (原始 {enc!r})"


# --------------------------------------------------------------------------
# 收集
# --------------------------------------------------------------------------

def _flagish(text: bytes, min_len: int = 3, max_len: int = 80) -> bool:
    if not (min_len <= len(text) <= max_len):
        return False
    if not _FLAG_CHARS.fullmatch(text):
        return False
    # 至少要有一点"内容感"：有小写字母/下划线，或者含大括号（前缀段）
    return bool(_HAS_WORD.search(text) or b"{" in text or b"}" in text)


def collect_fragments(blob: bytes, min_len: int = 3, max_len: int = 80,
                      limit: int = 4000) -> List[Fragment]:
    """把数据里"可能是 flag 片段"的东西全捞出来（明文 / hex / base64 / base32 / 反转）。"""
    out: List[Fragment] = []
    seen: Set[bytes] = set()

    def add(kind: str, text: bytes, encoded: bytes, offset: int) -> None:
        if text in seen or not _flagish(text, min_len, max_len):
            return
        seen.add(text)
        out.append(Fragment(kind, text, encoded, offset))

    scan = blob[: 32 << 20]

    # 1) 明文片段
    for m in re.finditer(rb"[\x20-\x7e]{3,400}", scan):
        chunk = m.group(0)
        for sub in _FLAG_CHARS.finditer(chunk):
            add("raw", sub.group(0), sub.group(0), m.start() + sub.start())

    # 2) hex
    for m in re.finditer(rb"[0-9a-fA-F]{8,200}", scan):
        token = m.group(0)
        if len(token) % 2:
            continue
        try:
            decoded = binascii.unhexlify(token)
        except Exception:
            continue
        add("hex", decoded, token, m.start())

    # 3) base64 / base64url
    for pattern, kind in ((rb"[A-Za-z0-9+/]{8,200}={0,2}", "base64"),
                          (rb"[A-Za-z0-9_-]{12,200}={0,2}", "base64url")):
        for m in re.finditer(pattern, scan):
            token = m.group(0)
            try:
                if kind == "base64":
                    decoded = base64.b64decode(token + b"=" * ((-len(token)) % 4), validate=True)
                else:
                    decoded = base64.urlsafe_b64decode(token + b"=" * ((-len(token)) % 4))
            except Exception:
                continue
            add(kind, decoded, token, m.start())

    # 4) base32
    for m in re.finditer(rb"[A-Z2-7]{16,200}={0,6}", scan):
        token = m.group(0)
        try:
            decoded = base64.b32decode(token + b"=" * ((-len(token)) % 8))
        except Exception:
            continue
        add("base32", decoded, token, m.start())

    # 5) 反转（有些段是倒着存的）
    for frag in list(out):
        if frag.kind == "raw":
            add("reversed", frag.text[::-1], frag.encoded[::-1], frag.offset)

    out.sort(key=lambda f: (-_frag_score(f), -len(f.text), f.offset))
    return out[:limit]

# --------------------------------------------------------------------------
# 拼接
# --------------------------------------------------------------------------

def _frag_score(frag: Fragment) -> float:
    """给片段打分：越像"flag 的一段"分越高。

    要点：
    * **hex/base64/base32 片段加权**——它们是出题人"刻意编码"的那几段；
      明文片段与它们同分时会被无关的短串（如 ``l_ns``）挤到后面；
    * 把 ``ABCDEFGHIJKLMNOP…`` 这种字符表噪声按连续段长度扣分。
    """
    from . import recover
    score = 0.0
    if frag.kind in ("hex", "base64", "base64url", "base32"):
        score += 0.6
    if frag.kind == "reversed":
        score -= 0.5
    if b"{" in frag.text or b"}" in frag.text:
        score += 3.0
    if _HAS_WORD.search(frag.text):
        score += 2.0
    if b"_" in frag.text:
        score += 1.0
    if 4 <= len(frag.text) <= 40:
        score += 1.0
    run = recover.longest_ordered_run(frag.text)
    score -= min(8.0, max(0, run - 3))
    return score


def _overlap_merge(left: bytes, right: bytes, min_overlap: int = 3) -> Optional[bytes]:
    """把 right 与 left 的尾部重叠拼起来（片段之间可能有重叠）。"""
    top = min(len(left), len(right))
    for k in range(top, min_overlap - 1, -1):
        if left[-k:] == right[:k]:
            return left + right[k:]
    return None


def _plausible_flag(text: bytes) -> bool:
    """拼完之后的"内容质量"检查。

    光有 ``XJUSEC{...}`` 这种形状不算数——它可能只是用法说明里的占位符
    （R10 的 .pyc 里就有 ``check.pyc <flag>``、``XJUSEC{...}`` 这类文本），
    也可能是二进制数据的噪声碰巧凑出来的。

    所以三条硬要求（都是从投稿包 12 道真题的真实 flag 反推出来的）：
    1. **前缀**必须是 ``[A-Za-z][A-Za-z0-9]{2,23}`` —— 不含下划线、至少 3 个字符。
       实测里的合法前缀是 ``XJUSEC``/``flag``/``CTF``；而噪声凑出来的
       ``jc_{...}``（前缀里带下划线、只有 2 个字符）一律拒掉；
    2. **正文**里至少有 4 个字母/数字/下划线，且含真正的字母；
    3. **正文**只允许 ``[A-Za-z0-9_]``（12 道真题的正文全部满足），
       出现 ``&``、``?``、控制字符之类的一律判为噪声。
    """
    m = re.match(rb"([A-Za-z][A-Za-z0-9]{2,23})\{([ -~]*)\}$", text)
    if not m:
        return False
    content = m.group(2)
    if len(content) < 4:
        return False
    if not re.fullmatch(rb"[A-Za-z0-9_]*", content):
        return False
    alnum = sum(1 for c in content if chr(c).isalnum() or c == 0x5F)
    return alnum >= 4 and any(chr(c).isalpha() for c in content)


def flag_quality(flag: bytes) -> float:
    """给一个"看起来像 flag"的串打质量分（0~1），给上层决定要不要当成功。

    为什么要单独一个函数：片段拼接、公式反推这类"从数据里凑出来的"结果，
    它们的强判据（命中前缀 + 闭合花括号）**在噪声上也成立**——实测中
    PNG 二进制里就凑出过 ``jc_{8_&vfo9?_uL_}``。所以调用方拿到 0.95 的
    "形状分"之后，还要乘上这个质量分再决定是否算成功。
    """
    m = re.match(rb"([A-Za-z][A-Za-z0-9]{2,23})\{(.*)\}$", flag)
    if not m:
        return 0.0
    content = m.group(2)
    if len(content) < 4 or not re.fullmatch(rb"[A-Za-z0-9_]*", content):
        return 0.2 if content else 0.0
    from . import langscore
    text = content.decode("latin-1").replace("_", " ")
    lang = langscore.score_text(text).score
    # 词感分只当"辅助"：真 flag 里也有 leet 化的（strcmp_1s_n0t_3n0ugh 只有 0.48），
    # 所以下限给 0.6，只要不是明显的乱码就能通过。
    return max(0.6, lang)


def _valid_partial(text: bytes, max_len: int) -> bool:
    if len(text) > max_len:
        return False
    if not _FLAG_CHARS.fullmatch(text):
        return False
    if text.count(b"{") > 1 or text.count(b"}") > 1:
        return False
    if b"}" in text and not text.endswith(b"}"):
        return False
    if b"{" in text and text.index(b"{") > 32:
        return False
    return True


def _assembly_score(flag: bytes, path: Sequence[Fragment]) -> float:
    """给一条拼接结果打分：正文越像"有意义的英文词组"越好。

    这一步很关键——噪声片段（如 ``l_ns``）也能拼出"形状合法"的串，
    但正文词覆盖率低；真实 flag 的正文（``the_first_step_is_the_hardest``）
    词覆盖率高。用语言模型排序比"谁先被搜到"靠谱得多。
    """
    from . import langscore
    m = re.search(rb"\{([ -~]*)\}", flag)
    content = m.group(1) if m else flag
    text = content.decode("latin-1").replace("_", " ").replace("-", " ")
    base = langscore.score_text(text).score
    kinds = {f.kind for f in path}
    if len(kinds) >= 2:
        base += 0.2                      # 多段用不同存储方式 → 更可能是出题人的设计
    if "reversed" in kinds:
        base -= 0.25
    if len(content) >= 12:
        base += 0.1
    return base


def reassemble_flags(fragments: Sequence[Fragment], crib: Optional[bytes] = None,
                     max_parts: int = 6, max_len: int = 180, budget: int = 400000,
                     limit: int = 12, try_overlap: bool = True,
                     collect_limit: int = 400,
                     window: Optional[int] = 8192) -> List[Tuple[bytes, List[Fragment]]]:
    """把片段拼成 flag。返回 [(flag, 用到的片段)]，按"像不像真 flag"排序。

    先用**局部窗口**：flag 的各段通常存在相近位置（同一段 .rodata 里），
    只在"含 ``{`` 的片段"附近 ±window 字节内取候选池；
    局部拼不出来再退回全文件搜索，避免被 ELF 符号名之类的全局噪声淹没。
    """
    if crib:
        starts = [f for f in fragments if f.text.startswith(crib) or crib in f.text]
    else:
        starts = [f for f in fragments if b"{" in f.text]

    def build_pool(radius: Optional[int]) -> List[Fragment]:
        if radius is None:
            candidates = list(fragments)
        else:
            candidates = [f for f in fragments
                          if any(abs(f.offset - a.offset) <= radius for a in starts)]
        pool: List[Fragment] = []
        seen: Set[bytes] = set()
        for frag in sorted(candidates, key=lambda f: (-_frag_score(f), -len(f.text))):
            if frag.text in seen:
                continue
            seen.add(frag.text)
            pool.append(frag)
            if len(pool) >= 600:
                break
        return pool

    def run(pool: List[Fragment]) -> List[Tuple[bytes, List[Fragment]]]:
        found: List[Tuple[bytes, List[Fragment]]] = []
        visited: Set[bytes] = set()
        nodes = [0]

        def dfs(text: bytes, used: Set[bytes], path: List[Fragment], depth: int) -> None:
            if nodes[0] > budget or len(found) >= collect_limit:
                return
            nodes[0] += 1
            if text.endswith(b"}") and b"{" in text and len(text) >= 8:
                if _plausible_flag(text) and (
                        _FLAG_SHAPE.fullmatch(text)
                        or (crib and text.startswith(crib) and b"}" in text)):
                    found.append((text, path))
                return
            if depth >= max_parts:
                return
            for frag in pool:
                if frag.text in used:
                    continue
                if nodes[0] > budget:
                    return
                candidates = [text + frag.text]
                if try_overlap:
                    merged = _overlap_merge(text, frag.text)
                    if merged:
                        candidates.append(merged)
                for cand in candidates:
                    if cand == text or not _valid_partial(cand, max_len):
                        continue
                    if cand in visited:
                        continue
                    visited.add(cand)
                    dfs(cand, used | {frag.text}, path + [frag], depth + 1)

        for start in starts[:60]:
            if nodes[0] > budget or len(found) >= collect_limit:
                break
            dfs(start.text, {start.text}, [start], 1)
        return found

    results: List[Tuple[bytes, List[Fragment]]] = []
    for radius in ((window,) if window else ()) + (None,):
        pool = build_pool(radius)
        if not pool:
            continue
        results = run(pool)
        if results:
            break

    # 去重 + 按"正文像不像有意义的内容"排序
    uniq: Dict[bytes, List[Fragment]] = {}
    for flag, path in results:
        uniq.setdefault(flag, path)
    ranked = sorted(uniq.items(),
                    key=lambda kv: (-_assembly_score(kv[0], kv[1]), -len(kv[0])))
    return ranked[:limit]


def solve(blob: bytes, crib: Optional[bytes] = None, min_len: int = 3,
          max_parts: int = 6, budget: int = 400000) -> List[Tuple[bytes, List[Fragment], List[Fragment]]]:
    """一站式：收集 + 拼接。返回 [(flag, 片段路径, 全部片段)]。"""
    fragments = collect_fragments(blob, min_len=min_len)
    results = reassemble_flags(fragments, crib=crib, max_parts=max_parts, budget=budget)
    return [(flag, path, fragments) for flag, path in results]


def best_flag(blob: bytes, crib: Optional[bytes] = None, min_len: int = 3,
              budget: int = 200000) -> Optional[Tuple[bytes, List[Fragment]]]:
    """只要最优的那一个（给一条龙流水线用，失败返回 None）。"""
    try:
        results = solve(blob, crib=crib, min_len=min_len, budget=budget)
    except Exception:
        return None
    if not results:
        return None
    flag, path, _all = results[0]
    return flag, path


def report(blob: bytes, crib: Optional[bytes] = None, min_len: int = 3) -> str:
    fragments = collect_fragments(blob, min_len=min_len)
    results = reassemble_flags(fragments, crib=crib)
    lines = [f"收集到 {len(fragments)} 个候选片段"]
    if not results:
        lines.append("没有拼出完整 flag。可以试试 --crib 给出前缀，或 --min-len 1 放宽")
        for frag in fragments[:15]:
            lines.append("  · " + str(frag))
        return "\n".join(lines)
    for flag, path in results:
        lines.append(f"\n拼接成功：{flag.decode('utf-8', 'replace')}")
        for frag in path:
            lines.append("    + " + str(frag))
    return "\n".join(lines)
