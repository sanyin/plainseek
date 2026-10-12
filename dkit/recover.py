"""已知明文 / 密钥恢复辅助。

这是"通用"的另一半：很多题根本不需要还原密钥——
只要有一对"明文 + 密文"，就能直接拿到密钥流，再拿去解同目录的其它文件。
另外还能用**字符集约束**把改造版 RC4 的未知常量（如 0x72、0x37）枚举出来。
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import ciphers, oracles

# --------------------------------------------------------------------------
# 密钥流 / XOR
# --------------------------------------------------------------------------


def xor_keystream(plain: bytes, cipher: bytes, cap: int = 0) -> bytes:
    """由一对明文/密文得到异或密钥流。"""
    n = min(len(plain), len(cipher))
    if cap:
        n = min(n, cap)
    return bytes(a ^ b for a, b in zip(plain[:n], cipher[:n]))


def repeating_period(stream: bytes, max_period: int = 64) -> Optional[int]:
    """判断密钥流是不是短周期重复（即"重复密钥 XOR"）。"""
    for period in range(1, min(max_period, max(1, len(stream) // 3)) + 1):
        if all(stream[i] == stream[i % period] for i in range(len(stream))):
            return period
    return None


def analyze_stream_layer(plain: bytes, cipher: bytes) -> Dict[str, object]:
    """分析"明文⊕密文"的性质：常量 / 短周期 / 伪随机 / 替换表。"""
    ks = xor_keystream(plain, cipher)
    if not ks:
        return {"kind": "empty"}
    info: Dict[str, object] = {"keystream": ks, "len": len(ks), "distinct": len(set(ks))}
    if len(set(ks)) == 1:
        info["kind"] = "常数"
        info["key"] = ks[:1]
    else:
        period = repeating_period(ks)
        if period:
            info["kind"] = "短周期重复密钥"
            info["period"] = period
            info["key"] = ks[:period]
        else:
            info["kind"] = "伪随机密钥流（可直接复用同偏移）"
    return info


def apply_keystream_to_siblings(keystream: bytes, data: bytes) -> bytes:
    n = min(len(keystream), len(data))
    return bytes(a ^ b for a, b in zip(data[:n], keystream)) + data[n:]


# --------------------------------------------------------------------------
# 替换表：明文 ↔ 自定义字符表数据
# --------------------------------------------------------------------------


def table_from_pair(plain: bytes, cipher_stream: bytes, alphabet=None) -> Optional[bytes]:
    """已知明文 + "自定义 Base64 密文流" → 还原出 64 字符表。

    返回标准顺序下的字符表（若密文并非该结构则返回 None）。
    """
    from . import alphabets as _al
    alphabet = alphabet or _al.B64_STD
    try:
        mapping = _al.mapping_from_pair(plain, cipher_stream, alphabet)
    except Exception:
        return None
    if len(mapping) < 4:
        return None
    reverse = {v: k for k, v in mapping.items()}
    return bytes(reverse.get(i, ord("?")) for i in range(len(alphabet.chars)))


# --------------------------------------------------------------------------
# 字符串提取（密钥常在二进制里）
# --------------------------------------------------------------------------

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def strings(data: bytes, minlen: int = 4) -> List[bytes]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append(m.group(0))
    return out


_ORDERED_ALPHABETS = (b"abcdefghijklmnopqrstuvwxyz", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                      b"0123456789")


def longest_ordered_run(s: bytes) -> int:
    """找出最长的"按字母表顺序连续"的片段长度（ABCDEFG 这种）。

    二进制里字符串经常首尾粘连，提取出来会得到 ``BCDEFGHIJKLMNOP<真密钥>``
    这种噪声；真正像口令的密钥不会有这么长的连续段。
    """
    best = 1
    for order in _ORDERED_ALPHABETS:
        pos = {c: i for i, c in enumerate(order)}
        prev = None
        cur = 0
        for ch in s:
            i = pos.get(ch)
            if i is None:
                prev, cur = None, 0
                continue
            cur = cur + 1 if (prev is not None and abs(i - prev) == 1) else 1
            prev = i
            if cur > best:
                best = cur
    return best


def harvest_keys(paths: Sequence[str], minlen: int = 5, max_keys: int = 400) -> List[bytes]:
    """从附件（尤其是可执行文件）里抓取可疑密钥字符串。"""
    keys: List[bytes] = []
    seen: Set[bytes] = set()
    interesting = re.compile(rb"[A-Za-z0-9_@#$%^&*!+\-]{5,64}")
    _run = re.compile(rb"ABCDEFGH|abcdefgh|0123456789|HGFEDCBA|hgfedcba|9876543210")
    for path in paths:
        try:
            with open(path, "rb") as fh:
                blob = fh.read(8 << 20)
        except OSError:
            continue
        for s in strings(blob, minlen):
            for token in interesting.findall(s):
                # 二进制里字符串常常首尾粘连（密钥紧跟在字符表后面），
                # 所以长 token 还要拆出所有后缀/前缀来试
                variants = [token]
                if len(token) > 12:
                    variants += [token[i:] for i in range(1, min(len(token) - 7, 40))]
                    variants += [token[:i] for i in range(8, len(token))]
                for cand in variants:
                    if cand in seen or not (minlen <= len(cand) <= 64):
                        continue
                    seen.add(cand)
                    keys.append(cand)
        for name in (os.path.basename(path), os.path.splitext(os.path.basename(path))[0]):
            if len(name) >= 4 and name.encode() not in seen:
                seen.add(name.encode())
                keys.append(name.encode())

    def rank(k: bytes) -> Tuple[int, int]:
        """像"人写的口令"的排前面：大小写混合、含数字/符号、长度适中，
        且不是 ABCDEFGH 这种连续字符表（那种多半是提取字符串时粘出来的噪声）。"""
        score = 0
        score += 2 if (re.search(rb"[a-z]", k) and re.search(rb"[A-Z]", k)) else 0
        score += 1 if re.search(rb"\d", k) else 0
        score += 1 if re.search(rb"[_@#$%^&*!+\-]", k) else 0
        score += 1 if 8 <= len(k) <= 40 else 0
        # 连续段越长越像"字符串粘连"的噪声，按长度渐进扣分
        # （这样 abcd1234 这种正常口令只略微降权，而 BCDEFGHIJKLMNOP 直接被压下去）
        score -= min(5, max(0, longest_ordered_run(k) - 3))
        if len(k) > 40:
            score -= 1
        return (-score, -len(k))
    keys.sort(key=rank)
    return keys[:max_keys]


# --------------------------------------------------------------------------
# RC4 家族：用字符集约束枚举未知常量
# --------------------------------------------------------------------------

B64_CHARSET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
HEX_CHARSET = set(b"0123456789abcdefABCDEF")
PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _prga_trace(key: bytes, steps: int, ksa_id: int = 0, ksa_const: int = 0,
                drop: int = 0) -> List[Tuple[List[int], int, int]]:
    """预计算 PRGA 的状态轨迹（与掩码公式无关，所以可以复用）。"""
    key = bytes(key) or b"\x00"
    state = list(range(256))
    klen = len(key)
    j = 0
    for i in range(256):
        if ksa_id == 0:
            j = (j + state[i] + key[i % klen] + ksa_const) & 0xFF
        elif ksa_id == 1:
            j = (j + state[i] + key[klen - 1 - (i % klen)]) & 0xFF
        elif ksa_id == 2:
            j = ((j + state[i]) ^ key[i % klen]) & 0xFF
        else:
            j = (j + state[i] + key[(i * 7) % klen]) & 0xFF
        state[i], state[j] = state[j], state[i]
    trace: List[Tuple[List[int], int, int]] = []
    i = j = 0
    for _ in range(steps + drop):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        trace.append((list(state), i, j))
    return trace[drop:]


def _mask_base(state: List[int], i: int, j: int, mask_id: int, p1: int) -> int:
    """掩码公式中"与 p2 无关"的那部分（p2 只在最后异或）。"""
    si, sj = state[i], state[j]
    if mask_id == 0:
        return state[(si + sj) & 0xFF]
    if mask_id == 1:
        return state[(si * sj + p1) & 0xFF]
    if mask_id == 2:
        return (si + sj + p1) & 0xFF
    if mask_id == 3:
        return si ^ sj ^ p1
    if mask_id == 4:
        return state[(si ^ sj) & 0xFF] ^ p1
    if mask_id == 5:
        return state[(si - sj) & 0xFF] ^ p1
    if mask_id == 6:
        return state[(si * p1 + sj) & 0xFF]
    if mask_id == 7:
        return (state[(si + sj) & 0xFF] + p1) & 0xFF
    if mask_id == 8:
        return (si * sj + p1) & 0xFF
    if mask_id == 9:
        return state[(si + sj + p1) & 0xFF]
    raise ValueError(mask_id)


USES_XOR_P2 = (1, 3, 6, 9)


def rc4_family_recover(cipher: bytes, key: bytes, allowed: Optional[Set[int]] = None,
                       known_plain: Optional[bytes] = None, mask_ids: Sequence[int] = tuple(range(10)),
                       ksa_ids: Sequence[int] = (0, 1, 2, 3), check: int = 16,
                       min_hit: int = 8) -> List[Dict[str, object]]:
    """枚举改造版 RC4 的 (掩码公式, 常量)，用**字符集**或**已知明文**当筛子。

    两个关键优化：
    1. PRGA 的状态演化与掩码公式无关 → 每个密钥只算一次轨迹，之后纯查表；
    2. 带异或常量的掩码可以在第 0 步就把 p2 的候选从 256 个缩到 |字符集| 个。
    这样 0x72/0x37 这种"改了密码表"的常量几毫秒就能试出来。
    """
    hits: List[Dict[str, object]] = []
    n = min(len(cipher), check)
    if n < 4:
        return hits
    target = known_plain[:n] if known_plain else None
    if target is None and allowed is None:
        return hits
    allowed_list = sorted(allowed) if allowed else []

    for ksa_id in ksa_ids:
        try:
            trace = _prga_trace(key, n, ksa_id=ksa_id)
        except Exception:
            continue
        state0, i0, j0 = trace[0]
        for mask_id in mask_ids:
            p1_values = (0,) if mask_id == 0 else range(256)
            for p1 in p1_values:
                if mask_id in USES_XOR_P2:
                    base0 = _mask_base(state0, i0, j0, mask_id, p1)
                    # 明文第 0 字节 = cipher[0] ^ base0 ^ p2，要求它落在字符集里
                    base_xor = base0 ^ cipher[0]
                    if target is not None:
                        p2_candidates = [base_xor ^ target[0]]
                    else:
                        p2_candidates = [base_xor ^ a for a in allowed_list]
                else:
                    p2_candidates = [0]
                for p2 in p2_candidates:
                    good = True
                    for t in range(n):
                        state, i, j = trace[t]
                        m = ciphers.rc4_mask_keystream(state, i, j, mask_id, p1, p2)
                        byte = cipher[t] ^ m
                        if target is not None:
                            if byte != target[t]:
                                good = False
                                break
                        elif byte not in allowed:                # type: ignore[operator]
                            good = False
                            break
                    if good:
                        hits.append({"mask": mask_id, "p1": p1, "p2": p2, "ksa": ksa_id,
                                     "checked": n})
    seen = set()
    uniq = []
    for h in hits:
        sig = (h["mask"], h["p1"], h["p2"], h["ksa"])
        if sig in seen:
            continue
        seen.add(sig)
        uniq.append(h)
    return uniq


def charset_check_len(allowed: Set[int], false_rate: float = 1e-12, floor: int = 24) -> int:
    """由字符集大小算出"需要连续命中多少字节才算数"。

    注意：不能直接按 ``|字符集|/256`` 估算——掩码常量只差 2 时，
    异或后的字节有约一半仍然落在同一个字符集里，所以下限要抬到 24 字节。
    """
    import math
    p = max(1e-6, len(allowed) / 256.0)
    need = math.ceil(math.log(false_rate) / math.log(p))
    return max(floor, need)


def rc4_family_search(cipher: bytes, keys: Sequence[bytes],
                      allowed: Optional[Set[int]] = None,
                      known_plain: Optional[bytes] = None,
                      mask_ids: Sequence[int] = tuple(range(10)),
                      check: int = 0, time_budget: float = 30.0) -> List[Dict[str, object]]:
    """对多个密钥候选依次尝试，返回所有候选解（含完整解密结果）。"""
    if not check:
        check = charset_check_len(allowed) if allowed else 16
    out: List[Dict[str, object]] = []
    deadline = time.time() + time_budget
    for key in keys:
        if time.time() > deadline:
            break
        for hit in rc4_family_recover(cipher, key, allowed, known_plain, mask_ids, check=check):
            params = {"key": key, "mask": hit["mask"], "p1": hit["p1"], "p2": hit["p2"],
                      "ksa": hit["ksa"]}
            plain = ciphers.rc4(cipher, key, mask_id=hit["mask"], p1=hit["p1"], p2=hit["p2"],
                                ksa_id=hit["ksa"])
            out.append({"params": params, "plain": plain, "hit": hit})
    return out


def charset_for(name: str, table: Optional[bytes] = None) -> Set[int]:
    if table:
        return set(table) | set(b"=")
    if name == "base64":
        return set(B64_CHARSET)
    if name == "hex":
        return set(HEX_CHARSET)
    if name == "printable":
        return set(PRINTABLE)
    return set(PRINTABLE)


# --------------------------------------------------------------------------
# 明文/密文配对
# --------------------------------------------------------------------------

PAIR_SUFFIXES = (".enc", ".encrypted", ".locked", ".crypt", ".crypto", ".bak", ".data", ".out")


def find_pairs(paths: Sequence[str]) -> List[Tuple[str, str]]:
    """找出目录里的 (明文, 密文) 配对，例如 readme.txt ↔ readme.txt.enc。"""
    by_name = {}
    for p in paths:
        by_name[os.path.basename(p)] = p
    pairs = []
    for p in paths:
        base = os.path.basename(p)
        for suffix in PAIR_SUFFIXES:
            if base.endswith(suffix):
                stem = base[: -len(suffix)]
                if stem in by_name:
                    pairs.append((by_name[stem], p))
                    break
    return pairs


@dataclass
class PairReport:
    plain_path: str
    cipher_path: str
    plain_len: int
    cipher_len: int
    layer: Dict[str, object] = field(default_factory=dict)
    table: Optional[bytes] = None
    notes: List[str] = field(default_factory=list)


def analyze_pair(plain_path: str, cipher_path: str) -> PairReport:
    """分析一对明文/密文，给出可复用的结论（密钥流、字符表等）。"""
    with open(plain_path, "rb") as fh:
        plain = fh.read()
    with open(cipher_path, "rb") as fh:
        cipher = fh.read()
    rep = PairReport(plain_path, cipher_path, len(plain), len(cipher))
    same_len = len(plain) == len(cipher)
    rep.notes.append("长度相同，像是流加密/替换" if same_len else
                     f"长度不同（{len(plain)} vs {len(cipher)}），可能含编码层")

    if same_len:
        rep.layer = analyze_stream_layer(plain, cipher)
    # 尝试还原自定义字符表：明文先做标准 Base64，再与密文对照
    from . import alphabets as _al
    import base64 as _b64
    if len(cipher) >= 8:
        for alphabet in (_al.B64_STD, _al.alphabet_by_name("base64url")):
            table = table_from_pair(plain, cipher, alphabet)
            if table:
                rep.table = table
                rep.notes.append(f"密文疑似 {alphabet.name} 字符表被打乱（可直接还原该表）")
                break
    return rep
