"""加密算法层：把"会被改"的加密做成参数化家族。

真实逆向题里，出题人几乎不会用标准库默认参数，常见改动：

* RC4 的 PRGA 掩码公式被改（如 ``S[(S[i]*S[j]+0x72)&0xff] ^ 0x37``）
* DES 的位选取表方向被反转（等价于把密钥每个字节按位倒序）
* 密钥只在前面几位有效、后面补零；数据前带长度前缀
* AES 用非常规 IV / 直接 ECB

所以这里不写"一个算法一个函数"，而是写**参数化家族**：未知常量留在参数里，
交给 search / recover 去枚举。标准实现只是参数取默认值的特例。
"""

from __future__ import annotations

import hashlib
import struct
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# RC4 家族
# --------------------------------------------------------------------------

# PRGA 掩码公式编号（i、j 为已交换后的下标，S 为状态盒）
RC4_MASK_IDS = range(10)


def rc4_mask_keystream(state: List[int], i: int, j: int, mask_id: int,
                       p1: int, p2: int) -> int:
    """按掩码公式取一个密钥流字节（可插拔，方便接新变种）。"""
    si, sj = state[i], state[j]
    if mask_id == 0:                                   # 标准 RC4
        return state[(si + sj) & 0xFF]
    if mask_id == 1:                                   # 题目常见：乘法 + 异或常量
        return state[(si * sj + p1) & 0xFF] ^ p2
    if mask_id == 2:
        return (si + sj + p1) & 0xFF
    if mask_id == 3:
        return (si ^ sj ^ p1) & 0xFF
    if mask_id == 4:
        return state[(si ^ sj) & 0xFF] ^ p1
    if mask_id == 5:
        return state[(si - sj) & 0xFF] ^ p1
    if mask_id == 6:
        return state[(si * p1 + sj) & 0xFF] ^ p2
    if mask_id == 7:
        return (state[(si + sj) & 0xFF] + p1) & 0xFF
    if mask_id == 8:
        return (si * sj + p1) & 0xFF
    if mask_id == 9:
        return state[(si + sj + p1) & 0xFF] ^ p2
    raise ValueError(f"未知掩码公式 {mask_id}")


def rc4_keystream(key: bytes, length: int, mask_id: int = 0, p1: int = 0, p2: int = 0,
                  ksa_id: int = 0, drop: int = 0, ksa_const: int = 0) -> bytes:
    """生成 RC4 家族密钥流。ksa_id 控制密钥调度变种。"""
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
        elif ksa_id == 3:
            j = (j + state[i] + key[(i * 7) % klen]) & 0xFF
        else:
            raise ValueError(f"未知 KSA 变种 {ksa_id}")
        state[i], state[j] = state[j], state[i]
    out = bytearray()
    i = j = 0
    total = length + drop
    for _ in range(total):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(rc4_mask_keystream(state, i, j, mask_id, p1, p2))
    return bytes(out[drop:])


def rc4(data: bytes, key: bytes, **kw) -> bytes:
    """RC4 家族加/解密（异或流，对称）。"""
    ks = rc4_keystream(key, len(data), **kw)
    return bytes(a ^ b for a, b in zip(data, ks))


def rc4_bruteforce_constants(known_plain: bytes, known_cipher: bytes, key: bytes,
                             mask_id: int = 1, c1: int = 0, c2: int = 0,
                             limit: int = 0x100) -> List[Tuple[int, int]]:
    """已知明文时暴力枚举掩码常量 (p1, p2)。

    只用到已知明文那么多字节，因此非常快；命中后可用完整密钥流复核。
    """
    klen = min(len(known_plain), len(known_cipher))
    if klen < 4:
        return []
    target = bytes(a ^ b for a, b in zip(known_plain[:klen], known_cipher[:klen]))
    hits: List[Tuple[int, int]] = []
    for p1 in range(limit):
        for p2 in range(limit):
            if rc4_keystream(key, klen, mask_id=mask_id, p1=p1, p2=p2) == target:
                hits.append((p1, p2))
    return hits


# --------------------------------------------------------------------------
# 密钥变换（DES 变体题的常见坑）
# --------------------------------------------------------------------------

def _bitrev_byte(b: int) -> int:
    r = 0
    for _ in range(8):
        r = (r << 1) | (b & 1)
        b >>= 1
    return r


def _bitrev_all(data: bytes) -> bytes:
    bits = "".join(f"{b:08b}" for b in data)
    return int(bits[::-1], 2).to_bytes(len(data), "big") if bits else b""


KEY_TRANSFORMS: Dict[str, Callable[[bytes], bytes]] = {
    "raw": lambda k: k,
    "bitrev": lambda k: bytes(_bitrev_byte(b) for b in k),          # 逐字节位反转
    "bitrev_all": _bitrev_all,                                      # 整体位序反转
    "reverse": lambda k: k[::-1],                                   # 字节顺序反转
    "nibswap": lambda k: bytes(((b & 0x0F) << 4) | (b >> 4) for b in k),
    "not": lambda k: bytes(b ^ 0xFF for b in k),
    "bitrev_not": lambda k: bytes(_bitrev_byte(b) ^ 0xFF for b in k),
    "xor80": lambda k: bytes(b ^ 0x80 for b in k),
}


def transform_key(key: bytes, name: str) -> bytes:
    if name not in KEY_TRANSFORMS:
        raise KeyError(f"未知密钥变换 {name}")
    return KEY_TRANSFORMS[name](key)


def key_candidates(base: bytes, names: Sequence[str] = ()) -> Iterable[Tuple[str, bytes]]:
    """给出一个密钥的所有常见变体（附带变体名，便于报告）。"""
    for name in (names or tuple(KEY_TRANSFORMS)):
        try:
            yield name, transform_key(base, name)
        except Exception:
            continue


# --------------------------------------------------------------------------
# DES / 3DES（pycryptodome）
# --------------------------------------------------------------------------

def _load_des():
    try:
        from Crypto.Cipher import DES, DES3
        return DES, DES3
    except Exception:
        return None, None


def des_crypt(data: bytes, key: bytes, mode: str = "ecb", iv: bytes = b"\x00" * 8,
              transform: str = "raw", pad_zero: bool = True, decrypt: bool = True) -> bytes:
    """DES 加/解密。``transform`` 指定密钥变体（如题目里位表反转 → bitrev）。"""
    DES, _ = _load_des()
    if DES is None:
        raise RuntimeError("需要 pycryptodome 才能用 DES")
    k = transform_key(key, transform)
    if pad_zero and len(k) < 8:
        k = k + b"\x00" * (8 - len(k))
    k = k[:8]
    if mode == "ecb":
        cipher = DES.new(k, DES.MODE_ECB)
    elif mode == "cbc":
        cipher = DES.new(k, DES.MODE_CBC, iv[:8])
    else:
        raise ValueError("DES 仅支持 ecb/cbc")
    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)


def des3_crypt(data: bytes, key: bytes, mode: str = "ecb", iv: bytes = b"\x00" * 8,
               transform: str = "raw", decrypt: bool = True) -> bytes:
    _, DES3 = _load_des()
    if DES3 is None:
        raise RuntimeError("需要 pycryptodome 才能用 3DES")
    k = transform_key(key, transform)
    while len(k) < 16:
        k += k
    k = k[:16 if len(k) < 24 else 24]
    cipher = DES3.new(k, DES3.MODE_ECB if mode == "ecb" else DES3.MODE_CBC,
                      **({} if mode == "ecb" else {"iv": iv[:8]}))
    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)


def aes_crypt(data: bytes, key: bytes, mode: str = "ecb", iv: bytes = b"\x00" * 16,
              decrypt: bool = True, nonce: bytes = b"\x00" * 8,
              segment_size: int = 128) -> bytes:
    """AES 常见模式。key 长度自动截断/补零到 16/24/32。"""
    try:
        from Crypto.Cipher import AES
    except Exception as exc:
        raise RuntimeError("需要 pycryptodome 才能用 AES") from exc
    k = key
    if len(k) not in (16, 24, 32):
        k = (k + b"\x00" * 32)[:16 if len(k) <= 16 else (24 if len(k) <= 24 else 32)]
    mode = mode.lower()
    if mode == "ecb":
        cipher = AES.new(k, AES.MODE_ECB)
    elif mode == "cbc":
        cipher = AES.new(k, AES.MODE_CBC, iv)
    elif mode == "cfb":
        cipher = AES.new(k, AES.MODE_CFB, iv, segment_size=segment_size)
    elif mode == "ofb":
        cipher = AES.new(k, AES.MODE_OFB, iv)
    elif mode == "ctr":
        cipher = AES.new(k, AES.MODE_CTR, nonce=nonce)
    else:
        raise ValueError(f"不支持的 AES 模式 {mode}")
    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)


def pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 0 < pad <= block and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data


# --------------------------------------------------------------------------
# TEA / XTEA / XXTEA（纯 Python，含端序与轮数参数）
# --------------------------------------------------------------------------

def _tea_words(data: bytes, endian: str = "<") -> List[int]:
    if len(data) % 4:
        data = data + b"\x00" * (4 - len(data) % 4)
    return list(struct.unpack(endian + f"{len(data) // 4}I", data))


def _tea_pack(words: Sequence[int], endian: str = "<") -> bytes:
    return struct.pack(endian + f"{len(words)}I", *[w & 0xFFFFFFFF for w in words])


def tea_crypt(data: bytes, key: bytes, decrypt: bool = True, rounds: int = 32,
              endian: str = "<") -> bytes:
    k = _tea_words((key + b"\x00" * 16)[:16], endian)
    delta, mask = 0x9E3779B9, 0xFFFFFFFF
    out = []
    for i in range(0, len(data) - 7, 8):
        v0, v1 = struct.unpack(endian + "2I", data[i:i + 8])
        s = (delta * (rounds // 2)) & mask if decrypt else 0
        for _ in range(rounds // 2):
            if decrypt:
                v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & mask
                v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & mask
                s = (s - delta) & mask
            else:
                s = (s + delta) & mask
                v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & mask
                v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & mask
        out.append((v0, v1))
    return b"".join(struct.pack(endian + "2I", *o) for o in out) + data[len(data) - len(data) % 8:]


def xtea_crypt(data: bytes, key: bytes, decrypt: bool = True, rounds: int = 32,
               endian: str = "<") -> bytes:
    k = _tea_words((key + b"\x00" * 16)[:16], endian)
    delta, mask = 0x9E3779B9, 0xFFFFFFFF
    out = []
    for i in range(0, len(data) - 7, 8):
        v0, v1 = struct.unpack(endian + "2I", data[i:i + 8])
        s = (delta * (rounds // 2)) & mask if decrypt else 0
        for _ in range(rounds // 2):
            if decrypt:
                v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & mask
                s = (s - delta) & mask
                v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & mask
            else:
                v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & mask
                s = (s + delta) & mask
                v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & mask
        out.append((v0, v1))
    return b"".join(struct.pack(endian + "2I", *o) for o in out) + data[len(data) - len(data) % 8:]


def xxtea_crypt(data: bytes, key: bytes, decrypt: bool = True, endian: str = "<") -> bytes:
    if len(data) < 8:
        return data
    v = _tea_words(data, endian)
    k = _tea_words((key + b"\x00" * 16)[:16], endian)
    n = len(v)
    delta, mask = 0x9E3779B9, 0xFFFFFFFF

    def mx(y, z, p, e):
        return (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((p ^ y) + (k[(p & 3) ^ e] ^ z))) & mask

    if not decrypt:
        rounds = 6 + 52 // n
        s = 0
        for _ in range(rounds):
            s = (s + delta) & mask
            e = (s >> 2) & 3
            for p in range(n):
                y = v[(p + 1) % n]
                v[p] = (v[p] + mx(v[p - 1], y, s, e)) & mask
    else:
        rounds = 6 + 52 // n
        s = (rounds * delta) & mask
        for _ in range(rounds):
            e = (s >> 2) & 3
            for p in range(n - 1, -1, -1):
                y = v[(p + 1) % n]
                v[p] = (v[p] - mx(v[p - 1], y, s, e)) & mask
            s = (s - delta) & mask
    raw = _tea_pack(v, endian)
    # 去 XXTEA 长度前缀
    if decrypt:
        nbytes = v[-1] if endian == "<" else v[0]
        if 0 < nbytes <= len(raw):
            return raw[:nbytes]
    return raw


# --------------------------------------------------------------------------
# PRNG 密钥流
# --------------------------------------------------------------------------

def mt19937_keystream(seed, length: int, mode: str = "getrandbits") -> bytes:
    """MT19937 密钥流。mode=getrandbits 用 Python random；rand 用 C 风格 32 位取模。"""
    import random as _random
    rng = _random.Random(seed)
    if mode == "getrandbits":
        return bytes(rng.getrandbits(8) for _ in range(length))
    out = bytearray()
    while len(out) < length:
        v = rng.getrandbits(32)
        for shift in (0, 8, 16, 24):
            out.append((v >> shift) & 0xFF)
    return bytes(out[:length])


def lcg_keystream(seed: int, length: int, a: int = 1103515245, c: int = 12345,
                  m: int = 1 << 31, width: int = 1, mode: str = "low") -> bytes:
    """线性同余密钥流。width=1 取低字节，width=4 取 32 位小端。"""
    out = bytearray()
    x = seed & (m - 1)
    while len(out) < length:
        x = (a * x + c) % m
        if width == 1:
            out.append((x >> 16) & 0xFF if mode == "high" else x & 0xFF)
        else:
            out += (x & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out[:length])


def apply_keystream(data: bytes, keystream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream))


# --------------------------------------------------------------------------
# 常用哈希/密钥派生（题目里常见的"输入 → 密钥"链条）
# --------------------------------------------------------------------------

def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def derive_keys(seed: bytes, algorithms: Sequence[str] = ("md5", "sha1", "sha256")) -> Dict[str, bytes]:
    out = {}
    for algo in algorithms:
        try:
            h = hashlib.new(algo, seed)
        except Exception:
            continue
        out[algo] = h.digest()
        out[f"{algo}_hex"] = h.hexdigest().encode()
    return out
