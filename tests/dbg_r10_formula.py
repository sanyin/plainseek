"""R10 公式反推：用已知 flag 找出 _build 的逐字节混合公式。

思路（也是要泛化成工具的"公式搜索"能力）：
已知明文 F、密文 T、密钥材料 K → 枚举一族"密钥流派生 + 混合运算"，
要求公式对**所有已知字节**成立。只要有一个公式成立，就能对未知部分外推。
"""
import itertools
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import sample                            # noqa: E402

blob = sample("_投稿测试/R10_pyc/check.pyc").read_bytes()
hexes = [m.decode() for m in re.findall(rb"[0-9a-f]{64}", blob)]
A, B = (bytes.fromhex(h) for h in hexes[:2])
F = b"XJUSEC{every_byte_tells_a_story}"
n = len(F)


def rol(b, s):
    s &= 7
    return ((b << s) | (b >> (8 - s))) & 0xFF


def ror(b, s):
    s &= 7
    return ((b >> s) | (b << (8 - s))) & 0xFF


def keystream_candidates(K, T, F):
    """可能的密钥流派生方式（每个返回长度 n 的字节序列或 None）。"""
    out = {}
    out["K[i]"] = bytes(K)
    out["K[i]^i"] = bytes(K[i] ^ i for i in range(n))
    out["K[i]+i"] = bytes((K[i] + i) & 0xFF for i in range(n))
    out["K[i]^(i*7+0x13)"] = bytes(K[i] ^ ((i * 7 + 0x13) & 0xFF) for i in range(n))
    out["K[i]+(i*7+0x13)"] = bytes((K[i] + i * 7 + 0x13) & 0xFF for i in range(n))
    out["rol(K[i],i)"] = bytes(rol(K[i], i) for i in range(n))
    out["ror(K[i],i)"] = bytes(ror(K[i], i) for i in range(n))
    out["K reversed"] = bytes(K[::-1])
    # 与前一位链式
    prevF = bytes([0]) + F[:-1]
    prevT = bytes([0]) + T[:-1]
    out["K[i]^F[i-1]"] = bytes(K[i] ^ prevF[i] for i in range(n))
    out["K[i]^T[i-1]"] = bytes(K[i] ^ prevT[i] for i in range(n))
    out["K[i]+F[i-1]"] = bytes((K[i] + prevF[i]) & 0xFF for i in range(n))
    out["K[i]+T[i-1]"] = bytes((K[i] + prevT[i]) & 0xFF for i in range(n))
    chain = bytearray()
    for i in range(n):
        chain.append(K[i] ^ (chain[i - 1] if i else 0))
    out["K 的累加异或链"] = bytes(chain)
    # 相邻密钥字节混
    out["K[i]^K[i-1]"] = bytes(K[i] ^ (K[i - 1] if i else 0) for i in range(n))
    out["K[i]+K[i-1]"] = bytes((K[i] + (K[i - 1] if i else 0)) & 0xFF for i in range(n))
    # 移位取密钥（不同步长）
    for step in (1, 2, 3, 5, 7, 11, 13, 17, 31):
        out[f"K[(i*{step})%n]"] = bytes(K[(i * step) % len(K)] for i in range(n))
        out[f"K[(i+{step})%n]"] = bytes(K[(i + step) % len(K)] for i in range(n))
    return out


def mix_candidates(f, ks):
    """可能的混合运算（对每个字节给出候选输出）。"""
    out = {}
    out["F^KS"] = bytes(a ^ b for a, b in zip(f, ks))
    out["(F^KS)+i"] = bytes(((a ^ b) + i) & 0xFF for i, (a, b) in enumerate(zip(f, ks)))
    out["(F+KS)&0xff"] = bytes((a + b) & 0xFF for a, b in zip(f, ks))
    out["(F-KS)&0xff"] = bytes((a - b) & 0xFF for a, b in zip(f, ks))
    out["(KS-F)&0xff"] = bytes((b - a) & 0xFF for a, b in zip(f, ks))
    out["rol(F^KS,i)"] = bytes(rol(a ^ b, i) for i, (a, b) in enumerate(zip(f, ks)))
    out["(F^KS)^i"] = bytes((a ^ b) ^ i for i, (a, b) in enumerate(zip(f, ks)))
    out["(F^KS)^(i*7+0x13)"] = bytes((a ^ b) ^ ((i * 7 + 0x13) & 0xFF)
                                     for i, (a, b) in enumerate(zip(f, ks)))
    out["((F^KS)*0x1f)&0xff"] = bytes(((a ^ b) * 0x1F) & 0xFF for a, b in zip(f, ks))
    return out


hits = []
for kn, KS in keystream_candidates(A, B, F).items():
    for mn, cand in mix_candidates(F, KS).items():
        if cand == B:
            hits.append(f"TARGET[i] = {mn}  其中 KS = {kn}")
        # 也试反过来（A/B 角色互换）
for kn, KS in keystream_candidates(B, A, F).items():
    for mn, cand in mix_candidates(F, KS).items():
        if cand == A:
            hits.append(f"KEY[i] = {mn}  其中 KS = {kn}")

if hits:
    print("找到成立公式：")
    for h in hits:
        print("   ", h)
else:
    print("简单公式族里没有成立项——需要更强的手段（反汇编 3.10 字节码）")
    # 输出一些诊断量，便于手工推断
    print("\n诊断：")
    print("  T^F  =", bytes(a ^ b for a, b in zip(B, F)).hex())
    print("  A    =", A.hex())
    print("  T^F^A=", bytes(a ^ b ^ c for a, b, c in zip(B, F, A)).hex())
    print("  (T-F)&0xff =", bytes((b - a) & 0xFF for a, b in zip(F, B)).hex())
    print("  (F-T)&0xff =", bytes((a - b) & 0xFF for a, b in zip(F, B)).hex())
