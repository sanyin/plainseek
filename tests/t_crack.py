"""古典密码破解 + 压缩区抑制 的测试。"""
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dkit import carve, crack

ENGLISH = (b"It was a bright cold day in April, and the clocks were striking thirteen. "
           b"Winston Smith, his chin nuzzled into his breast in an effort to escape the "
           b"vile wind, slipped quickly through the glass doors of Victory Mansions, though "
           b"not quickly enough to prevent a swirl of gritty dust from entering along with him. "
           b"The hallway smelt of boiled cabbage and old rag mats.")

print("=" * 70)
print("[1] 凯撒")
ct = crack.caesar(ENGLISH.decode(), 7, decode=False).encode()
res = crack.crack_caesar(ct)
print("  最优:", res[0].line())
print("  [PASS]" if res[0].plaintext == ENGLISH else "  [FAIL]")

print("[2] 仿射")
text = ENGLISH.decode()


def affine_encrypt(src: str, a: int, b: int) -> str:
    out = []
    for ch in src:
        if ch.isupper():
            out.append(chr((a * (ord(ch) - 65) + b) % 26 + 65))
        elif ch.islower():
            out.append(chr((a * (ord(ch) - 97) + b) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


ct2 = affine_encrypt(text, 5, 8).encode()
res = crack.crack_affine(ct2)
print("  最优:", res[0].line())
print("  [PASS]" if res[0].plaintext == ENGLISH else "  [FAIL]")

print("[3] 维吉尼亚")
key = "secret"
ct3 = []
i = 0
for ch in text:
    if ch.isalpha():
        base = 97 if ch.islower() else 65
        ct3.append(chr((ord(ch) - base + ord(key[i % len(key)]) - 97) % 26 + base))
        i += 1
    else:
        ct3.append(ch)
ct3 = "".join(ct3).encode()
res = crack.crack_vigenere(ct3, 12)
print("  最优:", res[0].line())
print("  [PASS]" if res[0].plaintext[:60] == ENGLISH[:60] else "  [FAIL]")

print("[4] 单表替换")
import random
rng = random.Random(7)
perm = list("abcdefghijklmnopqrstuvwxyz")
rng.shuffle(perm)
mapping = dict(zip("abcdefghijklmnopqrstuvwxyz", perm))
ct4 = "".join(mapping.get(c, c) for c in text).encode()
res = crack.crack_substitution(ct4, restarts=8, iterations=40000)
best = res[0]
print("  最优:", best.line())
same = sum(1 for a, b in zip(best.plaintext, ENGLISH) if a == b) / len(ENGLISH)
print(f"  与原文一致度 {same:.1%}")
print("  [PASS]" if same > 0.85 else "  [FAIL]")

print("[5] 栅栏密码")
ct5 = []
rails = 3
pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
buckets = [[] for _ in range(rails)]
for idx, ch in enumerate(text):
    buckets[pattern[idx % len(pattern)]].append(ch)
ct5 = "".join("".join(b) for b in buckets).encode()
res = crack.crack_railfence(ct5, 8)
print("  最优:", res[0].line())
print("  [PASS]" if res[0].plaintext == ct5 or res[0].plaintext.decode() == text else "  [FAIL]")

print("[6] 综合自动（crack_all）")
res = crack.crack_all(ct)
print("  最优:", res[0].line())

print("=" * 70)
print("[7] 压缩区抑制（hexforge 的核心思路）")


def _chunk(ctype: bytes, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload)) + ctype + payload
            + struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF))


noise = b"PK\x03\x04" * 8 + os.urandom(64)          # 放在"压缩数据"里的假 ZIP 头
stored = zlib.compress(noise, 0)                     # level 0 = 原样存储，字节会原文出现
png = (b"\x89PNG\r\n\x1a\n"
       + _chunk(b"IHDR", struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0))
       + _chunk(b"IDAT", stored)
       + _chunk(b"IEND", b""))
assert b"PK\x03\x04" in png, "测试数据构造失败"
rep = carve.scan(png, "noise.png", depth=0)
print(carve.report_text(rep))
zip_hits = [c for c in rep.found if c.ext == "zip"]
print(f"  IDAT 里的假 ZIP 头是否被抑制: {not zip_hits} (抑制计数={rep.suppressed})")
print("  [PASS]" if not zip_hits and rep.suppressed > 0 else "  [FAIL]")
print("=" * 70)
