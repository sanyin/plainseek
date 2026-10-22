"""验证 ciphers 模块：改造 RC4、DES 密钥位反转变体。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pseek import ciphers

# ---------- 1. 改造 RC4：与题目 solve.py 的 crypt() 逐字节对照 ----------
KEY = b"CCB_M4gic_K3y_2026"


def origin_crypt(data):
    state = list(range(256))
    cursor = 0
    for index in range(256):
        cursor = (cursor + state[index] + KEY[index % len(KEY)]) & 255
        state[index], state[cursor] = state[cursor], state[index]
    index = cursor = 0
    out = bytearray()
    for value in data:
        index = (index + 1) & 255
        cursor = (cursor + state[index]) & 255
        state[index], state[cursor] = state[cursor], state[index]
        out.append(value ^ state[(state[index] * state[cursor] + 0x72) & 255] ^ 0x37)
    return bytes(out)


sample = bytes(range(256)) * 3
mine = ciphers.rc4(sample, KEY, mask_id=1, p1=0x72, p2=0x37)
print("改造 RC4 与题目原始实现一致:", mine == origin_crypt(sample))
print("标准 RC4 与改造版不同:", ciphers.rc4(sample, KEY, mask_id=0) != mine)

# 常量暴力枚举（已知明文场景）
known_pt = b"flag{this_is_known_plaintext}"
known_ct = ciphers.rc4(known_pt, KEY, mask_id=1, p1=0x72, p2=0x37)
hits = ciphers.rc4_bruteforce_constants(known_pt, known_ct, KEY, mask_id=1, limit=0x100)
print("枚举出的掩码常量:", [(hex(a), hex(b)) for a, b in hits])

# ---------- 2. DES 位反转密钥变体：用 100w 题目的已知信息反查密文 ----------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import sample                            # noqa: E402

EXE = sample("待解题/100w_20260919162532.exe")
key_buf = b"czR@7" + b"\x00" * 3
print("八字节密钥缓冲区:", key_buf.hex(), "(writeup 为 637a524037000000)")
plaintext = b"CTF{4ef7836c744a0aaa0ac00dbc885849d3}"
block = struct.pack("<I", len(plaintext)) + plaintext
block = block + b"\x00" * ((8 - len(block) % 8) % 8)
print("明文块长度:", len(block))

with open(EXE, "rb") as fh:
    exe = fh.read()
print("exe 大小:", len(exe))

for name in ("bitrev", "raw", "reverse", "bitrev_all"):
    ct = ciphers.des_crypt(block, key_buf, transform=name, decrypt=False)
    pos = exe.find(ct)
    print(f"  密钥变换 {name:10s}: 密文 {ct.hex()[:32]}... 在 exe 中位置 = {pos}")

# 解密方向回归测试
k = b"abcdefgh"
src = b"A" * 16
enc = ciphers.des_crypt(src, k, decrypt=False)
print("DES 往返:", ciphers.des_crypt(enc, k) == src)

# 其他算法冒烟测试
for name, fn in (("3DES", lambda d, e: ciphers.des3_crypt(d, b"0123456789abcdef01234567", decrypt=e)),
                 ("AES-ECB", lambda d, e: ciphers.aes_crypt(d, b"0123456789abcdef", decrypt=e))):
    enc = fn(src, False)
    print(f"{name} 往返:", fn(enc, True) == src)

x = ciphers.xtea_crypt(src, b"0123456789abcdef", decrypt=False)
print("XTEA 往返:", ciphers.xtea_crypt(x, b"0123456789abcdef", decrypt=True) == src)
x = ciphers.xxtea_crypt(src, b"0123456789abcdef", decrypt=False)
print("XXTEA 往返:", ciphers.xxtea_crypt(x, b"0123456789abcdef", decrypt=True) == src)
x = ciphers.tea_crypt(src, b"0123456789abcdef", decrypt=False)
print("TEA 往返:", ciphers.tea_crypt(x, b"0123456789abcdef", decrypt=True) == src)
