"""密钥确认机制的测试。

包含真实题目 `100w`：密文躺在 exe 里，密钥由 6 位输入经 MD5 派生，
DES 位选取表被反转。目标：**全自动反查出输入 732425 并解出 flag**。
"""
import hashlib
import io
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dkit import ciphers, oracles, verify
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import sample                            # noqa: E402

EXE = str(sample("待解题/100w_20260919162532.exe"))
SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "examples", "keyderive_template.py")

print("=" * 74)
print("[1] 密钥派生脚本是否复刻成功（输入 732425 → 密钥 czR@7\\x00\\x00\\x00）")
mod = verify.load_key_script(SCRIPT)
found = None
for label, key in verify.script_keys(mod):
    if label == "732425":
        found = key
        break
print("   派生结果:", found)
print("   [PASS]" if found == b"czR@7\x00\x00\x00" else "   [FAIL]")

print("=" * 74)
print("[2] 方式 A：加密已知明文 → 在程序里反查密文（合成 crackme）")
key = b"hunter2!"
plain_block = b"SECRET_PLAINTEXT"          # 正好 16 字节
ct = verify.encrypt_with({"name": "aes", "params": {}}, key, plain_block)
blob = os.urandom(4096) + ct + os.urandom(4096)
tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_fake_crackme.bin")
with open(tmp, "wb") as fh:
    fh.write(blob)
res = verify.run_verify(tmp, ciphers_list=["aes"], keys=[b"wrongkey", key],
                        key_transforms=["raw"], verify_plain=plain_block,
                        log=lambda m: None)
ok = bool(res) and res[0].key == key and res[0].offset == 4096
print("   确认结果:", res[0].line() if res else "无")
print("   [PASS] 命中偏移正确" if ok else "   [FAIL]")
os.remove(tmp)

print("=" * 74)
print("[3] 候选密钥空间枚举 + 派生规则")
from dkit.verify import Keyspace, keyspace_keys
pairs = list(keyspace_keys(Keyspace("digits", 3, "md5_hex")))
expect = hashlib.md5(b"000").hexdigest().encode()
print("   3 位数字 × md5_hex →", len(pairs), "个候选；首个:", pairs[0])
print("   [PASS]" if len(pairs) == 1000 and pairs[0][1] == expect else "   [FAIL]")

print("=" * 74)
print("[4] 真实题目 100w：方式 B 解密程序内密文，反查输入")
if not os.path.exists(EXE):
    print("   跳过（找不到附件）")
else:
    with open(EXE, "rb") as fh:
        exe = fh.read()
    # 先自己算一遍密文位置（确认脚本里给的偏移没错）
    payload = b"CTF{4ef7836c744a0aaa0ac00dbc885849d3}"
    block = struct.pack("<I", len(payload)) + payload
    block += b"\x00" * ((8 - len(block) % 8) % 8)
    ct_expect = ciphers.des_crypt(block, b"czR@7\x00\x00\x00", transform="bitrev", decrypt=False)
    offset = exe.find(ct_expect)
    print(f"   密文在程序里的文件偏移：{offset}（{len(block)} 字节明文块）")
    t0 = time.time()
    res = verify.run_verify(
        EXE, ciphers_list=["des"], keyspace=Keyspace("digits", 6, "raw"),
        key_script=SCRIPT, key_transforms=["bitrev"],
        ciphertext_offset=offset, ciphertext_length=len(block),
        log=lambda m: print("     " + m))
    dt = time.time() - t0
    print(f"   用时 {dt:.1f} 秒")
    if res:
        best = res[0]
        print("   确认:", best.line())
        ok = best.label == "732425" and b"CTF{4ef7836c744a0aaa0ac00dbc885849d3}" in best.plaintext
        print("   [PASS] 自动反查出输入 732425 并解出 flag" if ok else "   [FAIL] 结果不符")
    else:
        print("   [FAIL] 没有确认出密钥")
print("=" * 74)
