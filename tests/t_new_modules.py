"""新模块自测：语言打分 / 线索识别 / XOR 分析 / Base 家族 / 内嵌雕刻。"""
import io
import os
import sys
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from PIL import Image

from dkit import baseN, carve, identify, langscore, xoranalysis

print("=" * 70)
print("[1] 语言打分")
print("  模型:", langscore.describe_model())
samples = {
    "英文正常": b"The quick brown fox jumps over the lazy dog and then runs away quickly.",
    "英文乱码": b"Zx qwv mvb rtyu plok ijuh nbgf vfrt yhnb gtrf dcxs wqaz plmo ikjn uhby",
    "中文": "这是一段中文说明文字，用来测试语言模型对中文的识别能力。".encode(),
    "随机字节": os.urandom(64),
    "base64": b"VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==",
}
for name, data in samples.items():
    print(f"  {name:10s} {langscore.score_bytes(data)}")
assert langscore.score_bytes(samples["英文正常"]).score > langscore.score_bytes(samples["英文乱码"]).score
print("  [PASS] 正常英文得分高于乱码")

print("=" * 70)
print("[2] 线索识别")
cases = [
    ("5f4dcc3b5aa765d61d8327deb882cf99", "MD5 / MD4"),
    ("8843d7f92416211de9ebb963ff4ce28125932878", "SHA-1"),
    ("$2b$12$K3JNi5vQ8Tn1oQ2wZ9lZ4uJ8hVQ0mZ0oQ8Tn1oQ2wZ9lZ4uJ8hVQ0m", "bcrypt"),
    ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "JWT"),
    ("192.168.1.1", "IPv4"),
    ("AKIAIOSFODNN7EXAMPLE", "AWS Access Key"),
    ("https://example.com/path?q=1", "URL"),
    ("user@example.com", "电子邮箱"),
    ("550e8400-e29b-41d4-a716-446655440000", "UUID"),
    ("flag{this_is_a_test_flag}", "Flag"),
    ("-----BEGIN RSA PRIVATE KEY-----", "私钥"),
    ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "比特币地址"),
    ("0x52908400098527886E0F7030069857D2E4169EE7", "以太坊地址"),
    ("4111111111111111", "信用卡号"),
]
ok = 0
for text, label in cases:
    hits = identify.identify(text)
    names = [h.name for h in hits]
    hit = any(label in n for n in names)
    ok += hit
    print(f"  {'✔' if hit else '✘'} {label:14s} → {names[:2]}")
hits = identify.identify("4111111111111112")   # Luhn 不通过
print("  Luhn 校验能挡住假卡号:", not any("信用卡" in h.name for h in hits))
print(f"  [{'PASS' if ok == len(cases) else 'FAIL'}] {ok}/{len(cases)} 识别正确")

print("=" * 70)
print("[3] 多字节 XOR 自动分析")
plain = (b"flag{xor_key_length_detection_works}\n" * 3
         + b"The quick brown fox jumps over the lazy dog. This message is here to give "
           b"the language model enough ordinary English text to work with.\n" * 3)
key = b"s3cr3t"
cipher = xoranalysis.xor_with(plain, key)
res = xoranalysis.auto_xor(cipher, max_length=16)
best = res[0]
print("  密钥长度猜测(等字符计数):", [n for n, _ in xoranalysis.guess_key_lengths(cipher, 16)[:4]])
for r in res[:3]:
    print("   候选:", r.line())
true_score = [r for r in res if r.key == key]
print("  真密钥在候选里:", bool(true_score), true_score[0].score if true_score else "-")
print("  [PASS] 自动恢复出密钥" if best.key == key else f"  [FAIL] 得到 {best.key!r}")

print("=" * 70)
print("[4] Base 家族与递归多层解码")
data = b"flag{nested_base_decoding}"
for name in ("base36", "base45", "base58btc", "base62", "base85", "ascii85", "z85", "base91",
             "base32", "base32hex", "z-base-32", "base32crockford"):
    enc = baseN.encode(data, name)
    dec = baseN.decode(enc, name)
    good = dec == data or (name == "z85" and dec.startswith(data))   # Z85 要求 4 字节对齐
    print(f"  {name:16s} {'✔' if good else '✘'} {enc[:40]!r}")
nested = baseN.encode(baseN.encode(baseN.encode(data, "base64"), "base32"), "base45")
magic = baseN.magic_decode_best(nested, max_depth=6)
print("  三层嵌套:", magic.line() if magic else "失败")
print("  [PASS] 递归解出原文" if magic and data in magic.data else "  [FAIL]")

print("=" * 70)
print("[5] 内嵌文件雕刻")
buf = io.BytesIO()
Image.new("RGB", (32, 32), (240, 30, 30)).save(buf, format="PNG")
png = buf.getvalue()
z = io.BytesIO()
with zipfile.ZipFile(z, "w") as zf:
    zf.writestr("flag.txt", "flag{embedded_in_png}")
zip_bytes = z.getvalue()
blob = png + zip_bytes
rep = carve.scan(blob, "combined.png", depth=1)
print(carve.report_text(rep))
found_zip = any(c.ext == "zip" and c.valid for c in rep.found)
found_png = any(c.ext == "png" and c.valid for c in rep.found)
print("  [PASS] 找到 PNG 与内嵌 ZIP" if (found_zip and found_png) else "  [FAIL]")
print("  压缩区抑制计数:", rep.suppressed)

xor_blob = bytes(b ^ 0x5A for b in png[:64]) + png[64:]
hints = carve.xor_magic_hint(xor_blob)
print("  XOR 混淆探测:", hints)
print("  [PASS] 探测到 XOR 混淆" if hints and hints[0][0] == 0x5A else "  [FAIL]")
print("=" * 70)
