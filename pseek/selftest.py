"""自检：用**合成的多层加密**验证整条流水线，不需要任何题目附件。

覆盖：
  1. 自定义 Base64 字符表 + 改造 RC4（模拟真实勒索类题目）
  2. hex → 整串倒序 → zlib（三层叠加，链式搜索自动发现）
  3. Base64 → AES-ECB（已知密钥）
  4. Base64 → 长度前缀 → DES（密钥位反转变体）
  5. oracle 自身的基本正确性
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import shutil
import sys
import tempfile
import zipfile
import zlib
from typing import List, Tuple

from . import alphabets, ciphers, langscore, oracles, pipeline, recover, search
from .transforms import Ctx

FLAG = b"flag{autocrypt_selftest_0123456789}"


def _custom_table(seed: bytes = b"selftest") -> bytes:
    """用确定性洗牌造一张"被打乱"的字符表（仍保持是标准表的排列）。"""
    chars = list(alphabets.B64_STD.chars)
    idx = 0
    out: List[int] = []
    while chars:
        idx = (idx * 1103515245 + 12345 + seed[0]) % 0x7FFFFFFF
        out.append(chars.pop(idx % len(chars)))
    return bytes(out)


def _encode_custom_b64(data: bytes, table: bytes) -> bytes:
    """标准 Base64 结果按自定义表替换（'=' 填充保持不变）。"""
    std = alphabets.B64_STD.chars
    out = bytearray()
    for c in base64.b64encode(data):
        ch = bytes([c])
        out.append(table[std.index(ch)] if ch in std else c)
    return bytes(out)


TEST_RESULTS: List[Tuple[str, bool, str]] = []


def _record(name: str, ok: bool, detail: str = "") -> None:
    TEST_RESULTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  —— {detail}" if detail else ""))


def test_oracles() -> None:
    print("\n[1] oracle 基本正确性")
    buf = io.BytesIO()
    from PIL import Image
    Image.new("RGB", (24, 24)).save(buf, format="JPEG")
    jpg = buf.getvalue()
    _record("JPEG 判定满分", oracles.best(jpg).score >= 0.99, str(oracles.best(jpg)))
    png_buf = io.BytesIO()
    Image.new("RGB", (24, 24)).save(png_buf, format="PNG")
    _record("PNG 判定通过（CRC 校验）", oracles.best(png_buf.getvalue()).score >= 0.85,
            str(oracles.best(png_buf.getvalue())))
    _record("flag 正则命中", oracles.best(FLAG).label == "FLAG")
    _record("随机数据不被误判", oracles.best(os.urandom(512)).score < 0.5)


def test_custom_table_rc4() -> None:
    print("\n[2] 自定义 Base64 字符表 + 改造 RC4（模拟真实题目）")
    table = _custom_table(b"K")
    key = b"Selftest_M4gic_K3y_2026"
    plain = ("这是自检用的说明文件。\n" * 3).encode("utf-8")
    logo = io.BytesIO()
    from PIL import Image
    Image.new("RGB", (64, 64), (12, 200, 90)).save(logo, format="JPEG")
    logo_bytes = logo.getvalue()

    def encrypt(data: bytes) -> bytes:
        return ciphers.rc4(_encode_custom_b64(data, table), key, mask_id=1, p1=0x72, p2=0x37)

    tmp = tempfile.mkdtemp(prefix="autocrypt_st2_")
    try:
        with open(os.path.join(tmp, "readme.txt"), "wb") as fh:
            fh.write(plain)
        for name, data in (("readme.txt", plain), ("flag.txt", FLAG), ("logo.jpg", logo_bytes)):
            with open(os.path.join(tmp, name + ".enc"), "wb") as fh:
                fh.write(encrypt(data))
        # 放一个"程序文件"，密钥字符串藏在里面（测密钥收集）
        with open(os.path.join(tmp, "cryptor.exe"), "wb") as fh:
            fh.write(b"MZ" + os.urandom(64) + b"\x00" + key + b"\x00" + os.urandom(64))
        out_dir = os.path.join(tmp, "out")
        rep = pipeline.run([tmp], pipeline.Options(out_dir=out_dir, timeout=60,
                                                   log=lambda m: print("     " + m)))
        flag_ok = any(oracles.best(o.plaintext).label == "FLAG" for o in rep.outcomes)
        _record("恢复出 flag", flag_ok,
                next((oracles.best(o.plaintext).detail for o in rep.outcomes
                      if oracles.best(o.plaintext).label == "FLAG"), ""))
        table_ok = any("b64solve" in o.recipe for o in rep.outcomes)
        _record("自动识别出“密码表被打乱”", table_ok,
                next((o.recipe for o in rep.outcomes if "b64solve" in o.recipe), ""))
        readme_out = os.path.join(out_dir, "readme.txt")
        same = os.path.exists(readme_out) and open(readme_out, "rb").read() == plain
        _record("readme 逐字节还原", same)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_three_layers() -> None:
    print("\n[3] 三层叠加：hex → 整串倒序 → zlib")
    inner = zlib.compress(b"note: " + FLAG + b"\n")
    data = base64.b16encode(inner[::-1])
    results = search.solve_bytes(data, Ctx(), depth=4, beam=10, time_budget=60, work_limit=8000)
    ok = bool(results) and oracles.best(results[0].data).label == "FLAG"
    _record("链式搜索还原三层", ok, results[0].recipe if results else "无结果")


def test_aes_known_key() -> None:
    print("\n[4] Base64 → AES-ECB（已知密钥）")
    key = b"0123456789abcdef"
    block = b"secret payload: " + FLAG
    block = block + b"\x00" * ((16 - len(block) % 16) % 16)
    data = base64.b64encode(ciphers.aes_crypt(block, key, decrypt=False))
    ctx = Ctx(keys=[key])
    results = search.solve_bytes(data, ctx, depth=3, beam=10, time_budget=60, work_limit=6000)
    ok = bool(results) and oracles.best(results[0].data).label == "FLAG"
    _record("AES-ECB 解出 flag", ok, results[0].recipe if results else "无结果")


def test_des_bitrev() -> None:
    print("\n[5] Base64 → 长度前缀 → DES（密钥位反转变体）")
    key = b"czR@7\x00\x00\x00"
    payload = b"CTF{4ef7836c744a0aaa0ac00dbc885849d3}"
    block = len(payload).to_bytes(4, "little") + payload
    block = block + b"\x00" * ((8 - len(block) % 8) % 8)
    ct = ciphers.des_crypt(block, key, transform="bitrev", decrypt=False)
    data = base64.b64encode(ct)
    ctx = Ctx(keys=[key], key_transforms=("bitrev", "raw"))
    results = search.solve_bytes(data, ctx, depth=4, beam=10, time_budget=60, work_limit=8000)
    ok = bool(results) and oracles.best(results[0].data).label == "FLAG"
    _record("DES 位反转变体解出 flag", ok, results[0].recipe if results else "无结果")


def test_standard_rc4_custom_table() -> None:
    print("\n[6] 标准 RC4 + 自定义字符表（无已知明文，靠结构约束）")
    table = _custom_table(b"Z")
    key = b"another_selftest_key"
    payload = io.BytesIO()
    from PIL import Image
    Image.new("RGB", (48, 48), (200, 30, 30)).save(payload, format="JPEG")
    plain = payload.getvalue()
    cipher = ciphers.rc4(_encode_custom_b64(plain, table), key)
    tmp = tempfile.mkdtemp(prefix="autocrypt_st6_")
    try:
        with open(os.path.join(tmp, "photo.jpg.enc"), "wb") as fh:
            fh.write(cipher)
        with open(os.path.join(tmp, "keys.txt"), "wb") as fh:
            fh.write(key)
        rep = pipeline.run([tmp], pipeline.Options(timeout=60, log=lambda m: print("     " + m)))
        ok = any(oracles.best(o.plaintext).label in ("JPEG",) for o in rep.outcomes)
        _record("无配对也能还原（字符表 + RC4）", ok,
                next((o.recipe for o in rep.outcomes), "无结果"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_identify() -> None:
    print("\n[7] 线索识别（借鉴 pyWhat / Name-That-Hash）")
    from . import identify
    cases = [
        ("5f4dcc3b5aa765d61d8327deb882cf99", "MD5 / MD4"),
        ("$2b$12$K3JNi5vQ8Tn1oQ2wZ9lZ4uJ8hVQ0mZ0oQ8Tn1oQ2wZ9lZ4uJ8hVQ0m", "bcrypt"),
        ("192.168.1.1", "IPv4"),
        ("AKIAIOSFODNN7EXAMPLE", "AWS Access Key"),
        ("550e8400-e29b-41d4-a716-446655440000", "UUID"),
    ]
    ok = 0
    for text, expect in cases:
        names = [h.name for h in identify.identify(text)]
        if any(expect in n for n in names):
            ok += 1
    _record("识别常见哈希/凭证/标识", ok == len(cases), f"{ok}/{len(cases)}")
    fake = identify.identify("4111111111111112")
    _record("Luhn 校验能挡住假卡号", not any("信用卡" in h.name for h in fake))


def test_xor_auto() -> None:
    print("\n[8] 多字节 XOR 自动分析（借鉴 xortool）")
    from . import xoranalysis
    plain = (b"flag{xor_autosolve}\n" + b"the quick brown fox jumps over the lazy dog again "
             b"and again through the green fields\n" * 3)
    key = b"k3y!"
    data = xoranalysis.xor_with(plain, key)
    results = xoranalysis.auto_xor(data, max_length=16)
    ok = bool(results) and results[0].key == key
    _record("自动猜出重复密钥", ok, results[0].line() if results else "无结果")


def test_base_magic() -> None:
    print("\n[9] 递归多层 Base 解码（借鉴 basecrack）")
    from . import baseN
    payload = b"flag{nested_base_layers}"
    nested = baseN.encode(baseN.encode(baseN.encode(payload, "base64"), "base32"), "base45")
    best = baseN.magic_decode_best(nested, max_depth=6)
    _record("三层嵌套自动剥完", bool(best) and payload in best.data,
            best.line() if best else "无结果")
    rounds = all(baseN.decode(baseN.encode(payload, n), n) == payload
                 for n in ("base36", "base45", "base58btc", "base62", "base85", "base91",
                           "base32", "base32hex", "z-base-32"))
    _record("各 Base 变体往返一致", rounds)


def test_carve() -> None:
    print("\n[10] 内嵌文件扫描与雕刻（借鉴 hexforge）")
    from . import carve
    import struct
    logo = io.BytesIO()
    from PIL import Image
    Image.new("RGB", (24, 24), (10, 200, 60)).save(logo, format="PNG")
    png = logo.getvalue()
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("flag.txt", "flag{carved_from_png}")
    blob = png + zip_buf.getvalue()
    report = carve.scan(blob, "combined.png", depth=1)
    found = {(c.ext, c.valid) for c in report.found}
    _record("在 PNG 后找到内嵌 ZIP", ("zip", True) in found)

    def _chunk(ctype, payload):
        return (struct.pack(">I", len(payload)) + ctype + payload
                + struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF))

    noise = zlib.compress(b"PK\x03\x04" * 8 + os.urandom(48), 0)
    fake_png = (b"\x89PNG\r\n\x1a\n"
                + _chunk(b"IHDR", struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0))
                + _chunk(b"IDAT", noise) + _chunk(b"IEND", b""))
    rep2 = carve.scan(fake_png, "noise.png")
    suppressed = not [c for c in rep2.found if c.ext == "zip"] and rep2.suppressed > 0
    _record("压缩数据里的假 magic 被抑制", suppressed, f"抑制 {rep2.suppressed} 个")
    hint = carve.xor_magic_hint(bytes(b ^ 0x5A for b in png[:32]) + png[32:])
    _record("单字节 XOR 混淆探测", bool(hint) and hint[0][0] == 0x5A, str(hint))


def test_classical() -> None:
    print("\n[11] 古典密码自动破解（借鉴 quipqiup / dcode）")
    from . import crack
    english = (b"It was a bright cold day in April, and the clocks were striking thirteen. "
               b"Winston Smith, his chin nuzzled into his breast in an effort to escape the "
               b"vile wind, slipped quickly through the glass doors of Victory Mansions.")
    text = english.decode()
    ct = crack.caesar(text, 7, decode=False).encode()
    res = crack.crack_caesar(ct)
    _record("凯撒", bool(res) and res[0].plaintext == english)
    vkey = "secret"
    out, i = [], 0
    for ch in text:
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            out.append(chr((ord(ch) - base + ord(vkey[i % len(vkey)]) - 97) % 26 + base))
            i += 1
        else:
            out.append(ch)
    res = crack.crack_vigenere("".join(out).encode(), 12)
    _record("维吉尼亚", bool(res) and res[0].plaintext[:60] == english[:60],
            res[0].line() if res else "无结果")
    _record("语言打分能区分人话与乱码",
            langscore.score_bytes(english).score > langscore.score_bytes(
                b"zx qwv mvb rtyu plok ijuh nbgf vfrt yhnb gtrf dcxs").score)


def test_verify() -> None:
    print("\n[12] 密钥确认（拿程序里存着的密文当标准答案）")
    from . import verify
    # 方式 A：程序里同时有明文常量和它的密文（crackme 常见）
    key = b"hunter2!"
    block = b"SECRET_PLAINTEXT"
    ct = verify.encrypt_with({"name": "aes", "params": {}}, key, block)
    blob = os.urandom(2048) + ct + os.urandom(2048)
    tmp = os.path.join(tempfile.gettempdir(), "autocrypt_selftest_crackme.bin")
    with open(tmp, "wb") as fh:
        fh.write(blob)
    try:
        res = verify.run_verify(tmp, ciphers_list=["aes"], keys=[b"nope", key],
                                key_transforms=["raw"], verify_plain=block, log=lambda _m: None)
        ok = bool(res) and res[0].key == key and res[0].offset == 2048
        _record("加密已知明文 → 在程序里反查密文", ok,
                res[0].line() if res else "无结果")
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    # 方式 B：解密程序内密文 → 用「长度前缀+flag」结构判据自证
    payload = b"flag{length_prefixed_secret}"
    plain = len(payload).to_bytes(4, "little") + payload
    plain += b"\x00" * ((8 - len(plain) % 8) % 8)
    ct2 = ciphers.des_crypt(plain, b"testkey\x00", transform="bitrev", decrypt=False)
    tmp2 = os.path.join(tempfile.gettempdir(), "autocrypt_selftest_ct.bin")
    with open(tmp2, "wb") as fh:
        fh.write(os.urandom(512) + ct2 + os.urandom(512))
    try:
        res = verify.run_verify(tmp2, ciphers_list=["des"],
                                keyspace=verify.Keyspace("none"),
                                keys=[b"testkey\x00"], key_transforms=["bitrev"],
                                ciphertext_offset=512, ciphertext_length=len(ct2),
                                log=lambda _m: None)
        ok = bool(res) and payload in res[0].plaintext
        _record("解密程序内密文 + 长度前缀判据", ok, res[0].line() if res else "无结果")
    finally:
        try:
            os.remove(tmp2)
        except OSError:
            pass

    pairs = list(verify.keyspace_keys(verify.Keyspace("digits", 3, "md5_hex")))
    expect = hashlib.md5(b"000").hexdigest().encode()
    _record("候选空间枚举 + 派生规则", len(pairs) == 1000 and pairs[0][1] == expect,
            f"{len(pairs)} 个候选")


def test_fragments() -> None:
    print("\n[13] flag 片段收集与拼接（flag 被拆成几段分别存储）")
    from . import fragments
    # 造一段"三段式"数据：明文片段 + hex 片段 + base64 片段，故意乱序放
    part_plain = b"XJUSEC{"
    part_hex = b"the_firs"
    part_b64 = b"t_step_is_the_hardest}"
    blob = (b"\x00" * 64 + part_hex.hex().encode() + b"\x00" * 40
            + base64.b64encode(part_b64) + b"\x00" * 8 + part_plain + b"\x00" * 128)
    flag = fragments.best_flag(blob)
    _record("拼出被拆散的 flag",
            bool(flag) and flag[0] == b"XJUSEC{the_first_step_is_the_hardest}",
            f"{flag[0].decode()} ← {[p.kind for p in flag[1]]}" if flag else "无结果")
    # 占位符不算数
    placeholder = fragments.best_flag(b"\x00" * 32 + b"XJUSEC{...}" + b"\x00" * 32)
    _record("用法说明里的 XJUSEC{...} 不算 flag", placeholder is None)


def test_pyc_formula() -> None:
    print("\n[14] Python 字节码读取 + 逐字节线性公式反推")
    import importlib.util
    import marshal
    from . import formula, pyc
    # (a) 跨版本 marshal 读取：用本机解释器造一个 .pyc，再自己解析回来
    src = "SECRET = b'abcdefgh'\n\ndef check(s):\n    for i, ch in enumerate(s):\n        assert (ord(ch) * 5 + i * 3) & 255 == SECRET[i % len(SECRET)]\n"
    code = compile(src, "<selftest>", "exec")
    blob = importlib.util.MAGIC_NUMBER + b"\x00" * 12 + marshal.dumps(code)
    got = pyc.load_code(blob)
    same = (got.co_consts if hasattr(got, "co_consts") else None) is None or True
    ok = ([(c.name if hasattr(c, "name") else None) for c in got.walk()] is not None
          and got.code == code.co_code and tuple(got.names) == tuple(code.co_names))
    _record(f"读取本机 Python {pyc.pyc_version(blob)} 的 .pyc",
            ok, f"code={[c.name for c in got.walk()]}")
    # (b) 线性公式反推：造一段"逐字节线性变形"，用 crib 解出来
    flag = b"flag{linear_formula_roundtrip_ok}"
    formula_true = formula.Formula(a=5, b=7, c=9, r=3, k=0x5A)
    target = formula_true.forward(flag)
    hits = formula.solve_blob(target, flag[:8], top=3)
    ok2 = bool(hits) and hits[0].plaintext == flag
    _record("用已知前缀解出线性公式并还原全文", ok2,
            f"{hits[0].formula} → {hits[0].plaintext.decode()}" if hits else "无结果")
    # (c) 目标字节不是直接给的，而要"两团常量异或 + 异或小整数"派生出来（R10 的形态）
    flag2 = b"flag{const_xor_derive_ok}"
    f2 = formula.Formula(a=5, b=7, c=9, r=3, k=0x5A)
    tgt = f2.forward(flag2)
    noise = bytes((i * 7 + 3) & 0xFF for i in range(len(flag2)))
    # 让 A ^ noise ^ 90 == tgt，于是真答案只藏在 XOR 派生链里
    A = bytes(x ^ y ^ 90 for x, y in zip(tgt, noise))
    found = formula.crack_pyc_constants([A, noise], ["flag{...}"], [90],
                                        crib=b"flag{", budget_seconds=30)
    _record("从两团常量派生目标字节并还原", bool(found), found[0][1].line() if found else "无结果")


def test_stego() -> None:
    print("\n[15] 隐写：BMP 位平面提取 + WAV 音频解码")
    import struct
    from . import stego
    # (a) 造一张 24 位 BMP，把文本塞进蓝通道最低位（MSB-first）——最经典的 LSB 隐写
    text = b"flag{lsb_hidden_ok}"
    w = h = 64
    bits = []
    for byte in text:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    stride = w * 3
    body = bytearray(b"\x80" * (stride * h))
    for i, b in enumerate(bits):
        row, col = divmod(i, w)                     # 每像素只藏蓝通道 1 位
        off = (h - 1 - row) * stride + col * 3      # 自底向上存放
        body[off] = (body[off] & 0xFE) | b
    header = (b"BM" + struct.pack("<IHHI", 54 + len(body), 0, 0, 54)
              + struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(body),
                            2835, 2835, 0, 0))
    bmp = header + bytes(body)
    info = stego.bmp_pixels(bmp)
    got = stego.lsb_extract(info, "b", 0, True, "row")[:len(text)]
    _record("BMP 蓝通道最低位能提取出藏进去的文本", got == text,
            f"提取={got!r}")
    cands = stego.scan_lsb(bmp, top=4)
    hit = any(text in c.data for c in cands)
    _record("scan_lsb 能自动枚举出正确组合", hit,
            f"{cands[0].tag()} → {cands[0].head[:32]!r}" if cands else "无候选")
    # 头部撒谎（宽高与数据长度矛盾）时，要能按数据长度纠正
    lie = (b"BM" + struct.pack("<IHHI", 54 + len(body), 0, 0, 54)
           + struct.pack("<IiiHHIIiiII", 40, w, 8, 1, 24, 0, len(body),
                         2835, 2835, 0, 0)) + bytes(body)
    p = stego.bmp_pixels(lie)
    _record("BMP 头部的宽高谎言会被按数据长度纠正",
            p is not None and p.fixed and p.height == h,
            p.describe() if p else "解析失败")

    # (b) 造一段 DTMF 音频（拨号音 "1234"），验证音频解码
    import math
    import struct as _s
    rate = 8000
    samples = bytearray()
    for ch in "1234":
        f1, f2 = stego._DTMF[ch]
        for n in range(int(rate * 0.06)):
            v = int(9000 * (math.sin(2 * math.pi * f1 * n / rate)
                            + math.sin(2 * math.pi * f2 * n / rate)) / 2)
            samples += _s.pack("<h", v)
        samples += b"\x00\x00" * int(rate * 0.03)          # 音之间留静音
    wav = (b"RIFF" + _s.pack("<I", 36 + len(samples)) + b"WAVEfmt "
           + _s.pack("<IHHIIHH", 16, 1, 1, rate, rate * 2, 2, 16)
           + b"data" + _s.pack("<I", len(samples)) + bytes(samples))
    decoded = stego.dtmf_decode(stego.wav_info(wav))
    _record("DTMF 双音拨号音能解出 1234", "1234" in decoded, f"解出={decoded!r}")


def _tiny_elf(code: bytes, code_addr: int, buf_addr: int, buf_fill: int,
              size: int = 0x1000) -> bytes:
    """手工拼一个最小可用的 ELF64：一个 RWX 段，代码 + 一块预填充的数据区。

    自检不想依赖外部附件，所以连测试用的二进制都自己造（也能顺便验证
    ELF 解析本身：程序头字段顺序、vaddr/p_filesz 这些）。
    """
    import struct as _s
    base = 0x400000
    code_off = 0x100
    buf_off = buf_addr - base
    body = bytearray(size)
    body[code_off:code_off + len(code)] = code
    body[buf_off:buf_off + 64] = bytes([buf_fill]) * 64
    total = len(body)
    ehdr = (_s.pack("<16sHHIQQQIHHHHHH",
                    b"\x7fELF\x02\x01\x01" + b"\x00" * 9, 2, 0x3E, 1,
                    base + code_off, 64, 0, 0, 64, 56, 1, 64, 0, 0)
            + b"\x00" * 0)                       # 64 字节 ELF 头
    phdr = _s.pack("<IIQQQQQQ", 1, 7, 0, base, base, total, size, 0x1000)
    out = bytearray(ehdr + phdr)
    out += b"\x00" * (total - len(out))
    out[code_off:code_off + len(code)] = code
    out[buf_off:buf_off + 64] = bytes([buf_fill]) * 64
    return bytes(out)


def test_emu() -> None:
    print("\n[16] 模拟执行取证：ELF 解析 + 跑函数 + 内存改写差分 + 置换表识别")
    from . import emu
    # 一段手写机器码：把 0..0x23 写进 rdi 指向的缓冲区，然后 ret
    #   31 c0              xor eax, eax
    #   88 04 07           mov byte ptr [rdi+rax], al
    #   48 ff c0           inc rax
    #   48 83 f8 24        cmp rax, 0x24
    #   75 f4              jne -12  (回到 mov)
    #   c3                 ret
    code = bytes([0x31, 0xC0, 0x88, 0x04, 0x07, 0x48, 0xFF, 0xC0,
                  0x48, 0x83, 0xF8, 0x24, 0x75, 0xF4, 0xC3])
    code_addr, buf_addr = 0x400100, 0x400800
    elf = _tiny_elf(code, code_addr, buf_addr, 0xAA)
    img = emu.ElfImage.parse(elf)
    seg = img.segments[0] if img.segments else None
    _record("ELF 程序头解析（段地址/大小/权限）",
            seg is not None and seg.vaddr == 0x400000 and seg.executable
            and seg.writable,
            seg.describe() if seg else "没解析出段")
    res = emu.run_function(img, code_addr, [buf_addr], max_ins=10000)
    table = [d for at, d in res["changes"] if at == buf_addr]
    _record("模拟执行能跑出结果并发现被改写的内存",
            res["stop"] == "函数返回" and bool(table),
            f"ins={res['ins']} stop={res['stop']} "
            f"改变={[hex(a) for a, _ in res['changes']]}")
    ok = (bool(table) and table[0][:36] == bytes(range(36))
          and any(at == buf_addr and n == 36 for at, n in res["tables"]))
    _record("自动识别出「0..n-1 的置换表」", ok,
            f"tables={[(hex(a), n) for a, n in res['tables']]}")


def _tiny_pe(code: bytes, strings: dict, imports: list,
             image_base: int = 0x140000000) -> bytes:
    """手工拼一个最小可用的 PE64（带导入表），用来验证 PE 解析与 Windows 模拟执行。

    布局：DOS 头(0x40) + PE 头 + 2 个节 —— ``.text``（代码/字符串/输入缓冲区，RWX）
    与 ``.idata``（导入描述符/ILT/IAT/hint-name/DLL 名）。字符串和 IAT 都用**绝对立即数**
    引用，省得在自检里做 RIP 相对重定位。
    """
    import struct as _s
    text_rva, idata_rva, raw_align = 0x1000, 0x2000, 0x400
    ilt_rva, iat_rva = idata_rva + 0x40, idata_rva + 0x60
    names_rva = idata_rva + 0x90
    dll_rva = idata_rva + 0x100
    text = bytearray(0x400)
    text[0:len(code)] = code
    for _name, (off, text_bytes) in strings.items():
        text[off:off + len(text_bytes)] = text_bytes
    idata = bytearray(0x400)
    dll = b"msvcrt.dll\x00"
    idata[dll_rva - idata_rva:dll_rva - idata_rva + len(dll)] = dll
    name_rvas = []
    cursor = names_rva
    for imp in imports:
        ent = b"\x00\x00" + imp.encode() + b"\x00"
        idata[cursor - idata_rva:cursor - idata_rva + len(ent)] = ent
        name_rvas.append(cursor)
        cursor += (len(ent) + 7) & ~7
    idata[0:20] = _s.pack("<IIIII", ilt_rva, 0, 0, dll_rva, iat_rva)
    for i, rva in enumerate(name_rvas):
        _s.pack_into("<Q", idata, ilt_rva - idata_rva + i * 8, rva)
        _s.pack_into("<Q", idata, iat_rva - idata_rva + i * 8, rva)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    _s.pack_into("<I", dos, 0x3C, 0x40)
    opt = bytearray(240)
    _s.pack_into("<H", opt, 0, 0x20B)                 # PE32+
    _s.pack_into("<I", opt, 16, text_rva)             # AddressOfEntryPoint
    _s.pack_into("<Q", opt, 24, image_base)
    _s.pack_into("<I", opt, 32, 0x1000)               # SectionAlignment
    _s.pack_into("<I", opt, 36, raw_align)            # FileAlignment
    _s.pack_into("<I", opt, 56, 0x3000)               # SizeOfImage
    _s.pack_into("<I", opt, 60, 0x400)                # SizeOfHeaders
    _s.pack_into("<H", opt, 68, 3)                    # 控制台子系统
    _s.pack_into("<I", opt, 108, 16)                  # NumberOfRvaAndSizes（PE32+ 在 108）
    _s.pack_into("<II", opt, 112 + 8, idata_rva, 40)  # DataDirectory[1] = 导入表
    coff = _s.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, len(opt), 0x22)
    sec_text = (b".text\x00\x00\x00" + _s.pack("<IIII", 0x400, text_rva, 0x400,
                                               raw_align)
                + b"\x00" * 12 + _s.pack("<I", 0xE0000020))
    sec_idata = (b".idata\x00\x00" + _s.pack("<IIII", 0x400, idata_rva, 0x400,
                                             raw_align + 0x400)
                 + b"\x00" * 12 + _s.pack("<I", 0xC0000040))
    # 节表必须紧跟在可选头之后（在这里踩过：先 padding 到 0x400 再拼节表，
    # 结果节表落到了 0x400 处，解析出来节名全空、导入表也读不到）
    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sec_text + sec_idata
    headers = headers + b"\x00" * (0x400 - len(headers))
    return headers + bytes(text) + bytes(idata)


def test_pe_emu() -> None:
    print("\n[17] Windows PE：解析 + 导入表打桩 + 让程序自己判对错")
    from . import emu, pe
    try:
        import keystone
    except ImportError:                                   # pragma: no cover
        _record("PE 模拟执行（需要 keystone 组装测试用 PE）", False, "未安装 keystone")
        return
    base = 0x140000000
    s_input, s_want, s_ok, s_bad, buf = 0x100, 0x110, 0x128, 0x140, 0x180
    iat = 0x2060                                          # 与 _tiny_pe 里一致
    asm = f"""
        sub rsp, 0x28
        mov rcx, {base + 0x1000 + s_input}
        mov rax, {base + iat + 16}
        call qword ptr [rax]
        mov rcx, {base + 0x1000 + buf}
        mov rax, {base + iat + 0}
        call qword ptr [rax]
        mov rcx, {base + 0x1000 + buf}
        mov rdx, {base + 0x1000 + s_want}
        mov rax, {base + iat + 8}
        call qword ptr [rax]
        test eax, eax
        jne wrong
        mov rcx, {base + 0x1000 + s_ok}
        mov rax, {base + iat + 16}
        call qword ptr [rax]
        xor eax, eax
        add rsp, 0x28
        ret
    wrong:
        mov rcx, {base + 0x1000 + s_bad}
        mov rax, {base + iat + 16}
        call qword ptr [rax]
        xor eax, eax
        add rsp, 0x28
        ret
    """
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _count = ks.asm(asm)
    strings = {
        "input": (s_input, b"Input: \x00"),
        "want": (s_want, b"flag{emulated_ok}\x00"),
        "ok": (s_ok, b"Correct!\x00"),
        "bad": (s_bad, b"Wrong\x00"),
    }
    blob = _tiny_pe(bytes(code), strings, ["gets", "strcmp", "puts"])
    img = pe.PeImage.parse(blob)
    ok_parse = (len(img.sections) == 2
                and {i.name for i in img.imports} == {"gets", "strcmp", "puts"}
                and img.entry == base + 0x1000)
    _record("PE 解析（节表/导入表/入口）", ok_parse,
            f"节={[s.name for s in img.sections]} "
            f"导入={[i.name for i in img.imports]}")
    good = emu.run_main(blob, stdin=b"flag{emulated_ok}\n", max_ins=200000)
    _record("喂正确输入 → 程序自己打印 Correct（result=True）",
            good["result"] is True, f"stdout={good['stdout']!r}")
    bad = emu.run_main(blob, stdin=b"flag{not_the_one}\n", max_ins=200000)
    _record("喂错误输入 → 程序打印 Wrong（result=False）",
            bad["result"] is False, f"stdout={bad['stdout']!r}")

    # (d) 执行轨迹：记录真实执行过的地址，并按真实边界反汇编。
    #     这是对付"跳进指令中间"花指令的唯一可靠办法——线性反汇编会从函数头一路
    #     顺着解，永远碰不到那些半路跳进来的字节。
    img2 = emu.load_image(blob)
    res = emu.run_function(img2, base + 0x1000, max_ins=20000, stdin=b"flag{emulated_ok}\n",
                           snapshot=False, coverage=True)
    lines = emu.trace_disasm(img2, res["coverage"], limit=200)
    _record("执行轨迹能记录访问过的地址",
            bool(res["coverage"]) and res["ins"] > 20,
            f"覆盖 {len(res['coverage'])} 个地址，共 {res['ins']} 条指令")
    _record("按真实执行边界反汇编出指令",
            any(m == "call" for _a, m, _o in lines) and len(lines) >= 10,
            f"解出 {len(lines)} 条，例：{[f'{m} {o}' for _a, m, o in lines[:3]]}")
    # (e) 崩溃时也要有寄存器现场（否则只有 RIP，看不出"它在访问什么"）
    weak = emu.run_function(img2, base + 0x1000, max_ins=20000, args=[0],
                            stop_at=[], snapshot=False)
    _record("模拟执行会返回寄存器现场/停止原因", "stop" in weak and "regs" in weak,
            str(weak.get("stop"))[:60])

    # (f) GUI/控制台通用的"自动判定"：宿主喂输入，看程序自己报成功还是失败
    from . import gui
    ok_out = gui.judge(img2, base + 0x1000, [], b"flag{emulated_ok}", max_ins=20000)
    bad_out = gui.judge(img2, base + 0x1000, [], b"flag{nope}", max_ins=20000)
    _record("自动判定：正确输入 → success、错误输入 → failure",
            ok_out["verdict"] == "success" and bad_out["verdict"] == "failure",
            f"正确={ok_out['verdict']}（{ok_out['texts'][:1]}） "
            f"错误={bad_out['verdict']}（{bad_out['texts'][:1]}）")
    _record("自动判定：能找到候选校验入口",
            bool(gui.candidate_entries(img2)),
            f"候选 {[hex(a) for a, _w in gui.candidate_entries(img2)][:3]}")


def test_crt_callbacks() -> None:
    """C++ 题的命门：`_initterm` 要**真的去调用表里的函数**，`getc` 要真的读 stdin。

    这两块以前是"静默不通"的：
      * `_initterm` 只返回 0 → 静态构造器一个都不跑 → `std::cout`/locale 未初始化 → abort；
      * `getc` 落到"未知 API 返回 0" → `std::cin` 读到无尽的 0 字节 → getc/ungetc 死循环。
    所以这里造一个 PE：入口先调 `_initterm(表头, 表尾)`，两个初始化函数各写一个标记字节，
    再调 `getc` 读一个字节。三件事都必须成立，否则说明回调机制或栈恢复又坏了。
    """
    print("\n[18] C++ CRT：_initterm 真的调用静态构造器 + getc 读 stdin")
    from . import emu
    try:
        import keystone
    except ImportError:                                   # pragma: no cover
        _record("CRT 回调（需要 keystone 组装测试用 PE）", False, "未安装 keystone")
        return
    base = 0x140000000
    table, flag1, flag2, flag3 = 0x200, 0x150, 0x151, 0x152
    fn1, fn2 = 0x300, 0x340
    iat = 0x2060
    # ⚠ 别在 keystone 的汇编串里写 `; 注释(带括号)`：它的 x86 解析器会
    #    把 `(start, end)` 当成操作数，报 "Invalid operand"。
    asm = f"""
        sub rsp, 0x28
        mov rcx, {base + 0x1000 + table}
        mov rdx, {base + 0x1000 + table + 0x10}
        mov rax, {base + iat + 0}
        call qword ptr [rax]
        mov rax, {base + iat + 8}
        call qword ptr [rax]
        mov rcx, {base + 0x1000 + flag3}
        mov byte ptr [rcx], al
        xor eax, eax
        add rsp, 0x28
        ret
    """
    init1 = f"""
        mov rax, {base + 0x1000 + flag1}
        mov byte ptr [rax], 1
        ret
    """
    init2 = f"""
        mov rax, {base + 0x1000 + flag2}
        mov byte ptr [rax], 2
        ret
    """
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm(asm)
    c1, _ = ks.asm(init1)
    c2, _ = ks.asm(init2)
    text = bytearray(0x400)
    text[0:len(code)] = code
    # table/fn1/fn2 都是**节内偏移**（.text 的 RVA 是 0x1000，所以不用再减 0x1000）
    text[fn1:fn1 + len(c1)] = bytes(c1)
    text[fn2:fn2 + len(c2)] = bytes(c2)
    import struct as _s
    text[table:table + 8] = _s.pack("<Q", base + 0x1000 + fn1)
    text[table + 8:table + 16] = _s.pack("<Q", base + 0x1000 + fn2)
    text[table + 16:table + 24] = _s.pack("<Q", 0)
    blob = _tiny_pe(bytes(text), {}, ["_initterm", "getc"])
    img = emu.load_image(blob)
    res = emu.run_function(img, base + 0x1000, max_ins=20000,
                           stdin=b"a", snapshot=False)
    # 标记字节是程序**写到内存里**的，要从模拟器的内存读，不能读文件字节
    uc = res.get("_uc")
    flags = bytes(uc.mem_read(base + 0x1000 + flag1, 3)) if uc else b""
    _record("_initterm 真的调用了表里的两个静态构造器（且按顺序）",
            flags[0] == 1 and flags[1] == 2,
            f"标记字节={flags[:2].hex()}（应为 0102）；stop={res.get('stop')}")
    _record("getc 从 stdin 读到了字节",
            flags[2] == ord("a"), f"读到={flags[2]!r}（应为 97）")
    _record("回调跑完后栈已恢复、入口正常返回",
            "返回" in str(res.get("stop")), f"stop={res.get('stop')}")


def test_triage() -> None:
    """triage 是"指路层"：它不造答案，但必须给出**能直接复制执行**的下一步。"""
    print("\n[19] triage：侦察 + 排序好的下一步（不造答案）")
    from . import triage
    info = triage.triage_blob(b"just some text, not a binary", "note.txt")
    _record("triage：非二进制不崩，给 B 档 + scan 建议",
            info["tier"] == "B" and any("scan" in c for c, _w in info["next_steps"]),
            f"tier={info['tier']} steps={[c for c, _w in info['next_steps']][:2]}")
    try:
        import keystone
    except ImportError:                                   # pragma: no cover
        _record("triage：PE 样本（需要 keystone）", False, "未安装 keystone")
        return
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm("xor eax, eax\nret")
    strings = {"ok": (0x100, b"*** SUCCESS! ***\x00"),
               "bad": (0x150, b"[!] Wrong password.\x00")}
    blob = _tiny_pe(bytes(code), strings, ["puts"])
    info2 = triage.triage_blob(blob, "demo.exe")
    _record("triage：PE 样本识别出身份/运行时/输入口",
            "PE" in str(info2["kind"]) and bool(info2["runtime"]) and bool(info2["input_channels"]),
            f"{info2['kind']} | {info2['runtime'][:1]}")
    # 档位判定单独测（纯函数、确定性）：四种关键输入各测一次。
    # 不靠合成 PE 去撞"文案能不能被扫到"，那样测的是扫描器的节过滤，不是判定逻辑。
    cases = [
        ("C++ 无壳 + 有成败文案 → A",
         {"runtime": ["MSVC C++ 运行库"], "packed": {"kind": None},
          "verdict_strings": {"success": [1], "failure": [2]}}, "A"),
        (".NET → B",
         {"runtime": [".NET / IL（CLR 头 v2.5）"], "packed": {"kind": None},
          "verdict_strings": {"success": [1], "failure": [2]}}, "B"),
        ("UPX → B（先脱壳）",
         {"runtime": ["MSVC C++"], "packed": {"kind": "upx"},
          "verdict_strings": {"success": [1], "failure": [2]}}, "B"),
        ("没有成败文案 → B",
         {"runtime": ["原生"], "packed": {"kind": None},
          "verdict_strings": {"success": [], "failure": []}}, "B"),
        ("低置信度“可能加壳”不该降档 → A",
         {"runtime": ["MSVC C++"], "packed": {"kind": "other", "name": "可能加壳", "confidence": "低"},
          "verdict_strings": {"success": [1], "failure": [2]}}, "A"),
    ]
    bad = [(name, triage._tier(info)[0], want) for name, info, want in cases
           if triage._tier(info)[0] != want]
    _record("triage：档位判定（A/B）在五种关键输入上都正确", not bad,
            f"不符：{bad}" if bad else f"{len(cases)} 例全对")
    text = triage.format_report(info2)
    _record("triage：报告里能同时看到档位与下一步",
            "档" in text and "下一步" in text, "")
    _record("triage：带空格的路径会被引号包住（否则复制出来跑不通）",
            triage._q("a b.exe").startswith('"'), triage._q("a b.exe"))
    _record("triage：普通路径不会被多包一层引号",
            triage._q("demo.exe") == "demo.exe", triage._q("demo.exe"))


def test_sigscan() -> None:
    print("\n[18] 签名扫描：被改过的加密常量 + 打包器识别")
    import struct as _s
    from . import sigscan

    class _Sec:
        def __init__(self, data, addr, name=".data"):
            self.data, self.vaddr, self.name = data, addr, name
            self.writable, self.executable = True, False
            self.vsize = self.raw_size = len(data)

        def __len__(self):
            return len(self.data)

    class _Img:
        entry = 0
        imports: list = []

        def __init__(self, segs):
            self.segments = segs

    # (a) 被改过几个字节的 AES S 盒 + 被改一位的 TEA delta 都要能认出来
    bad_sbox = bytearray(sigscan.AES_SBOX)
    bad_sbox[10] ^= 0x11
    bad_sbox[100] ^= 0x22
    blob = (bytes(bad_sbox) + _s.pack("<I", 0x9E3779B9 ^ 0x40) + b"\x00" * 32
            + sigscan.AES_SBOX)                       # 末尾再放一个"没被改"的
    hits = sigscan.scan_crypto(_Img([_Sec(blob, 0x1000)]))
    names = {h.name for h in hits}
    modified = [h for h in hits if not h.exact and h.name == "AES S 盒"]
    tea = [h for h in hits if h.name == "TEA delta" and not h.exact]
    _record("能认出「被改过几个字节」的 AES S 盒",
            bool(modified) and modified[0].diffs[:3] == [10, 100],
            f"{modified[0].line()}" if modified else "没认出来")
    _record("能认出「被改过一位」的 TEA delta（按位相似度）",
            bool(tea), tea[0].line() if tea else "没认出来")
    _record("没被改的常量报成完全一致",
            "AES S 盒" in names and any(h.exact for h in hits if h.name == "AES S 盒"),
            f"命中 {len(hits)} 处")

    # (b) 打包器识别：UPX 的节名 + 高熵 + 入口在末节
    upx_img = _Img([_Sec(b"\x90" * 0x200, 0x401000, "UPX0"),
                    _Sec(bytes(range(256)) * 64, 0x403000, "UPX1")])
    upx_img.entry = 0x403000
    verdict = sigscan.detect_packer(upx_img)
    _record("靠节名认出 UPX 并给出证据",
            verdict is not None and "UPX" in verdict.name and verdict.evidence,
            verdict.line() if verdict else "没认出来")
    # (c) 普通程序不能误报成壳（这条是踩过坑加的：曾把 MSVC 函数序言当签名）
    #     注意测试镜像要**像真程序**：代码段是重复的指令模式（低熵），
    #     有导入表，入口在第一个节里。用 `bytes(range(256))*N` 当 .text 是不现实的——
    #     那玩意熵必然 8.0，被判成"高熵"并不算误报。
    code = (b"\x55\x8b\xec\x83\xec\x10\xe8\x12\x00\x00\x00\x33\xc0\x5d\xc3\x90") * 64
    normal = _Img([_Sec(code, 0x401000, ".text"),
                   _Sec(b"\x90" * 0x100, 0x402000, ".rdata")])
    normal.entry = 0x401000
    normal.imports = [object()]                     # 有导入表 → 不像壳
    normal_verdict = sigscan.detect_packer(normal)
    _record("普通程序不会被误判成加壳",
            normal_verdict is None or normal_verdict.confidence == "低",
            normal_verdict.line() if normal_verdict else "未报壳")

    # (d) 异或加密的字符串自动解密
    #     单字节路径默认开启且要求"像人话"（含常见词），实测在真实样本上零假阳性；
    #     多字节路径假阳性多，必须显式 opt-in。
    plain = b"Registration failed, please try again\x00"
    blob1 = b"\x00" * 16 + bytes(c ^ 0x5A for c in plain) + b"\x00" * 16
    hits1 = sigscan.decrypt_strings(_Img([_Sec(blob1, 0x401000, ".rdata")]), limit=5)
    got1 = [t for t, _a, _n in hits1]
    _record("单字节异或的提示语能自动解出来",
            any("Registration failed" in t for t in got1),
            f"命中 {len(got1)} 条，例：{got1[:2]}")
    key = b"\x5a\x13\x77"
    plain2 = b"Congratulations! you got the right serial\x00"
    blob2 = (b"\x00" * 16
             + bytes(plain2[i] ^ key[i % 3] for i in range(len(plain2)))
             + b"\x00" * 16)
    img2 = _Img([_Sec(blob2, 0x401000, ".rdata")])
    quiet = sigscan.decrypt_strings(img2, limit=5)
    loud = sigscan.decrypt_strings(img2, limit=5, try_crib=True)
    _record("多字节异或默认不报（避免假阳性），opt-in 后能解出",
            not quiet and any("right serial" in t for t, _a, _n in loud),
            f"默认 {len(quiet)} 条；opt-in 命中 "
            f"{[t[:34] for t, _a, _n in loud][:1]}")


def main() -> int:
    print("=" * 64)
    print("autocrypt 自检：用合成题目验证整条流水线")
    print("=" * 64)
    test_oracles()
    test_custom_table_rc4()
    test_three_layers()
    test_aes_known_key()
    test_des_bitrev()
    test_standard_rc4_custom_table()
    test_identify()
    test_xor_auto()
    test_base_magic()
    test_carve()
    test_classical()
    test_verify()
    test_fragments()
    test_pyc_formula()
    test_stego()
    test_emu()
    test_pe_emu()
    test_crt_callbacks()
    test_triage()
    test_sigscan()
    passed = sum(1 for _n, ok, _d in TEST_RESULTS if ok)
    total = len(TEST_RESULTS)
    print("\n" + "=" * 64)
    print(f"自检结果：{passed}/{total} 通过")
    for name, ok, detail in TEST_RESULTS:
        if not ok:
            print(f"  失败：{name}  {detail}")
    print("=" * 64)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
