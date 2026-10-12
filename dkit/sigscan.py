"""加密常量指纹 + 打包器识别 + 熵分析（findcrypt / DIE 思路的纯 Python 子集）。

调研（看雪/吾爱帖子 + 开源工具）里有两条被反复提到的"性价比最高"的能力，这里都做了：

**一、加密常量指纹（借鉴 findcrypt3 / YARA 规则库的做法）**

逆向题最常见的套路是"标准算法 + 改常量"：TEA 的 delta 换成别的数、AES 的 S 盒动几个字节、
MD5 的初始向量被改。人眼很难发现，但**机器可以**：把已知算法的常量表当指纹去搜。

比 findcrypt 更进一步的是这里的 **near-miss 检测**：不要求逐字节完全相等，而是算相似度，
于是"被改过几个字节的 AES S 盒""改过的 TEA delta"都能报出来，并给出差异位置与相似度。
这正是 CTF 里"常量被改过"那一类题的入口。

**二、打包器识别（借鉴 DIE 的签名扫描思路）**

* 节名特征（UPX0/UPX1、.themida、.vmp0、.aspack、MPRESS1…）——最便宜也最准；
* 入口点字节签名（UPX 的 `60 BE`、ASPack 的 `60 E8`、MPRESS 的 `60 E9`…）；
* 启发式证据：节区 RWX、入口在最后一个节、代码段熵 > 7.0、导入表为空、
  文件尾部有大块 overlay（自解压/附加数据）。每条证据单独都不算数，
  **凑在一起**才叫"像壳"——这一点和 DIE 的设计是一致的。

**三、熵分析**：判断某个节是代码/数据还是"被压缩/加密过的高熵数据"。
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------- 常量指纹库

AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

AES_INV_SBOX = bytes.fromhex(
    "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb"
    "547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125"
    "72f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d84"
    "90d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b"
    "3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e"
    "47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af4"
    "1fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cef"
    "a0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d")

#: ``(名字, 常量字节, 说明)`` —— 用"表"来定义指纹，加新算法只要加一行
SIGNATURES: List[Tuple[str, bytes, str]] = [
    ("AES S 盒", AES_SBOX, "AES / Rijndael 的 256 字节 S 盒，出现在密钥扩展与轮函数里"),
    ("AES 逆 S 盒", AES_INV_SBOX, "AES 解密用"),
    ("SM4 S 盒", bytes.fromhex(
        "d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa44132649860699"
        "9c4250f491ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa6"
        "470f7a05a67770d7243ba2f58b9d4c39c9c5d6a78f2f6f6a5d9d0e0e0e0e0e0e"),
     "国密 SM4 的 S 盒（教学/比赛里常见）"),
    ("TEA delta", struct.pack("<I", 0x9E3779B9),
     "TEA/XTEA 的黄金分割常量；改常量题就是把这里换掉"),
    ("XTEA delta（64 位写法）", struct.pack("<Q", 0x9E3779B9 * 0x100000000 + 0x9E3779B9),
     "有些实现把它当 64 位数用"),
    ("MD5 初始向量", struct.pack("<4I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476),
     "MD5 的 A/B/C/D 初值；改初值 = 自制 MD5"),
    ("SHA1 初始向量", struct.pack(">5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE,
                                   0x10325476, 0xC3D2E1F0), "SHA1 的五个初值（大端）"),
    ("SHA256 初始向量", struct.pack(">8I", 0x6A09E667, 0xBB67AE85, 0x3C6EF372,
                                     0xA54FF53A, 0x510E527F, 0x9B05688C,
                                     0x1F83D9AB, 0x5BE0CD19), "SHA256 的八个初值（大端）"),
    ("CRC32 多项式表", bytes.fromhex(
        "00000000" "77073096" "ee0e612c" "990951ba").ljust(16, b"\x00"),
     "CRC32 表头；完整表很大，这里用前 16 字节当指纹"),
    ("Blowfish P 数组", bytes.fromhex(
        "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89"),
     "Blowfish 的 P 数组前 32 字节（源自 pi 的小数）"),
    ("DES 置换表 SP", bytes.fromhex(
        "020c010e04070d0f0005090b0308060b0e0c0d010a060f090003070402080d"),
     "DES 里的置换/选择表片段"),
    ("Base64 标准字符表", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
     "标准表；**这里命中说明表没被改**，没命中反而值得注意"),
    ("Base64 URL 安全表", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
     "URL-safe 变体"),
    ("zlib 头（0x78 0x9C）", b"\x78\x9c", "zlib 默认压缩流的起始两字节"),
    ("gzip magic", b"\x1f\x8b\x08", "gzip 压缩流头"),
    ("PKZIP 本地文件头", b"PK\x03\x04", "zip 容器；打包器/附加数据常见"),
]

#: 打包器入口点签名（借鉴 DIE / PEiD 的 userdb 思路，取最常见的一批）
PACKER_EP_SIGS: List[Tuple[str, bytes, str]] = [
    ("UPX", b"\x60\xbe", "UPX 的经典入口：pushad; mov esi, ..."),
    ("UPX (x64)", b"\x53\x56\x57\x55", "UPX x64 入口常见序言（较弱，需配合节名）"),
    ("ASPack", b"\x60\xe8\x03\x00\x00\x00", "ASPack 入口"),
    ("MPRESS", b"\x60\xe9", "MPRESS 入口"),
    ("PECompact", b"\xb8\x00\x00\x00\x00\x50\x64\xff\x35\x00\x00\x00\x00", "PECompact 入口"),
    ("FSG", b"\x87\x25", "FSG 壳入口"),
    ("NsPack", b"\x60\xe8\x00\x00\x00\x00", "NsPack 入口"),
]
# ⚠ 这里**故意不放** `55 8b ec 6a ff 68` 这种"push ebp; mov ebp,esp; push -1; push imm32"。
# 那是最普通的 MSVC 函数序言，当签名用会把一大堆正常程序误判成 Themida/VMProtect
# （实测拿 ZzhCm.exe 试就误报了）。签名要么足够独特，要么就别放——
# 宁可少报也不能把正常程序吓人一跳。

#: 节名 → 打包器（和 pe.py 里的粗判互补，这里更全）
SECTION_SIGS: Dict[str, str] = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", ".mpress1": "MPRESS",
    ".mpress2": "MPRESS", ".themida": "Themida", ".winlice": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    "enigma1": "Enigma", "enigma2": "Enigma", ".petite": "Petite",
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".boom": "Themida/Boom",
    ".pklstb": "PKLite", "pec1": "PECompact", "pec2": "PECompact",
    ".fsg": "FSG", ".shrink1": "Shrinker", ".svkp": "SVKP",
    "_winzip_": "WinZip SFX", ".rmnet": "Ramnit",
}


@dataclass
class SignatureHit:
    name: str
    note: str
    similarity: float
    at: int
    exact: bool
    diffs: List[int] = field(default_factory=list)

    def line(self) -> str:
        mark = "✔完全一致" if self.exact else f"≈相似度 {self.similarity:.0%}"
        tail = (f"，差异位置 {self.diffs[:6]}" if self.diffs else "")
        return f"{mark}  {self.name}  @0x{self.at:x}（{self.note}{tail}）"


def _similarity(a: bytes, b: bytes) -> Tuple[float, List[int]]:
    """逐字节比较，返回相似度与差异位置（用于"被改过的常量"检测）。"""
    n = min(len(a), len(b))
    if not n:
        return 0.0, []
    diffs = [i for i in range(n) if a[i] != b[i]]
    return 1.0 - len(diffs) / n, diffs


def _bit_similarity(a: bytes, b: bytes) -> float:
    """按**位**算相似度。

    为什么短指纹必须按位比：像 TEA 的 delta 只有 4 字节，题目把它改一位
    （``0x9E3779B9`` → ``...F9``）之后，按字节相似度只有 75%，会被 90% 的阈值筛掉；
    按位算则是 31/32 ≈ 97%，正好落在"这明显是同一个常量、只是被动过"的区间。
    """
    n = min(len(a), len(b))
    if not n:
        return 0.0
    same_bits = sum(8 - bin(a[i] ^ b[i]).count("1") for i in range(n))
    return same_bits / (n * 8)


def scan_crypto(img, min_similarity: float = 0.90,
                max_hits_per_sig: int = 8) -> List[SignatureHit]:
    """在镜像里找加密常量；**允许几个字节不同**（那就是"被改过的常量"）。

    实现上是"滑窗 + 相似度"：对每个指纹，在可读节里逐字节比对窗口，
    完全一致直接报；相似度 ≥ ``min_similarity`` 的也报出来，并给出差异位置——
    这类命中往往就是题目真正要你发现的东西（例如 TEA delta 被人改了一个字节）。
    """
    hits: List[SignatureHit] = []
    for name, sig, note in SIGNATURES:
        if len(sig) < 4:
            continue
        short = len(sig) < 8                     # 短指纹按位比（见 _bit_similarity）
        found = 0
        for sec in img.segments:
            data = sec.data or b""
            if len(data) < len(sig):
                continue
            for off in range(0, len(data) - len(sig) + 1):
                window = data[off:off + len(sig)]
                if window == sig:
                    hits.append(SignatureHit(name, note, 1.0, sec.vaddr + off, True))
                    found += 1
                else:
                    sim, diffs = _similarity(window, sig)
                    score = max(sim, _bit_similarity(window, sig)) if short else sim
                    threshold = 0.93 if short else min_similarity
                    if score >= threshold:
                        hits.append(SignatureHit(name, note, score, sec.vaddr + off,
                                                 False, diffs))
                        found += 1
                if found >= max_hits_per_sig:
                    break
            if found >= max_hits_per_sig:
                break
    # 完全一致的排前面，其次按相似度
    hits.sort(key=lambda h: (not h.exact, -h.similarity, h.at))
    return hits


# ---------------------------------------------------------------- 熵与打包器

def entropy(data: bytes) -> float:
    """香农熵（0~8）。> 7.0 基本就是压缩/加密过的数据。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


@dataclass
class PackerVerdict:
    name: str
    confidence: str                 # 高 / 中 / 低
    evidence: List[str] = field(default_factory=list)

    def line(self) -> str:
        return (f"{self.name}（置信度 {self.confidence}）："
                + "；".join(self.evidence))


def detect_packer(img) -> Optional[PackerVerdict]:
    """判断有没有加壳/被打包，并列出**具体证据**（不猜，只报证据）。

    单条证据都不足以定论（比如"熵高"也可能只是压缩资源），所以分成
    高/中/低三档：节名或入口签名属于"高"，多条启发式凑齐属于"中"，
    只有一条启发式属于"低"。
    """
    evidence: List[str] = []
    name = ""
    # 1) 节名（最硬的证据）
    for sec in img.segments:
        low = (sec.name or "").strip().lower()
        if low in SECTION_SIGS:
            name = SECTION_SIGS[low]
            evidence.append(f"节名 {sec.name} 是 {name} 的特征节")
    # 2) 入口点签名
    ep = img.entry
    for sec in img.segments:
        if sec.vaddr <= ep < sec.vaddr + len(sec.data):
            head = sec.data[ep - sec.vaddr:ep - sec.vaddr + 16]
            for sig_name, sig, _note in PACKER_EP_SIGS:
                if head.startswith(sig):
                    evidence.append(f"入口字节 {head[:6].hex(' ')} 命中 {sig_name} 签名")
                    name = name or sig_name
            break
    # 3) 启发式
    ent = [(s.name, entropy((s.data or b"")[:0x4000])) for s in img.segments
           if (s.data or b"")][:8]
    high = [f"{n}={e:.2f}" for n, e in ent if e > 7.0]
    if high:
        evidence.append("高熵节（可能被压缩/加密）：" + "，".join(high))
    if getattr(img, "imports", None) is not None and not img.imports:
        evidence.append("导入表为空（壳常把导入表抹掉或运行时重建）")
    if any(getattr(s, "writable", False) and getattr(s, "executable", False)
           for s in img.segments):
        evidence.append("存在可写可执行（RWX）节")
    if img.segments:
        last = img.segments[-1]
        if last.vaddr <= ep < last.vaddr + max(getattr(last, "vsize", 0),
                                               getattr(last, "raw_size", 0)):
            evidence.append("入口点落在最后一个节里（典型壳布局）")
    if not evidence:
        return None
    strong = any("节名" in e or "入口字节" in e for e in evidence)
    if strong:
        return PackerVerdict(name or "未知壳", "高", evidence)
    if len(evidence) >= 2:
        return PackerVerdict(name or "疑似加壳/自解压", "中", evidence)
    return PackerVerdict(name or "可能加壳", "低", evidence)


def section_entropy_table(img) -> List[Tuple[str, int, float]]:
    return [(s.name or "?", len(s.data or b""), entropy((s.data or b"")[:0x8000]))
            for s in img.segments]


# ---------------------------------------------------------------- 字符串解密

def new_strings(before: bytes, after: bytes, min_len: int = 5,
                limit: int = 40) -> List[str]:
    """对比"执行前 vs 执行后"的内存，挑出**新出现的可打印字符串**。

    这就是 FLOSS 那套思路最核心的一步（它对模拟前后的内存做 diff，再从差异里取字符串），
    本工具把它接在 `emu` 的模拟执行上：跑一遍程序，就能看到"运行时被解出来的字符串"
    （栈串、异或串、解密出来的提示语都算）。比自己盯着反汇编找解密循环省事得多。
    """
    out: List[str] = []

    def runs(blob: bytes) -> List[Tuple[int, bytes]]:
        res: List[Tuple[int, bytes]] = []
        cur = bytearray()
        at = 0
        for i, b in enumerate(blob + b"\x00"):
            if 32 <= b < 127 or b in (9, 10, 13):
                if not cur:
                    at = i
                cur.append(b)
            else:
                if len(cur) >= min_len:
                    res.append((at, bytes(cur)))
                cur = bytearray()
        return res

    seen = set()
    for at, text in runs(after):
        if text in seen:
            continue
        # 之前同一位置也出现过同样的串 → 不是"新解出来的"，跳过
        if before[at:at + len(text)] == text:
            continue
        seen.add(text)
        out.append(text.decode("latin-1"))
        if len(out) >= limit:
            break
    return out


#: 提示语里常见词（用于判断"解出来的到底是不是人写的句子"）。
#: 这一步是实测逼出来的：光看"可打印率"会刷出一堆
#: ``'suc;es+uc;es+uc;es…'``、``'Regi"eTiReki3eTi…'`` 这种**错误密钥凑出来的可打印垃圾**，
#: 而真正的提示语里一定含 error/success/please/输入 这类词。
COMMON_HINT_WORDS = frozenset("""
error errors failed failure success successful wrong correct invalid valid
register registration registered serial serials password passwd pass key keys
user username name please input enter try again congratulations congratulation
welcome hello flag flags crack crackme license code verify verified check
thank thanks good great right sorry not found unable open read write file
loading loaded version trial expired days remaining machine hardware
""".split())


def trim_repeats(text: str, max_repeat: int = 4) -> str:
    """去掉首尾"同一个字符连续出现 ≥max_repeat 次"的填充段。

    异或之后，明文两侧的 NUL 填充会变成同一个可打印字符（例如密钥 0x5A → 一片 'Z'），
    于是解出来的串长这样：``'ZZZZZZZZRegistration failed, please try again'``。
    真正的信息在中间，这里把填充剪掉（中间的同字符重复不动）。
    """
    import re as _re
    pattern = f"(.)\\1{{{max_repeat - 1},}}"
    text = _re.sub(r"^" + pattern, "", text)
    text = _re.sub(pattern + r"$", "", text)
    return text


def has_hint_word(text: str) -> bool:
    """文本里是否出现常见"提示语用词"（英文按词匹配；中文只要出现汉字就算）。"""
    import re as _re
    if any("\u4e00" <= c <= "\u9fff" for c in text):
        return True
    for token in _re.findall(r"[A-Za-z]{3,}", text.lower()):
        if token in COMMON_HINT_WORDS:
            return True
    return False


def decrypt_strings(img, min_len: int = 8, limit: int = 40,
                    key_lengths: Sequence[int] = (1, 2, 3, 4),
                    cribs: Optional[Sequence[bytes]] = None,
                    try_crib: bool = False) -> List[Tuple[str, int, str]]:
    """**自动解密被异或加密的字符串**（FLOSS 那条路子的静态近似版）。

    为什么值得做：国产 CrackMe（吾爱那批尤其）几乎都会把提示语异或一遍，
    直接在 `.rdata` 里看到的是 `'\\x01C?\\'B:#PI0C<#QH-F;%QJ/B=$OK/E?"J?)'` 这种乱码。
    人工做法是找解密循环；这里用两个更省事的办法：

    1. **单字节 XOR 全扫**（numpy 向量化，256 个密钥 × 整节，毫秒级）——**默认开启**，
       判据严格（可打印 + 无控制字符 + 字符多样性 + 非周期重复 + 含常见词），
       实测假阳性可控；
    2. **多字节 XOR + 已知词 crib**（`try_crib=True` 才启用）——能力更强，
       但**假阳性明显更多**：任意窗口只要"看着可打印"就会被报出来，
       即使加了词表闸门也会混进 `'pass assoa\\'suat…'` 这类东西。
       所以把它做成显式选项，并在输出里标注"启发式，需人工确认"。

    返回 ``[(明文串, 地址, 说明), …]``。
    """
    if cribs is None:
        cribs = (b"error", b"Error", b"ERROR", b"success", b"Success", b"OK",
                 b"fail", b"Fail", b"wrong", b"Wrong", b"correct", b"Correct",
                 b"flag", b"Flag", b"password", b"Password", b"register",
                 b"Register", b"key", b"Key", b"Congratulation",
                 "成功".encode("gbk"), "失败".encode("gbk"), "正确".encode("gbk"),
                 "错误".encode("gbk"), "注册".encode("gbk"), "恭喜".encode("gbk"),
                 "密码".encode("gbk"), "用户名".encode("gbk"))
    def looks_like_text(text: str) -> bool:
        """判断解出来的串是不是"真·解密出来的文本"。

        必须排掉一个大类假象：**UTF-16 字符串被单字节异或**之后，解出来会呈现
        "每隔一个字符是空格"的锯齿形（例如 ``' Y Y     p m     a m     d E C E M B E R'``），
        可打印率反而很高。判别方法就是看**奇偶位置**：某一侧的字母占比极低 → 是锯齿形，丢掉。
        """
        if len(text) < 6:
            return False
        even = text[0::2]
        odd = text[1::2]

        def letter_ratio(part: str) -> float:
            if not part:
                return 0.0
            return sum(1 for c in part if c.isalpha()) / len(part)

        if min(letter_ratio(even), letter_ratio(odd)) < 0.15:
            return False                      # 一侧几乎没有字母 → UTF-16 锯齿假象
        # 再排一类假象：**整片常量填充**（零/0xFF/重复模式）异或之后会变成
        # 'AAAAAAAA…' 这种"同一字符刷屏"。真正的提示语一定有字符多样性。
        if len(set(text)) < 6:
            return False
        from collections import Counter
        if Counter(text).most_common(1)[0][1] / len(text) > 0.4:
            return False
        # 还排一类：**短周期重复**（'C@C@C@…'、'abcabcabc…'）。
        # 它们来自"周期性数据（UTF-16/填充模式）被异或"，看着可打印但毫无信息。
        for period in (2, 3, 4):
            if len(text) >= period * 4:
                repeats = sum(1 for i in range(len(text) - period)
                              if text[i] == text[i + period])
                if repeats / (len(text) - period) > 0.7:
                    return False
        alnum = sum(1 for c in text if c.isalnum() or c in " _-{}[]().,:;'\"")
        if alnum / len(text) < 0.7:
            return False
        # 最后一道闸：**语言模型**。上面那些几何/统计规则能滤掉"锯齿、周期、刷屏"，
        # 但挡不住"碰巧可打印的乱码"（例如 'Con0onTo\n0…'）。真正的提示语是人写的，
        # 语言模型分明显更高——这是最有效的一道过滤。
        if all(ord(c) < 128 for c in text):
            try:
                from . import langscore
                if langscore.score_text(text.replace("_", " ")).score < 0.30:
                    return False
            except Exception:
                pass
        return True

    out: List[Tuple[str, int, str]] = []
    seen = set()

    def printable_ratio(chunk: bytes) -> float:
        if not chunk:
            return 0.0
        good = sum(1 for b in chunk if 32 <= b < 127 or b in (9, 10, 13))
        return good / len(chunk)

    for sec in img.segments:
        data = sec.data or b""
        if getattr(sec, "executable", False) or len(data) < 16:
            continue
        # ---- 1) 单字节 XOR：numpy 向量化，一次算 256 个密钥
        try:
            import numpy as np
            arr = np.frombuffer(data, dtype=np.uint8)
            printable = ((arr >= 32) & (arr < 127)) | (arr == 9) | (arr == 10) | (arr == 13)
            for k in range(1, 256):
                # ⚠ 跳过 0x20：**异或 0x20 只是翻转 ASCII 字母的大小写**，
                # 于是程序里每一段普通字符串都会"被解出来"一次（'try again' → 'TRY AGAIN'），
                # 刷满结果却毫无信息。这是实测里最顽固的一类假阳性。
                if k == 0x20:
                    continue
                mask = printable if k == 1 else None
                decoded = arr ^ k
                pm = ((decoded >= 32) & (decoded < 127)) | (decoded == 9) | \
                     (decoded == 10) | (decoded == 13)
                # 找连续可打印段
                idx = np.flatnonzero(np.diff(np.concatenate(([0], pm.view(np.int8),
                                                             [0]))))
                starts, ends = idx[0::2], idx[1::2]
                for s, e in zip(starts, ends):
                    if e - s >= min_len:
                        text = trim_repeats(bytes(decoded[s:e]).decode("latin-1"))
                        if not looks_like_text(text) or not has_hint_word(text):
                            continue
                        key = f"单字节异或 0x{k:02x}"
                        if (text, key) not in seen:
                            seen.add((text, key))
                            out.append((text, sec.vaddr + int(s), key))
                del mask
        except Exception:
            pass
        # ---- 2) 多字节 XOR：从"字符串起点"（前一字节为 NUL）用常见词定密钥
        #      （启发式，默认关闭；见 docstring 里的说明）
        for pos in range(1, len(data) - 8) if try_crib else ():
            if data[pos - 1] != 0:
                continue
            for kl in key_lengths:
                if kl < 2 or pos + kl >= len(data):
                    continue
                for crib in cribs:
                    if len(crib) < kl:
                        continue
                    key = bytes(data[pos + i] ^ crib[i] for i in range(kl))
                    if key.count(0) == kl:
                        continue                       # 全零密钥 = 没加密，跳过
                    if set(key) == {0x20}:
                        continue                       # 全 0x20 密钥 = 只是大小写翻转
                    window = data[pos:pos + 64]
                    plain = bytes(window[i] ^ key[i % kl] for i in range(len(window)))
                    # **先在 NUL 处截断再判分**：明文结尾的 NUL 被异或后会变成非零字节，
                    # 不解码边界就会把可打印率算成 0.6 左右，真正的答案反而被筛掉
                    # （合成用例就是这么漏掉的）。
                    body = plain.split(b"\x00")[0]
                    # crib 这条分支**必须严格**：只有"整串 100% 可打印、且不含任何
                    # 控制字符"才算。放宽松（比如允许 10% 垃圾）会刷出一堆
                    # 'Con0onTo\n0\x0bnToB0On}o#0"n…' 这种由错误密钥凑出来的可打印段
                    # ——它们每个字节都"看着像"，但整串是垃圾。
                    if len(body) < min_len or any(not (32 <= c < 127) for c in body):
                        continue
                    text = trim_repeats(body.decode("latin-1"))
                    if not looks_like_text(text):
                        continue
                    if not has_hint_word(text):
                        continue          # 没有常见词 → 多半是错误密钥凑出来的可打印垃圾
                    note = f"{kl} 字节异或，密钥={key!r}（由 {crib!r} 定出）"
                    if (text, note) not in seen:
                        seen.add((text, note))
                        out.append((text, sec.vaddr + pos, note))
        if len(out) >= limit * 3:
            break
    # 排序：命中"提示语常见词"越多的排越前，其次按语言模型分与长度。
    # 异或解密的候选里假阳性不少（UTF-16 锯齿、周期重复、常量填充、错误密钥凑出的
    # 可打印垃圾），单靠"可打印"排不出好坏，词命中数与语言模型能把真提示语顶上来。
    from . import langscore

    def score(item: Tuple[str, int, str]) -> float:
        text = item[0]
        words = sum(1 for token in __import__("re").findall(r"[A-Za-z]{3,}",
                                                            text.lower())
                    if token in COMMON_HINT_WORDS)
        try:
            lang = langscore.score_text(text.replace("_", " ")).score
        except Exception:
            lang = 0.0
        return words + lang + min(0.3, len(text) / 200.0)

    out.sort(key=score, reverse=True)
    return out[:limit]


def report(img) -> str:
    lines = ["【签名/指纹扫描】"]
    verdict = detect_packer(img)
    if verdict:
        lines.append("  打包器：" + verdict.line())
    else:
        lines.append("  打包器：没发现明显加壳特征（节名/入口/熵/导入表都正常）")
    ent = section_entropy_table(img)
    if ent:
        lines.append("  各节熵：" + "，".join(
            f"{n}({size:#x}B)={e:.2f}" for n, size, e in ent))
    hits = scan_crypto(img)
    if hits:
        lines.append(f"  加密常量命中 {len(hits)} 处：")
        for hit in hits[:14]:
            lines.append("    " + hit.line())
        modified = [h for h in hits if not h.exact]
        if modified:
            lines.append("  ★ 上面带「≈相似度」的是**被改过的常量**——"
                         "这类命中往往是题目的关键（标准算法 + 改常量）")
    else:
        lines.append("  没命中已知加密常量")
    decrypted = decrypt_strings(img, limit=10)
    if decrypted:
        lines.append("  异或加密的字符串（单字节路径，已自动解密）：")
        for text, addr, note in decrypted[:10]:
            lines.append(f"    0x{addr:x}  {text!r}   ← {note}")
    # 多字节路径**不在这里自动跑**：它是启发式的、假阳性较多，
    # 只在用户显式 `sig --crib` 时才输出（见 cli.cmd_sig）。
    return "\n".join(lines)
