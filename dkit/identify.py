"""线索识别：给你一串东西，告诉你"这是什么"。

借鉴（GitHub 上同类工具的做法）：

* **pyWhat / lemmeknow** —— 正则库 + 标签过滤 + 递归在文本里找东西；
* **Name-That-Hash** —— 哈希识别带**流行度排序**和 hashcat/john 模式号，
  并且"只认真 hash"，不把 base64 当哈希；
* **CyberChef Magic** —— 报告"还有哪些编码可能匹配"（Matching ops）。

本模块的取向是**宁可少报也不要误导**：能用校验器的（IPv4 段值、信用卡 Luhn、
JWT 结构、哈希长度与字符集）都做校验。
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# 数据结构
# --------------------------------------------------------------------------


@dataclass
class Pattern:
    name: str
    regex: bytes
    tags: Tuple[str, ...]
    confidence: float = 0.9
    rarity: float = 0.5                 # 越大越罕见
    description: str = ""
    hashcat: Optional[int] = None
    john: str = ""
    validator: Optional[str] = None     # 校验器名字（见 VALIDATORS）


@dataclass
class Hit:
    name: str
    value: str
    offset: int
    tags: Tuple[str, ...]
    confidence: float
    rarity: float = 0.5
    description: str = ""
    hashcat: Optional[int] = None
    john: str = ""

    def line(self) -> str:
        extra = ""
        if self.hashcat is not None:
            extra = f"  [hashcat -m {self.hashcat}" + (f" / john --format={self.john}" if self.john else "") + "]"
        desc = f" —— {self.description}" if self.description else ""
        snippet = self.value if len(self.value) <= 72 else self.value[:69] + "..."
        return (f"[{self.confidence:.2f}] {self.name}{extra}{desc}\n"
                f"        @{self.offset}: {snippet}")


# --------------------------------------------------------------------------
# 校验器（宁可少报，不要误导）
# --------------------------------------------------------------------------

def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _valid_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def _luhn(value: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", value)]
    if len(digits) < 12:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _valid_jwt(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    try:
        for part in parts[:2]:
            raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
            json.loads(raw)
        return True
    except Exception:
        return False


def _valid_btc(value: str) -> bool:
    if value.lower().startswith("bc1"):
        return 14 <= len(value) <= 90
    return bool(re.fullmatch(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", value))


def _valid_eth(value: str) -> bool:
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", value))


def _valid_pem(value: str) -> bool:
    return "-----BEGIN" in value


def _always(_value: str) -> bool:
    return True


VALIDATORS: Dict[str, object] = {
    "ipv4": _valid_ipv4,
    "ipv6": _valid_ipv6,
    "luhn": _luhn,
    "jwt": _valid_jwt,
    "btc": _valid_btc,
    "eth": _valid_eth,
    "pem": _valid_pem,
    "always": _always,
}


# --------------------------------------------------------------------------
# 模式库
# --------------------------------------------------------------------------

def _p(name, regex, tags, conf=0.9, rarity=0.5, desc="", hashcat=None, john="", validator=None):
    return Pattern(name, regex.encode() if isinstance(regex, str) else regex, tuple(tags),
                   conf, rarity, desc, hashcat, john, validator)


PATTERNS: List[Pattern] = [
    # ---------- flag ----------
    _p("Flag（flag{...} 形式）", rb"(?i)\b(flag|ctf|key|pass|secret|anser|answer)[{(\[][!-~]{3,160}[})\]]",
       ["CTF"], 0.95, 0.4, "疑似题目 flag"),
    # ---------- 哈希 ----------
    _p("MD5 / MD4 / NTLM / LM（32 位十六进制）", rb"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])",
       ["哈希"], 0.7, 0.2, "32 位十六进制：MD5(0)/MD4(900)/NTLM(1000)/LM(3000)", hashcat=0),
    _p("SHA-1 / RIPEMD-160（40 位十六进制）", rb"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])",
       ["哈希"], 0.75, 0.3, "40 位十六进制：SHA-1(100)/RIPEMD-160(6000)/MySQL5(300)", hashcat=100),
    _p("SHA-224", rb"(?<![0-9a-fA-F])[0-9a-fA-F]{56}(?![0-9a-fA-F])", ["哈希"], 0.8, 0.6,
       "SHA-224", hashcat=1300),
    _p("SHA-256 / Keccak-256 / SHA3-256 / BLAKE2s（64 位十六进制）",
       rb"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", ["哈希"], 0.8, 0.3,
       "SHA-256(1400)/Keccak-256(17800)/SHA3-256(17400)", hashcat=1400),
    _p("SHA-384", rb"(?<![0-9a-fA-F])[0-9a-fA-F]{96}(?![0-9a-fA-F])", ["哈希"], 0.85, 0.6,
       "SHA-384", hashcat=10800),
    _p("SHA-512 / Whirlpool / BLAKE2b（128 位十六进制）",
       rb"(?<![0-9a-fA-F])[0-9a-fA-F]{128}(?![0-9a-fA-F])", ["哈希"], 0.85, 0.4,
       "SHA-512(1700)/Whirlpool(6100)", hashcat=1700),
    _p("bcrypt", rb"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}", ["哈希", "凭证"], 0.97, 0.5,
       "bcrypt", hashcat=3200, john="bcrypt"),
    _p("MD5crypt", rb"\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}", ["哈希"], 0.95, 0.5,
       "MD5crypt", hashcat=500),
    _p("SHA-256crypt", rb"\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}",
       ["哈希"], 0.95, 0.6, "sha256crypt", hashcat=7400),
    _p("SHA-512crypt", rb"\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}",
       ["哈希"], 0.95, 0.6, "sha512crypt", hashcat=1800),
    _p("phpass（WordPress）", rb"\$P\$[./A-Za-z0-9]{31}", ["哈希", "凭证"], 0.95, 0.5,
       "phpass", hashcat=400),
    _p("Django PBKDF2", rb"pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]{10,}\$[A-Za-z0-9+/=]{20,}",
       ["哈希"], 0.95, 0.7, "Django", hashcat=10000),
    _p("Werkzeug PBKDF2", rb"pbkdf2:sha256:\d+\$[0-9a-f]{8,}\$[0-9a-f]{40,}", ["哈希"], 0.9, 0.7,
       "Werkzeug", hashcat=10900),
    _p("Argon2", rb"\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+",
       ["哈希"], 0.97, 0.6, "Argon2", hashcat=34000),
    _p("scrypt", rb"\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+",
       ["哈希"], 0.95, 0.7, "scrypt"),
    _p("Unix crypt(3) DES", rb"(?<![./A-Za-z0-9])[./A-Za-z0-9]{13}(?![./A-Za-z0-9])",
       ["哈希"], 0.55, 0.6, "可能是传统 DES crypt（也可能是随机短串）"),
    _p("CRC32 / Adler-32（8 位十六进制）", rb"(?<![0-9a-fA-F])[0-9a-fA-F]{8}(?![0-9a-fA-F])",
       ["哈希", "校验和"], 0.5, 0.2, "8 位十六进制：CRC32(11500)/Adler-32", hashcat=11500),
    # ---------- 编码 / 令牌 ----------
    _p("JWT", rb"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}",
       ["编码", "令牌"], 0.95, 0.5, "JSON Web Token（含 Header/Payload/Signature）", validator="jwt"),
    _p("Base64（较长）", rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])",
       ["编码"], 0.6, 0.2, "疑似 Base64 编码"),
    _p("Base64URL", rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{24,}={0,2}(?![A-Za-z0-9_-])",
       ["编码"], 0.5, 0.3, "疑似 Base64URL（- _ 字符集）"),
    _p("Hex 字符串", rb"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])",
       ["编码"], 0.6, 0.2, "十六进制字节串"),
    _p("URL 编码", rb"(?:%[0-9A-Fa-f]{2}){3,}", ["编码"], 0.9, 0.3, "百分号编码"),
    _p("HTML 实体", rb"&(?:#\d{2,5}|#x[0-9A-Fa-f]{2,4}|[a-zA-Z]{2,8});", ["编码"], 0.85, 0.4,
       "HTML 转义"),
    _p("Unicode 转义", rb"(?:\\u[0-9a-fA-F]{4}){2,}|(?:\\x[0-9a-fA-F]{2}){4,}", ["编码"], 0.9, 0.4,
       "\\uXXXX / \\xNN 转义"),
    _p("PowerShell 编码命令", rb"(?i)-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}",
       ["编码", "可疑"], 0.9, 0.7, "PowerShell -EncodedCommand（Base64+UTF-16LE）"),
    # ---------- 网络 ----------
    _p("IPv4 地址", rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", ["网络"], 0.9, 0.1, "IPv4", validator="ipv4"),
    _p("IPv6 地址", rb"\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b", ["网络"], 0.85, 0.5,
       "IPv6", validator="ipv6"),
    _p("MAC 地址", rb"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", ["网络"], 0.95, 0.3,
       "MAC 地址"),
    _p("URL", rb"\bhttps?://[^\s\"'<>()\[\]]{4,}", ["网络"], 0.95, 0.1, "HTTP(S) 链接"),
    _p("域名", rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|cn|edu|gov|xyz|top|info|dev|app|me|co|uk|de|jp|ru)\b",
       ["网络"], 0.8, 0.1, "域名"),
    _p("电子邮箱", rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", ["网络", "身份"], 0.95, 0.2,
       "邮箱地址"),
    _p("Windows 路径", rb"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*",
       ["系统"], 0.75, 0.3, "Windows 文件路径"),
    _p("注册表路径", rb"(?i)\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s\"']{4,}", ["系统", "取证"], 0.9, 0.6,
       "Windows 注册表键"),
    # ---------- 身份 / 金融 ----------
    _p("UUID", rb"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
       ["标识符"], 0.97, 0.3, "UUID/GUID"),
    _p("信用卡号（Luhn 校验通过）", rb"\b(?:\d[ -]?){13,19}\b", ["金融", "身份"], 0.8, 0.8,
       "银行卡号", validator="luhn"),
    _p("SSN（美）", rb"\b\d{3}-\d{2}-\d{4}\b", ["身份"], 0.7, 0.6, "美国社保号格式"),
    _p("中国手机号", rb"(?<!\d)1[3-9]\d{9}(?!\d)", ["身份"], 0.7, 0.5, "中国大陆手机号"),
    # ---------- 加密货币 ----------
    _p("比特币地址", rb"\b(?:bc1[a-z0-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
       ["加密货币"], 0.85, 0.7, "BTC 地址", validator="btc"),
    _p("以太坊地址", rb"\b0x[0-9a-fA-F]{40}\b", ["加密货币"], 0.9, 0.6, "ETH 地址", validator="eth"),
    _p("门罗币地址", rb"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", ["加密货币"], 0.9, 0.85, "XMR 地址"),
    _p("Ripple 地址", rb"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b", ["加密货币"], 0.6, 0.8, "XRP 地址"),
    # ---------- 凭证 / API Key ----------
    _p("AWS Access Key ID", rb"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b",
       ["凭证", "云"], 0.97, 0.8, "AWS Access Key ID"),
    _p("Google API Key", rb"\bAIza[0-9A-Za-z\-_]{35}\b", ["凭证", "云"], 0.95, 0.8, "Google API Key"),
    _p("GitHub Token", rb"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", ["凭证"], 0.97, 0.85, "GitHub Token"),
    _p("Slack Token", rb"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b", ["凭证"], 0.95, 0.85, "Slack Token"),
    _p("Stripe Key", rb"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b", ["凭证"], 0.95, 0.85,
       "Stripe Key"),
    _p("Twilio SID", rb"\b(?:AC|SK)[0-9a-fA-F]{32}\b", ["凭证"], 0.85, 0.85, "Twilio SID/Key"),
    _p("Telegram Bot Token", rb"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", ["凭证"], 0.9, 0.85,
       "Telegram Bot Token"),
    _p("Discord Token", rb"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,}\b", ["凭证"], 0.85, 0.9,
       "Discord Bot Token"),
    _p("npm Token", rb"\bnpm_[A-Za-z0-9]{36}\b", ["凭证"], 0.95, 0.85, "npm Access Token"),
    _p("私钥（PEM）", rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
       ["凭证", "密钥"], 0.99, 0.9, "私钥文件头", validator="pem"),
    _p("证书（PEM）", rb"-----BEGIN CERTIFICATE-----", ["凭证", "密钥"], 0.97, 0.7, "X.509 证书"),
    _p("SSH 公钥", rb"\bssh-(?:rsa|dss|ed25519)\s+AAAA[A-Za-z0-9+/=]{20,}",
       ["凭证", "密钥"], 0.95, 0.7, "OpenSSH 公钥"),
    # ---------- 其它 ----------
    _p("CVE 编号", rb"\bCVE-\d{4}-\d{4,7}\b", ["情报"], 0.97, 0.5, "CVE 漏洞编号"),
    _p("Magnet 链接", rb"\bmagnet:\?xt=urn:btih:[0-9a-fA-F]{32,40}", ["网络", "P2P"], 0.97, 0.7,
       "BT 磁力链接"),
    _p("Torrent infohash", rb"\b[0-9a-fA-F]{40}\b", ["P2P"], 0.4, 0.5, "可能是 BT infohash（也是 SHA-1 长度）"),
    _p("坐标", rb"\b-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b", ["地理"], 0.7, 0.6, "经纬度"),
    _p("Unix 时间戳", rb"\b1[0-9]{9}\b", ["时间"], 0.6, 0.3, "10 位 Unix 时间戳（秒）"),
    _p("Unix 毫秒时间戳", rb"\b1[0-9]{12}\b", ["时间"], 0.7, 0.5, "13 位时间戳（毫秒）"),
    _p("Base64 编码的 gzip", rb"\bH4sI[A-Za-z0-9+/=]{20,}", ["编码", "压缩"], 0.9, 0.6,
       "Base64(GZIP) —— 常见于压缩后的 Web token"),
    _p("Base64 编码的 zlib", rb"\beJ(?:A[A-Za-z0-9+/=]{20,}|[A-Za-z0-9+/=]{20,})", ["编码", "压缩"],
       0.75, 0.6, "可能是 Base64(zlib)（Flask session 等）"),
]

# 文件魔数（比 oracles 的更全，用于 identify 的"文件是什么"）
FILE_MAGICS: Sequence[Tuple[bytes, str, str]] = (
    (b"\x89PNG\r\n\x1a\n", "PNG 图片", "image/png"),
    (b"\xff\xd8\xff", "JPEG 图片", "image/jpeg"),
    (b"GIF87a", "GIF 图片", "image/gif"),
    (b"GIF89a", "GIF 图片", "image/gif"),
    (b"BM", "BMP 图片", "image/bmp"),
    (b"RIFF", "RIFF 容器（WAV/AVI/WEBP）", "application/riff"),
    (b"PK\x03\x04", "ZIP 压缩包（或 docx/xlsx/apk/jar）", "application/zip"),
    (b"PK\x05\x06", "ZIP 空归档", "application/zip"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip 压缩包", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "RAR 压缩包", "application/x-rar-compressed"),
    (b"\x1f\x8b\x08", "GZIP 压缩", "application/gzip"),
    (b"BZh", "BZIP2 压缩", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", "XZ 压缩", "application/x-xz"),
    (b"(\xb5/\xfd", "Zstandard 压缩", "application/zstd"),
    (b"\x04\x22\x4d\x18", "LZ4 压缩", "application/x-lz4"),
    (b"%PDF-", "PDF 文档", "application/pdf"),
    (b"\x7fELF", "ELF 可执行文件", "application/x-executable"),
    (b"MZ", "PE/DOS 可执行文件", "application/x-dosexec"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class", "application/octet-stream"),
    (b"SQLite format 3\x00", "SQLite 数据库", "application/vnd.sqlite3"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE 文档（doc/xls/ppt）", "application/msword"),
    (b"\x00\x61\x73\x6d", "WebAssembly 模块", "application/wasm"),
    (b"dex\n", "Android DEX", "application/x-dex"),
    (b"\x1a\x45\xdf\xa3", "Matroska/WebM", "video/x-matroska"),
    (b"OggS", "Ogg 媒体", "application/ogg"),
    (b"ID3", "MP3（含 ID3 标签）", "audio/mpeg"),
    (b"fLaC", "FLAC 音频", "audio/flac"),
    (b"\xd4\xc3\xb2\xa1", "PCAP 抓包", "application/vnd.tcpdump.pcap"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG 抓包", "application/vnd.tcpdump.pcap"),
    (b"-----BEGIN", "PEM 文本（证书/密钥）", "application/x-pem-file"),
    (b"{\\rtf", "RTF 文档", "application/rtf"),
    (b"\x50\x4b\x03\x04\x0a", "ZIP 变体", "application/zip"),
)


def identify_file(data: bytes) -> List[Hit]:
    hits: List[Hit] = []
    head = data[:16]
    for magic, name, mime in FILE_MAGICS:
        if head.startswith(magic):
            hits.append(Hit(name, mime, 0, ("文件",), 0.97, 0.4, "按文件头识别"))
            break
    return hits


# --------------------------------------------------------------------------
# 识别主流程
# --------------------------------------------------------------------------

_ENC_CHARSETS = {
    "Base64": (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", 4),
    "Base64URL": (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=", 4),
    "Base32": (b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=", 8),
    "Base32hex": (b"0123456789ABCDEFGHIJKLMNOPQRSTUV=", 8),
    "Base58": (b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", 0),
    "Base62": (b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 0),
    "Base85": (bytes(range(0x21, 0x76)), 5),
    "Hex": (b"0123456789abcdefABCDEF", 2),
}


def guess_encodings(text: str) -> List[Tuple[str, str]]:
    """猜"这串东西可能是什么编码"，返回 [(编码名, 说明)]。"""
    stripped = re.sub(r"\s", "", text)
    out: List[Tuple[str, str]] = []
    if len(stripped) < 6:
        return out
    data = stripped.encode("latin-1", "ignore")
    for name, (charset, group) in _ENC_CHARSETS.items():
        if not set(data) <= set(charset):
            continue
        ok = True
        if group and len(stripped) % group:
            ok = len(stripped) % group in (2, 3, 6, 7)      # 允许缺省 padding
        if not ok:
            continue
        note = ""
        try:
            if name.startswith("Base64"):
                raw = base64.urlsafe_b64decode(stripped + "=" * (-len(stripped) % 4)) \
                    if name.endswith("URL") else base64.b64decode(stripped + "=" * (-len(stripped) % 4))
            elif name == "Base32":
                raw = base64.b32decode(stripped + "=" * (-len(stripped) % 8))
            elif name == "Hex":
                raw = binascii.unhexlify(stripped if len(stripped) % 2 == 0 else stripped[:-1])
            else:
                continue
            printable = sum(1 for b in raw if 32 <= b < 127) / max(1, len(raw))
            note = f"解出 {len(raw)} 字节，可打印率 {printable:.2f}"
        except Exception:
            note = "字符集匹配（未试解码）"
        out.append((name, note))
    return out


def identify(data, include: Optional[Sequence[str]] = None, exclude: Optional[Sequence[str]] = None,
             limit: int = 40, recursive: bool = True) -> List[Hit]:
    """识别文本/字节里"有什么"。include/exclude 按标签过滤。"""
    raw = data.encode("utf-8", "ignore") if isinstance(data, str) else bytes(data)
    text_bytes = raw
    hits: List[Hit] = []
    if isinstance(data, (bytes, bytearray)):
        hits += identify_file(raw)
    if len(raw) > 4 << 20:                       # 大文件只扫前 4MB
        text_bytes = raw[: 4 << 20]

    for pat in PATTERNS:
        if include and not (set(pat.tags) & set(include)):
            continue
        if exclude and (set(pat.tags) & set(exclude)):
            continue
        for m in re.finditer(pat.regex, text_bytes):
            value = m.group(0)
            try:
                shown = value.decode("utf-8")
            except UnicodeDecodeError:
                shown = value.decode("latin-1")
            if pat.validator:
                fn = VALIDATORS.get(pat.validator)
                if fn and not fn(shown):          # type: ignore[operator]
                    continue
            hits.append(Hit(pat.name, shown, m.start(), pat.tags, pat.confidence, pat.rarity,
                            pat.description, pat.hashcat, pat.john))
            if len([h for h in hits if h.name == pat.name]) >= 3:
                break

    # 没找到强特征 → 退化成"猜编码"
    if not hits and isinstance(data, str):
        enc = guess_encodings(data)
        best = 0.75
        for name, note in enc:
            hits.append(Hit(f"疑似 {name}", data[:64], 0, ("编码",), best, 0.4, note))
            best -= 0.1

    # 递归：把命中的编码串解开一层再看看里面是什么
    if recursive:
        extra: List[Hit] = []
        for hit in list(hits):
            if "编码" not in hit.tags or len(hit.value) < 16:
                continue
            inner = _try_decode_any(hit.value)
            if inner:
                for sub in identify(inner, include, exclude, limit, recursive=False):
                    sub.offset += hit.offset
                    sub.description = f"（来自 {hit.name} 解出）" + sub.description
                    extra.append(sub)
        hits += extra

    hits.sort(key=lambda h: (-h.confidence, -h.rarity))
    return hits[:limit]


def _try_decode_any(text: str) -> Optional[bytes]:
    stripped = re.sub(r"\s", "", text)
    for name, (charset, _g) in _ENC_CHARSETS.items():
        if not set(stripped.encode("latin-1", "ignore")) <= set(charset):
            continue
        try:
            if name.startswith("Base64"):
                return base64.urlsafe_b64decode(stripped + "=" * (-len(stripped) % 4)) \
                    if name.endswith("URL") else base64.b64decode(stripped + "=" * (-len(stripped) % 4))
            if name == "Base32":
                return base64.b32decode(stripped + "=" * (-len(stripped) % 8))
            if name == "Hex" and len(stripped) % 2 == 0:
                return binascii.unhexlify(stripped)
        except Exception:
            continue
    return None


def describe(data, include=None, exclude=None) -> str:
    hits = identify(data, include, exclude)
    if not hits:
        return "没识别出已知特征。可以试试：autocrypt scan / oracle / chain 进一步分析。"
    lines = [f"共 {len(hits)} 条线索："]
    lines += [h.line() for h in hits]
    return "\n".join(lines)


def all_tags() -> List[str]:
    tags: Dict[str, int] = {}
    for pat in PATTERNS:
        for tag in pat.tags:
            tags[tag] = tags.get(tag, 0) + 1
    return [f"{t}({c})" for t, c in sorted(tags.items(), key=lambda kv: -kv[1])]
