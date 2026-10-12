"""内嵌文件扫描与雕刻（hexforge / binwalk 的思路）。

hexforge 讲清楚了一个关键坑：**短 magic 会误报**。``\\x78\\x9c``（zlib）在压缩数据里
平均每 64KB 就自然出现一次，PNG 的 IDAT 里全是这种字节。它的解法是两层：

1. **结构校验器**：每个短 magic 配一个格式自检（长度字段、头大小、版本号…）；
2. **压缩区抑制**：先把 PNG IDAT / GZIP 成员 / zlib 流的范围标出来，
   落在里面的短 magic 一律不报。

本模块照这个思路实现，并且：
* 结尾定位是**格式感知**的（PNG 找 IEND、JPEG 找 FF D9、ZIP 走 EOCD、
  GZIP 用 decompressobj 精确走到流尾、PDF 找 %%EOF、TAR 按块数算）；
* 支持**递归雕刻**（雕刻出来的文件再扫一遍，SHA-256 去重防死循环）；
* 附带**单字节 XOR 混淆探测**：文件头被异或了一个字节时直接告诉你密钥。
"""

from __future__ import annotations

import bz2
import hashlib
import io
import json
import lzma
import os
import struct
import zlib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# 结尾定位
# --------------------------------------------------------------------------

def _end_png(data: bytes, start: int) -> Optional[int]:
    pos = start + 8
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        if length > 0x7FFFFFFF:
            return None
        end = pos + 12 + length
        if end > len(data):
            return None
        if ctype == b"IEND":
            return end
        pos = end
    return None


def _end_jpeg(data: bytes, start: int) -> Optional[int]:
    pos = start + 2
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            return None
        marker = data[pos + 1]
        if marker == 0xD9:
            return pos + 2
        if marker == 0xDA:                       # 进入熵编码数据
            idx = data.find(b"\xff\xd9", pos + 2)
            return idx + 2 if idx >= 0 else None
        if marker in (0x01,) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        length = int.from_bytes(data[pos + 2:pos + 4], "big")
        if length < 2:
            return None
        pos += 2 + length
    return None


def _end_gif(data: bytes, start: int) -> Optional[int]:
    idx = data.rfind(b"\x3b", start, min(len(data), start + 20_000_000))
    return idx + 1 if idx > start else None


def _end_zip(data: bytes, start: int) -> Optional[int]:
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(data):
        return None
    comment = struct.unpack("<H", data[eocd + 20:eocd + 22])[0]
    return eocd + 22 + comment


def _end_gzip(data: bytes, start: int) -> Optional[int]:
    obj = zlib.decompressobj(31)
    try:
        obj.decompress(data[start:])
    except zlib.error:
        try:
            obj = zlib.decompressobj(31)
            obj.decompress(data[start:], 1 << 20)
        except zlib.error:
            return None
    consumed = len(data) - start - len(obj.unused_data)
    return start + consumed if consumed > 0 else None


def _end_bz2(data: bytes, start: int) -> Optional[int]:
    dec = bz2.BZ2Decompressor()
    try:
        dec.decompress(data[start:], 1 << 20)
    except Exception:
        return None
    if dec.eof:
        return len(data) - len(dec.unused_data)
    return None


def _end_xz(data: bytes, start: int) -> Optional[int]:
    dec = lzma.LZMADecompressor()
    try:
        dec.decompress(data[start:], 1 << 20)
    except Exception:
        return None
    if dec.eof:
        return len(data) - len(dec.unused_data)
    return None


def _end_pdf(data: bytes, start: int) -> Optional[int]:
    idx = data.find(b"%%EOF", start)
    return idx + 5 if idx >= 0 else None


def _end_bmp(data: bytes, start: int) -> Optional[int]:
    if start + 6 > len(data):
        return None
    size = struct.unpack("<I", data[start + 2:start + 6])[0]
    return start + size if 0 < size <= len(data) - start else None


def _end_riff(data: bytes, start: int) -> Optional[int]:
    if start + 8 > len(data):
        return None
    size = struct.unpack("<I", data[start + 4:start + 8])[0]
    return start + 8 + size if 0 < size <= len(data) - start else None


def _end_7z(data: bytes, start: int) -> Optional[int]:
    if start + 32 > len(data):
        return None
    next_off, next_size = struct.unpack("<QQ", data[start + 12:start + 28])
    end = start + 32 + next_off + next_size
    return end if 0 < next_off and end <= len(data) else None


def _end_tar(data: bytes, start: int) -> Optional[int]:
    pos = start
    while pos + 512 <= len(data):
        header = data[pos:pos + 512]
        if header == b"\x00" * 512:
            return pos + 512
        try:
            size = int(header[124:136].split(b"\x00")[0].strip() or b"0", 8)
        except ValueError:
            return None
        pos += 512 + ((size + 511) // 512) * 512
    return None


def _end_sqlite(data: bytes, start: int) -> Optional[int]:
    if start + 32 > len(data):
        return None
    page = struct.unpack(">H", data[start + 16:start + 18])[0]
    pages = struct.unpack(">I", data[start + 28:start + 32])[0]
    size = page * pages
    return start + size if 0 < size <= len(data) - start else None


# --------------------------------------------------------------------------
# 结构校验器（防短 magic 误报）
# --------------------------------------------------------------------------

def _check_gzip(data: bytes, start: int) -> bool:
    return start + 3 <= len(data) and data[start + 2] == 0x08 and not (data[start + 3] & 0xE0)


def _check_bmp(data: bytes, start: int) -> bool:
    if start + 18 > len(data):
        return False
    hdr = struct.unpack("<I", data[start + 14:start + 18])[0]
    return hdr in (12, 40, 52, 56, 64, 108, 124)


def _check_riff(data: bytes, start: int) -> bool:
    return start + 12 <= len(data) and data[start + 8:start + 12] in (
        b"WAVE", b"AVI ", b"WEBP", b"RMID", b"CDDA")


def _check_mp3(data: bytes, start: int) -> bool:
    if start + 2 > len(data):
        return False
    return (data[start] == 0xFF and (data[start + 1] & 0xE0) == 0xE0
            and (data[start + 1] & 0x18) != 0x08)


def _check_png(data: bytes, start: int) -> bool:
    return start + 16 <= len(data) and data[start + 12:start + 16] == b"IHDR"


def _check_always(_data: bytes, _start: int) -> bool:
    return True


# --------------------------------------------------------------------------
# 签名表
# --------------------------------------------------------------------------

def _check_pe(data: bytes, start: int) -> bool:
    if start + 0x40 > len(data):
        return False
    lfanew = struct.unpack("<I", data[start + 0x3C:start + 0x40])[0]
    if lfanew == 0 or start + lfanew + 4 > len(data):
        return False
    return data[start + lfanew:start + lfanew + 4] == b"PE\x00\x00"


def _check_tar(data: bytes, start: int) -> bool:
    return start >= 257 and data[start:start + 5] == b"ustar"


@dataclass
class Signature:
    name: str
    magic: bytes
    ext: str
    end: Optional[Callable[[bytes, int], Optional[int]]] = None
    check: Callable[[bytes, int], bool] = _check_always
    long_magic: bool = False          # 长度 ≥6 的 magic 不受压缩区抑制


def _sig(name, magic, ext, end=None, check=_check_always):
    return Signature(name, magic, ext, end, check, len(magic) >= 6)


SIGNATURES: List[Signature] = [
    _sig("PNG 图片", b"\x89PNG\r\n\x1a\n", "png", _end_png, _check_png),
    _sig("JPEG 图片", b"\xff\xd8\xff", "jpg", _end_jpeg),
    _sig("GIF 图片", b"GIF89a", "gif", _end_gif),
    _sig("GIF 图片", b"GIF87a", "gif", _end_gif),
    _sig("BMP 图片", b"BM", "bmp", _end_bmp, _check_bmp),
    _sig("ZIP 压缩包", b"PK\x03\x04", "zip", _end_zip),
    _sig("GZIP 压缩", b"\x1f\x8b\x08", "gz", _end_gzip, _check_gzip),
    _sig("BZIP2 压缩", b"BZh9", "bz2", _end_bz2),
    _sig("XZ 压缩", b"\xfd7zXZ\x00", "xz", _end_xz),
    _sig("PDF 文档", b"%PDF-", "pdf", _end_pdf),
    _sig("7-Zip 压缩包", b"7z\xbc\xaf\x27\x1c", "7z", _end_7z),
    _sig("RAR 压缩包", b"Rar!\x1a\x07", "rar"),
    _sig("TAR 归档", b"ustar", "tar", _end_tar, _check_tar),
    _sig("SQLite 数据库", b"SQLite format 3\x00", "sqlite", _end_sqlite),
    _sig("ELF 可执行文件", b"\x7fELF", "elf"),
    _sig("PE 可执行文件", b"MZ", "exe", None, _check_pe),
    _sig("RIFF 容器", b"RIFF", "riff", _end_riff, _check_riff),
    _sig("MP3 音频", b"ID3", "mp3"),
    _sig("PCAP 抓包", b"\xd4\xc3\xb2\xa1", "pcap"),
    _sig("OLE 文档", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    _sig("Matroska/WebM", b"\x1a\x45\xdf\xa3", "mkv"),
    _sig("WebAssembly", b"\x00asm", "wasm"),
    _sig("Android DEX", b"dex\n", "dex"),
    _sig("PEM 私钥/证书", b"-----BEGIN ", "pem", lambda d, s: d.find(b"-----END ", s) + 20),
    _sig("Zstd 压缩", b"\x28\xb5\x2f\xfd", "zst"),
    _sig("LZ4 压缩", b"\x04\x22\x4d\x18", "lz4"),
]


# --------------------------------------------------------------------------
# 压缩区抑制
# --------------------------------------------------------------------------

def compressed_spans(data: bytes) -> List[Tuple[int, int]]:
    """标出"压缩数据"的范围：PNG IDAT、ZIP 条目数据、GZIP 成员、裸 zlib 流。"""
    spans: List[Tuple[int, int]] = []

    # PNG IDAT
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        pos = 8
        while pos + 8 <= len(data):
            (length,) = struct.unpack(">I", data[pos:pos + 4])
            ctype = data[pos + 4:pos + 8]
            end = pos + 12 + length
            if end > len(data) or length > 0x7FFFFFFF:
                break
            if ctype in (b"IDAT", b"iCCP", b"zTXt", b"iTXt"):
                spans.append((pos + 8, pos + 8 + length))
            pos = end
            if ctype == b"IEND":
                break

    # ZIP 条目压缩数据
    pos = 0
    while True:
        pos = data.find(b"PK\x03\x04", pos)
        if pos < 0 or pos + 30 > len(data):
            break
        try:
            csize = struct.unpack("<I", data[pos + 18:pos + 22])[0]
            nlen, elen = struct.unpack("<HH", data[pos + 26:pos + 30])
        except struct.error:
            break
        start = pos + 30 + nlen + elen
        spans.append((start, min(len(data), start + csize)))
        pos = start + max(1, csize)

    # GZIP 成员：用 decompressobj 精确走到流尾
    search = 0
    while True:
        start = data.find(b"\x1f\x8b\x08", search)
        if start < 0:
            break
        obj = zlib.decompressobj(31)
        try:
            obj.decompress(data[start:], 1 << 20)
        except zlib.error:
            search = start + 1
            continue
        end = len(data) - len(obj.unused_data)
        if end > start:
            spans.append((start, end))
            search = end
        else:
            search = start + 1

    return spans


def _in_spans(offset: int, spans: Sequence[Tuple[int, int]]) -> bool:
    for start, end in spans:
        if start <= offset < end:
            return True
    return False


# --------------------------------------------------------------------------
# 扫描与雕刻
# --------------------------------------------------------------------------

@dataclass
class Carved:
    signature: str
    offset: int
    end: int
    ext: str
    data: bytes = b""
    valid: bool = False
    note: str = ""
    suppressed: bool = False
    depth: int = 0

    @property
    def size(self) -> int:
        return max(0, self.end - self.offset)

    def line(self) -> str:
        flag = "✔" if self.valid else "?"
        return (f"{flag} {self.signature:16s} @0x{self.offset:08x} "
                f"大小={self.size:<8d} .{self.ext}  {self.note}")


@dataclass
class CarveReport:
    path: str
    size: int
    found: List[Carved] = field(default_factory=list)
    suppressed: int = 0
    xor_hints: List[Tuple[int, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def xor_magic_hint(data: bytes) -> List[Tuple[int, str]]:
    """文件头被单字节 XOR 混淆时，反推出密钥（hexforge 的一个小功能）。"""
    out: List[Tuple[int, str]] = []
    head = data[:16]
    if not head:
        return out
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in head)
        for sig in SIGNATURES:
            if len(sig.magic) >= 3 and decoded.startswith(sig.magic):
                out.append((key, sig.name))
                break
        if len(out) >= 5:
            break
    return out


def scan(blob: bytes, path: str = "<memory>", min_magic: int = 4,
         depth: int = 0, seen: Optional[set] = None) -> CarveReport:
    """在数据里找内嵌文件。depth>0 时会递归雕刻。"""
    seen = seen if seen is not None else set()
    report = CarveReport(path, len(blob))
    spans = compressed_spans(blob)

    for sig in SIGNATURES:
        if len(sig.magic) < min_magic and not sig.long_magic:
            continue
        start = 0
        while True:
            idx = blob.find(sig.magic, start)
            if idx < 0:
                break
            start = idx + 1
            if not sig.check(blob, idx):
                continue
            if _in_spans(idx, spans) and not sig.long_magic:
                report.suppressed += 1
                continue
            end = sig.end(blob, idx) if sig.end else None
            if end is None:
                end = len(blob)
            if end <= idx:
                continue
            carved = Carved(sig.name, idx, end, sig.ext, blob[idx:end], False, "", False)
            carved.valid = _validate(carved)
            if not carved.valid:
                carved.note = "结构校验未通过（可能是误报）"
            report.found.append(carved)

    # 递归雕刻
    if depth > 0:
        base = {(c.offset, c.end, c.ext) for c in report.found}
        for carved in list(report.found):
            if carved.offset == 0 and carved.end == len(blob):
                continue                      # 别把整个文件再当成"内嵌的自己"
            digest = hashlib.sha256(carved.data).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            sub = scan(carved.data, f"{path} → 0x{carved.offset:x}", min_magic, depth - 1, seen)
            for item in sub.found:
                item.depth = carved.depth + 1
                item.offset += carved.offset
                if item.offset == 0 and carved.offset == 0:
                    continue
                key = (item.offset, item.end, item.ext)
                if key in base:
                    continue
                base.add(key)
                item.note += "（嵌套）"
                report.found.append(item)
            report.suppressed += sub.suppressed

    report.found.sort(key=lambda c: c.offset)
    report.xor_hints = xor_magic_hint(blob)
    return report


def _validate(carved: Carved) -> bool:
    data = carved.data
    try:
        if carved.ext == "png":
            return data.rstrip(b"\x00").endswith(b"IEND\xaeB`\x82")
        if carved.ext == "jpg":
            return b"\xff\xd9" in data[-4:]
        if carved.ext == "gif":
            return data.endswith(b"\x3b")
        if carved.ext == "zip":
            return b"PK\x05\x06" in data[-66000:]
        if carved.ext == "gz":
            return zlib.decompressobj(31).decompress(data) is not None
        if carved.ext == "pdf":
            return b"%%EOF" in data[-2048:]
        if carved.ext == "bmp":
            return struct.unpack("<I", data[2:6])[0] == len(data)
        if carved.ext == "sqlite":
            return data[:16] == b"SQLite format 3\x00"
        if carved.ext == "elf":
            return data[:4] == b"\x7fELF"
        if carved.ext == "bz2":
            return bz2.BZ2Decompressor().decompress(data, 1 << 16) is not None
        if carved.ext == "xz":
            return lzma.LZMADecompressor().decompress(data, 1 << 16) is not None
        if carved.ext == "7z":
            return data[:6] == b"7z\xbc\xaf\x27\x1c"
        if carved.ext == "pem":
            return b"-----END" in data
    except Exception:
        return False
    return len(data) > 16


def extract(report: CarveReport, out_dir: str, log=print) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    written: List[str] = []
    for i, carved in enumerate(report.found):
        if not carved.valid or carved.size < 16:
            continue
        name = f"{i:02d}_{carved.offset:08x}.{carved.ext}"
        dest = os.path.join(out_dir, name)
        try:
            with open(dest, "wb") as fh:
                fh.write(carved.data)
            written.append(dest)
        except OSError as exc:
            log(f"写出失败 {dest}: {exc}")
    return written


def report_text(report: CarveReport) -> str:
    lines = [f"=== {report.path}（{report.size} 字节）"]
    if report.xor_hints:
        for key, name in report.xor_hints:
            lines.append(f"  ⚠ 文件头疑似单字节 XOR 混淆：key={key:#04x} → 可能还原成 {name}")
    if not report.found:
        lines.append("  没有发现内嵌文件签名")
    for carved in report.found:
        indent = "    " * carved.depth
        lines.append(f"  {indent}{carved.line()}")
    if report.suppressed:
        lines.append(f"  （已抑制 {report.suppressed} 个落在压缩数据里的短 magic 误报）")
    return "\n".join(lines)


def report_json(report: CarveReport) -> str:
    return json.dumps({
        "path": report.path,
        "size": report.size,
        "suppressed": report.suppressed,
        "xor_hints": [{"key": k, "as": n} for k, n in report.xor_hints],
        "found": [{"signature": c.signature, "offset": c.offset, "end": c.end,
                   "size": c.size, "ext": c.ext, "valid": c.valid, "depth": c.depth,
                   "sha256": hashlib.sha256(c.data).hexdigest()} for c in report.found],
    }, ensure_ascii=False, indent=2)


def all_signatures() -> List[str]:
    return [f"{s.name:20s} {s.magic.hex(' '):24s} .{s.ext}" for s in SIGNATURES]
