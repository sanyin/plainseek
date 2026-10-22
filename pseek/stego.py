"""隐写分析：BMP 位平面提取 + WAV 音频分析/频谱图导出。

为什么单独一个模块：**隐写题的数据不是"加密"的，而是"藏在分辨率/位/顺序里"的**，
链式搜索那套"试算法"完全用不上——你没法用 oracle 给一堆错位提取的字节打分。
这类题的出路是**枚举结构组合 + 用文本判据筛选**，外加**把看不懂的东西画出来给人看**。

BMP 的实际坑（都是真实题目里踩出来的）：

* 头部字段会**撒谎**：自制工具常把 ``biHeight`` 写成别的值（或写成 0），
  但像素数据长度是准的。所以宽高要能用 ``数据长度 / 3`` 反推校验；
* 行是**自底向上**存的（``biHeight > 0`` 时），且每行按 4 字节对齐补零；
* 通道顺序是 **BGR** 不是 RGB；
* 位序可能是 MSB-first（常见）也可能 LSB-first（题目故意反过来）。

WAV 这边的现实：出题人最爱**把密钥"画"成频谱图**（用 Audacity 切频谱图就能读），
这种没法全自动 OCR，所以本模块的第一职责是**把频谱图导出成 PNG 让人眼读**，
第二职责才是能自动的（DTMF/FSK/静音段编码）。
"""

from __future__ import annotations

import io
import struct
import wave
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------- BMP


@dataclass
class BmpInfo:
    width: int
    height: int
    bpp: int
    data_offset: int
    row_stride: int
    bottom_up: bool
    header_width: int
    header_height: int
    fixed: bool                       # 头部字段是否被"按数据长度纠正"过
    pixels: bytes = b""

    def describe(self) -> str:
        lie = ""
        if self.fixed:
            lie = (f"（头部写的是 {self.header_width}x{abs(self.header_height)}，"
                   f"按数据长度纠正为 {self.width}x{self.height}）")
        return (f"BMP {self.width}x{self.height} bpp={self.bpp} "
                f"stride={self.row_stride} {'自底向上' if self.bottom_up else '自顶向下'}{lie}")


def bmp_pixels(data: bytes) -> Optional[BmpInfo]:
    """解析 BMP 的像素区。若头部宽高与数据长度矛盾，按数据长度反推。"""
    if len(data) < 54 or data[:2] != b"BM":
        return None
    data_offset = struct.unpack_from("<I", data, 10)[0]
    header_width, header_height = struct.unpack_from("<ii", data, 18)
    bpp = struct.unpack_from("<H", data, 28)[0]
    if bpp not in (24, 32) or data_offset >= len(data):
        return None
    body = data[data_offset:]
    w = abs(header_width)
    h = abs(header_height)
    fixed = False
    if w <= 0 or h <= 0 or w * h * (bpp // 8) != len(body):
        # 头部不可信：用"总字节数 = 宽 × 高 × 每像素字节"反推。
        # 先假定宽是对的（宽度定了 stride 才定，很多工具只写错高度）
        cand_w = w if w > 0 else int(round((len(body) / (bpp // 8)) ** 0.5))
        if cand_w > 0 and len(body) % (cand_w * (bpp // 8)) == 0:
            h2 = len(body) // (cand_w * (bpp // 8))
        else:
            # 宽也不可信：假定正方形
            side = int(round((len(body) / (bpp // 8)) ** 0.5))
            if side * side * (bpp // 8) != len(body):
                return None
            cand_w, h2 = side, side
        w, h, fixed = cand_w, h2, True
    stride = w * (bpp // 8)
    return BmpInfo(width=w, height=h, bpp=bpp, data_offset=data_offset,
                   row_stride=stride, bottom_up=header_height > 0,
                   header_width=header_width, header_height=header_height,
                   fixed=fixed, pixels=body)


def _pixel_array(info: BmpInfo):
    """把像素区变成 ``[高, 宽, 每像素字节数]`` 的 numpy 数组（自底向上会翻正）。"""
    import numpy as np
    step = info.bpp // 8
    count = info.width * info.height * step
    arr = np.frombuffer(info.pixels[:count], dtype=np.uint8).reshape(
        info.height, info.width, step)
    if info.bottom_up:
        arr = arr[::-1]
    return arr


def _iter_pixel_indices(info: BmpInfo, order: str, start: int):
    """纯 Python 回退路径：按行/按列给出像素访问顺序。"""
    w, h = info.width, info.height
    rows = list(range(h))
    if order == "col":
        seq = [r * w + c for c in range(w) for r in rows]
    else:
        seq = [r * w + c for r in rows for c in range(w)]
    return seq[start:]


def lsb_extract(info: BmpInfo, channel: str = "b", bit: int = 0,
                msb_first: bool = True, order: str = "row",
                start: int = 0, stride: int = 1,
                snake: bool = False, skip_pixels: int = 0) -> bytes:
    """提取最低(或第 ``bit``)有效位，打包成字节。

    ``channel``：``b``/``g``/``r``（24bpp 里字节顺序就是 B、G、R），
    ``all`` 表示 B、G、R 三个通道都取（**每像素 3 位**——很多自制工具这么写，
    只按"1 像素 1 位"去试会完全对不上）。
    ``order``：``row`` 逐行、``col`` 逐列、``plane`` **位平面拼接**
    （把第 0 位平面全部像素、第 1 位平面…依次拼起来，共 8 倍数据量）。
    ``snake``：**蛇形扫描**——偶数行从左到右、奇数行从右到左（自制打包工具常这么写；
    它不在"逐行/逐列"的组合空间里，所以只枚举那两种永远试不出来）。
    ``skip_pixels``：开头跳过多少个像素再开始取（题目有时留一段表头）。
    ``stride``：每取 1 位就跳过 ``stride - 1`` 个像素。
    """
    if order == "plane":
        parts = [lsb_extract(info, channel, b, msb_first, "row", start, stride,
                            snake, skip_pixels)
                 for b in range(8)]
        return b"".join(parts)
    step = info.bpp // 8
    if channel in ("b", "g", "r"):
        offs = [{"b": 0, "g": 1, "r": 2}[channel]] if step >= 3 else [0]
    else:
        offs = list(range(min(3, step)))
    try:
        import numpy as np
        arr = _pixel_array(info)
        if snake:
            arr = arr.copy()
            arr[1::2] = arr[1::2, ::-1]              # 奇数行反向 → 蛇形
        if order == "col":
            arr = np.transpose(arr, (1, 0, 2))
        sub = arr[:, :, offs]                              # [行, 列, 通道]
        bits = ((sub >> bit) & 1).reshape(-1)
        if skip_pixels:
            bits = bits[skip_pixels * len(offs):]
        bits = bits[start::max(1, stride)]
        if bits.size < 8:
            return b""
        return np.packbits(bits,
                           bitorder="big" if msb_first else "little").tobytes()
    except Exception:
        pass
    # 没有 numpy 时的回退（慢，但保证可用）
    seq = _iter_pixel_indices(info, order, start)
    if snake:
        w = info.width
        seq = [((r + 1) * w - 1 - (p % w)) if (p // w) % 2 else p
               for p in seq]
    seq = seq[skip_pixels:]
    bits: List[int] = []
    for idx in seq[::max(1, stride)]:
        base = idx * step
        for off in offs:
            if base + off < len(info.pixels):
                bits.append((info.pixels[base + off] >> bit) & 1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        chunk = bits[i:i + 8]
        val = 0
        if msb_first:
            for b in chunk:
                val = (val << 1) | b
        else:
            for j, b in enumerate(chunk):
                val |= b << j
        out.append(val)
    return bytes(out)


def _text_ratio(buf: bytes, limit: int = 512) -> float:
    head = buf[:limit]
    if not head:
        return 0.0
    good = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(head)


def _diversity(buf: bytes, limit: int = 256) -> float:
    """不同字节的占比。用来杀掉 "3333333…" 这种"可打印但毫无信息"的提取结果——
    它们往往是某个位平面整片是常数，而不是真的藏了文本。"""
    head = buf[:limit]
    if not head:
        return 0.0
    return min(1.0, len(set(head)) / 24.0)


def _printable_run(buf: bytes, limit: int = 256) -> int:
    """开头连续可打印字符的长度。

    为什么盯"开头"而不是整体可打印率：真实的 LSB 载荷是 [明文][随机噪声]，
    整体可打印率必然很低；但**开头**一定是一段连续的明文（flag、base64、zip 头）。
    所以"开头连续可打印 + 这段里字节有变化"才是有效判据。
    """
    n = 0
    for b in buf[:limit]:
        if 32 <= b < 127 or b in (9, 10, 13):
            n += 1
        else:
            break
    return n


def _lsb_score(buf: bytes, scorer: Optional[Callable[[bytes], float]]) -> float:
    run = _printable_run(buf)
    if run < 6:
        return 0.0
    div = min(1.0, len(set(buf[:run])) / 12.0)
    score = min(1.0, run / 32.0) * (0.4 + 0.6 * div)
    if scorer is not None:
        score += 0.5 * float(scorer(buf) or 0.0)
    return score


@dataclass
class LsbCandidate:
    channel: str
    bit: int
    msb_first: bool
    order: str
    stride: int
    data: bytes
    score: float
    head: str = ""
    snake: bool = False
    skip: int = 0

    def tag(self) -> str:
        extra = (" 蛇形" if self.snake else "")
        if self.skip:
            extra += f" 跳过{self.skip}像素"
        return (f"通道={self.channel} 位={self.bit} "
                f"{'MSB' if self.msb_first else 'LSB'}-first 顺序={self.order} "
                f"步长={self.stride}{extra}")


def scan_lsb(data: bytes, scorer: Optional[Callable[[bytes], float]] = None,
             top: int = 8, max_bit: int = 8,
             orders: Sequence[str] = ("row", "col", "plane"),
             strides: Sequence[int] = (1, 2, 3, 4),
             skips: Sequence[int] = (0, 64)) -> List[LsbCandidate]:
    """枚举"位平面 × 通道 × 位序 × 顺序 × 步长 × 蛇形 × 起始偏移"组合并排序。

    判据分两层：先看**开头连续可打印段的长度**（便宜的预筛），再交给 ``scorer``
    （工具里传 oracles 打分，能识别 base64/hex/flag 前缀等），并乘上"字节多样性"
    压掉 ``333333…`` 这种整片常数的假候选。

    ``skips``：开头跳过多少个像素（自制打包工具常留表头）。实测 R13 的真组合是
    "每像素 3 位（B、G、R 依次取）+ MSB-first + 跳过前 64 个像素"——它不在
    只试"1 像素 1 位 + 从 0 开始"的组合空间里，所以必须把这些变体也枚举进来。
    """
    info = bmp_pixels(data)
    if info is None:
        return []
    results: List[LsbCandidate] = []
    seen: set = set()
    for channel in ("b", "g", "r", "all"):
        for bit in range(max_bit):
            for msb in (True, False):
                for order in orders:
                    if order == "plane" and bit:      # plane 已经把 8 个平面拼完了
                        continue
                    for stride in strides:
                        for snake in (False, True):
                            for skip in skips:
                                buf = lsb_extract(info, channel, bit, msb, order,
                                                  stride=stride, snake=snake,
                                                  skip_pixels=skip)
                                if len(buf) < 16:
                                    continue
                                sc = _lsb_score(buf, scorer)
                                if sc < 0.15:
                                    continue
                                key = (buf[:64], round(sc, 3))
                                if key in seen:
                                    continue
                                seen.add(key)
                                results.append(LsbCandidate(
                                    channel, bit, msb, order, stride, buf, sc,
                                    buf[:64].decode("latin-1"), snake, skip))
    results.sort(key=lambda c: -c.score)
    return results[:top]


# ---------------------------------------------------------------- WAV


@dataclass
class WavInfo:
    channels: int
    sampwidth: int
    framerate: int
    nframes: int
    samples: bytes
    mono: List[float] = field(default_factory=list)

    @property
    def seconds(self) -> float:
        return self.nframes / self.framerate if self.framerate else 0.0

    def describe(self) -> str:
        return (f"WAV {self.channels} 声道 {self.sampwidth * 8} bit "
                f"{self.framerate} Hz {self.nframes} 帧（{self.seconds:.2f} 秒）")


def wav_info(data: bytes) -> Optional[WavInfo]:
    try:
        with wave.open(io.BytesIO(data), "rb") as w:
            ch, sw, fr, n = (w.getnchannels(), w.getsampwidth(),
                             w.getframerate(), w.getnframes())
            raw = w.readframes(n)
    except Exception:
        return None
    import array
    if sw == 2:
        arr = array.array("h")
        arr.frombytes(raw[:len(raw) - len(raw) % 2])
        if ch > 1:
            arr = array.array("h", [arr[i] for i in range(0, len(arr), ch)])
        peak = max(1.0, max(abs(v) for v in arr) if len(arr) else 1.0)
        mono = [v / peak for v in arr]
    elif sw == 1:
        arr = array.array("B", raw)
        if ch > 1:
            arr = array.array("B", [arr[i] for i in range(0, len(arr), ch)])
        mono = [(v - 128) / 128.0 for v in arr]
    else:
        return None
    return WavInfo(ch, sw, fr, len(mono), raw, mono)


def _goertzel(samples: Sequence[float], rate: int, freq: float) -> float:
    """单频点能量（Goertzel），比整段 FFT 更适合"逐帧看有没有某个音"。"""
    import math
    n = len(samples)
    if n == 0:
        return 0.0
    k = int(0.5 + n * freq / rate)
    w = 2.0 * math.pi * k / n
    c = 2.0 * math.cos(w)
    s1 = s2 = 0.0
    for x in samples:
        s0 = x + c * s1 - s2
        s2, s1 = s1, s0
    return (s1 * s1 + s2 * s2 - c * s1 * s2) ** 0.5 / n


_DTMF = {
    "1": (697, 1209), "2": (697, 1336), "3": (697, 1477), "A": (697, 1633),
    "4": (770, 1209), "5": (770, 1336), "6": (770, 1477), "B": (770, 1633),
    "7": (852, 1209), "8": (852, 1336), "9": (852, 1477), "C": (852, 1633),
    "*": (941, 1209), "0": (941, 1336), "#": (941, 1477), "D": (941, 1633),
}


def dtmf_decode(info: WavInfo, window: float = 0.04,
                hop: float = 0.02) -> str:
    """逐窗做 DTMF 双音识别（电话拨号音是最常见的"音频编码密钥"）。"""
    rate = info.framerate
    win = max(64, int(rate * window))
    step = max(1, int(rate * hop))
    out: List[str] = []
    for i in range(0, len(info.mono) - win, step):
        seg = info.mono[i:i + win]
        rms = (sum(x * x for x in seg) / len(seg)) ** 0.5
        if rms < 0.05:
            continue
        best, best_score = "?", 0.0
        for ch, (f1, f2) in _DTMF.items():
            e1 = _goertzel(seg, rate, f1)
            e2 = _goertzel(seg, rate, f2)
            sc = min(e1, e2) - 0.5 * max(e1, e2)      # 两个音都要强
            if sc > best_score:
                best, best_score = ch, sc
        if best_score > 0.05 and (not out or out[-1] != best):
            out.append(best)
    return "".join(out)


def fsk_bits(info: WavInfo, f0: float, f1: float, window: float = 0.01) -> bytes:
    """双频 FSK：每个窗口比较 f0/f1 谁的（Goertzel）能量大 → 1 bit。"""
    rate = info.framerate
    win = max(32, int(rate * window))
    bits: List[int] = []
    for i in range(0, len(info.mono) - win, win):
        seg = info.mono[i:i + win]
        e0 = _goertzel(seg, rate, f0)
        e1 = _goertzel(seg, rate, f1)
        bits.append(1 if e1 > e0 else 0)
    # 去掉停顿（连续相同值视为同一符号），再按 8 位打包（两种位序都试）
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        val = 0
        for b in bits[i:i + 8]:
            val = (val << 1) | b
        out.append(val)
    return bytes(out)


def dominant_frequencies(info: WavInfo, top: int = 8,
                         max_seconds: float = 2.0) -> List[Tuple[float, float]]:
    """整段（截前 ``max_seconds`` 秒）做 FFT，返回能量最强的若干频点。

    用途：先自动看看"这段音频里到底有几个稳定频率"，判断是 DTMF、FSK
    还是"人声/画图"（画图的频谱是宽带、单个频点能量并不集中）。
    """
    import numpy as np
    n = min(len(info.mono), int(info.framerate * max_seconds))
    if n < 256:
        return []
    seg = np.asarray(info.mono[:n], dtype=np.float64)
    seg = seg - seg.mean()
    win = np.hanning(len(seg))
    spec = np.abs(np.fft.rfft(seg * win))
    freqs = np.fft.rfftfreq(len(seg), 1.0 / info.framerate)
    peak = spec.max() or 1.0
    order = np.argsort(spec)[::-1][:top * 40]
    picked: List[Tuple[float, float]] = []
    for idx in order:
        f = float(freqs[idx])
        if any(abs(f - g) < 30 for g, _ in picked):
            continue
        picked.append((f, float(spec[idx] / peak)))
        if len(picked) >= top:
            break
    return picked


def tone_track(info: WavInfo, frame: float = 0.005,
               fmin: float = 200.0, fmax: float = 12000.0
               ) -> List[Tuple[float, float, float]]:
    """逐帧找主频：返回 ``[(时刻, 主频, 相对能量), …]``。

    "把密钥画成声音"的做法是：每个时间片发一个固定音，音的**高低**代表图案里的
    行，**时间**代表列。所以只要逐帧取主频，再按频率聚类，就能把图还原成矩阵。
    """
    try:
        import numpy as np
    except Exception:                                    # pragma: no cover
        return []
    rate = info.framerate
    nfft = 2048
    hop = max(1, int(rate * frame))
    x = np.asarray(info.mono, dtype=np.float64)
    if len(x) < nfft:
        return []
    freqs = np.fft.rfftfreq(nfft, 1.0 / rate)
    keep = (freqs >= fmin) & (freqs <= fmax)
    freqs = freqs[keep]
    out: List[Tuple[float, float, float]] = []
    win = np.hanning(nfft)
    for i in range(0, len(x) - nfft, hop):
        seg = x[i:i + nfft]
        if float(np.sqrt((seg ** 2).mean())) < 1e-4:
            out.append((i / rate, 0.0, 0.0))
            continue
        spec = np.abs(np.fft.rfft(seg * win))[keep]
        k = int(np.argmax(spec))
        peak = float(spec[k])
        mean = float(spec.mean()) or 1e-9
        out.append((i / rate, float(freqs[k]), peak / mean))
    return out


def detect_tone_rows(data: bytes, frame: float = 0.005, fmax: float = 16000.0,
                     min_count: int = 8, tolerance: float = 120.0,
                     nfft: int = 4096) -> List[float]:
    """自动探测"用音调画图"时用了哪些音高（返回升序的频率列表）。

    为什么必须自动探测：**把频率轴上限写死会直接改变读出来的字**。实测 R13 就是这样：
    一开始把上限设成 8000 Hz，字形被截掉一部分，`XJU2026` 被读成了 `XJUSEC`
    （数字 `2/0/6` 看成 `S/O/8`）。正确做法是先统计"哪些频率被持续用到"，
    按出现次数找峰、再按容差合并，得到真正的音高网格。
    """
    info = wav_info(data)
    if info is None:
        return []
    try:
        import numpy as np
    except Exception:                                    # pragma: no cover
        return []
    rate = info.framerate
    hop = max(1, int(rate * frame))
    x = np.asarray(info.mono, dtype=np.float64)
    if len(x) < nfft:
        return []
    freqs = np.fft.rfftfreq(nfft, 1.0 / rate)
    keep = (freqs > 80) & (freqs <= fmax)
    freqs = freqs[keep]
    peaks: List[float] = []
    win = np.hanning(nfft)
    for i in range(0, len(x) - nfft, hop):
        seg = x[i:i + nfft]
        if float(np.sqrt((seg ** 2).mean())) < 1e-4:
            continue
        spec = np.abs(np.fft.rfft(seg * win))[keep]
        k = int(np.argmax(spec))
        if spec[k] > 12 * float(spec.mean() or 1e-9):
            peaks.append(float(freqs[k]))
    if not peaks:
        return []
    # 直方图找持续出现的音高（步长 25 Hz 足够分辨 400 Hz 的网格）
    counts: Dict[int, int] = {}
    for f in peaks:
        counts[int(round(f / 25.0)) * 25] = counts.get(int(round(f / 25.0)) * 25, 0) + 1
    cand = sorted((f for f, c in counts.items() if c >= min_count))
    rows: List[float] = []
    for f in cand:
        if rows and f - rows[-1] <= tolerance:
            rows[-1] = (rows[-1] * 3 + f) / 4          # 合并抖动的相邻峰
        else:
            rows.append(float(f))
    return rows


def tone_rows_ascii(data: bytes, frame: float = 0.005, fmax: float = 16000.0,
                    seconds: float = 8.0, max_cols: int = 220,
                    tolerance: float = 120.0, nfft: int = 4096) -> str:
    """按**自动探测出来的音高网格**把频谱画成 ASCII（一行 = 一个音高）。

    与 ``tone_grid_ascii``（固定行数的二维阈值）相比，这种做法不会因为
    行数/上限选错而改变字形，输出的行数就等于"题目实际用了几个音高"。
    """
    rows = detect_tone_rows(data, frame=frame, fmax=fmax, tolerance=tolerance,
                            nfft=nfft)
    info = wav_info(data)
    if not rows or info is None:
        return ""
    try:
        import numpy as np
    except Exception:                                    # pragma: no cover
        return ""
    rate = info.framerate
    hop = max(1, int(rate * frame))
    x = np.asarray(info.mono[:int(rate * seconds)] if seconds else info.mono,
                   dtype=np.float64)
    freqs = np.fft.rfftfreq(nfft, 1.0 / rate)
    grid = [[] for _ in rows]
    win = np.hanning(nfft)
    for i in range(0, len(x) - nfft, hop):
        seg = x[i:i + nfft]
        if float(np.sqrt((seg ** 2).mean())) < 1e-4:
            for line in grid:
                line.append(" ")
            continue
        spec = np.abs(np.fft.rfft(seg * win))
        # 每个音高用一个窄带取能量（±tolerance/2），比全谱峰值稳定
        energies = []
        for f in rows:
            band = (freqs >= f - tolerance) & (freqs <= f + tolerance)
            energies.append(float(spec[band].max()) if band.any() else 0.0)
        top = max(energies) or 1e-9
        mean = float(spec.mean()) or 1e-9
        for r, e in enumerate(energies):
            grid[r].append("#" if e > 0.25 * top and e > 6 * mean else " ")
    cols = len(grid[0])
    step = max(1, cols // max_cols)
    body = []
    for r in range(len(rows) - 1, -1, -1):              # 高音画在上面
        line = "".join(grid[r][j] for j in range(0, cols, step))
        body.append(f"{rows[r]:6.0f}Hz |{line}|")
    head = (f"频谱点阵（自动探测到 {len(rows)} 个音高："
            f"{'、'.join(f'{f:.0f}' for f in rows)} Hz；{cols} 个时间片 × "
            f"{frame * 1000:.0f} ms）")
    return head + "\n" + "\n".join(body)


def tone_grid_ascii(data: bytes, frame: float = 0.003, fmax: float = 12000.0,
                    rows: int = 34, cols: int = 200, seconds: float = 8.0,
                    rel_threshold: float = 0.38, nfft: int = 4096) -> str:
    """把"用音调画出来的图"还原成终端里可读的 ASCII 点阵。

    为什么不用"逐帧取主频"：画出来的字形里，一个时间片**可能同时有两个音**
    （笔画交叉处），而且正弦的谐波会跑出鬼影。所以这里改用**二维阈值**：
    整段做 STFT → 按固定频率网格降到 ``rows × cols`` → 每个格子的能量
    超过"该行最大值 × rel_threshold"就打 ``#``。字形（往往是密钥本身）会
    直接显示出来，即使没法看图也能读。
    """
    info = wav_info(data)
    if info is None:
        return ""
    try:
        import numpy as np
    except Exception:                                    # pragma: no cover
        return ""
    rate = info.framerate
    x = np.asarray(info.mono[:int(rate * seconds)] if seconds else info.mono,
                   dtype=np.float64)
    if len(x) < nfft:
        return ""
    cols_n = min(cols, max(1, len(x) // nfft) * 4)
    hop = max(1, (len(x) - nfft) // max(1, cols_n - 1)) if len(x) > nfft else 1
    frames = []
    for i in range(0, len(x) - nfft + 1, hop):
        frames.append(np.abs(np.fft.rfft(x[i:i + nfft] * np.hanning(nfft))))
        if len(frames) >= cols_n:
            break
    if not frames:
        return ""
    spec = np.array(frames).T                                    # [freq, time]
    freqs = np.fft.rfftfreq(nfft, 1.0 / rate)
    keep = freqs <= fmax
    spec, freqs = spec[keep], freqs[keep]
    # 按频率分 rows 组，每组取该频段的最大能量，再沿时间轴聚合成一行
    edges = np.linspace(0, len(freqs) - 1, rows + 1).astype(int)
    grid = np.zeros((rows, spec.shape[1]))
    for r in range(rows):
        a, b = edges[r], max(edges[r] + 1, edges[r + 1])
        grid[r] = spec[a:b].max(axis=0)
    for r in range(rows):                       # 每行单独归一化：抗整体衰减
        m = grid[r].max()
        if m > 0:
            grid[r] = grid[r] / m
    body = []
    for r in range(rows - 1, -1, -1):           # 高频画在上面
        lo = freqs[edges[r]]
        line = "".join("#" if v >= rel_threshold else " " for v in grid[r])
        body.append(f"{lo:6.0f}Hz |{line}|")
    head = (f"频谱点阵：{rows} 个频段 × {grid.shape[1]} 个时间片"
            f"（{hop / rate * 1000:.0f} ms/列，上限 {fmax:.0f} Hz）")
    return head + "\n" + "\n".join(body)


def spectrogram_png(data: bytes, out_path: str, seconds: float = 6.0,                    fmax: float = 8000.0, width: int = 1000,
                    height: int = 420) -> Optional[str]:
    """把音频画成频谱图 PNG —— 出题人把密钥"画"成声音时的唯一出路。

    返回写出的路径（失败返回 ``None``）。没有 numpy/PIL 时返回 ``None``，
    调用方应提示用户用 Audacity 自己看频谱图。
    """
    info = wav_info(data)
    if info is None:
        return None
    try:
        import numpy as np
        from PIL import Image
    except Exception:
        return None
    rate = info.framerate
    x = np.asarray(info.mono[:int(rate * seconds)], dtype=np.float64)
    if len(x) < 512:
        return None
    nfft = 1024
    hop = max(1, len(x) // width)
    frames = []
    for i in range(0, len(x) - nfft, hop):
        seg = x[i:i + nfft] * np.hanning(nfft)
        frames.append(np.abs(np.fft.rfft(seg)))
        if len(frames) >= width:
            break
    if not frames:
        return None
    spec = np.array(frames).T                        # [freq, time]
    bins = int(nfft / 2 * fmax / (rate / 2))
    spec = spec[:max(1, bins)]
    spec = np.log1p(spec)
    spec = spec - spec.min()
    if spec.max() > 0:
        spec = spec / spec.max()
    img = Image.fromarray((spec[::-1] * 255).astype("uint8"), mode="L")
    img = img.resize((img.width, height))
    img = img.convert("RGB")
    # 手工上色（黑 → 蓝 → 绿 → 黄 → 白），比灰度更容易看出图里的字
    px = img.load()
    for yy in range(img.height):
        for xx in range(img.width):
            v = px[xx, yy][0] / 255.0
            r = int(max(0.0, min(1.0, 1.5 * v - 0.5)) * 255)
            g = int(max(0.0, min(1.0, 1.5 - abs(v - 0.6) * 3)) * 255)
            b = int(max(0.0, min(1.0, 1.2 - 2.0 * v)) * 255)
            px[xx, yy] = (r, g, b)
    img.save(out_path)
    return out_path


def report(data: bytes, kind: str = "auto") -> str:
    """给隐写相关文件做一份中文描述（CLI 的 ``stego`` 命令用）。"""
    lines: List[str] = []
    if kind in ("auto", "bmp") and data[:2] == b"BM":
        info = bmp_pixels(data)
        if info:
            lines.append(info.describe())
            ratios = []
            for bit in range(8):
                buf = lsb_extract(info, "all", bit)
                ratios.append(f"第{bit}位 文本率={_text_ratio(buf):.2f}")
            lines.append("  位平面可打印率：" + "，".join(ratios))
    if kind in ("auto", "wav") and data[:4] == b"RIFF":
        info = wav_info(data)
        if info:
            lines.append(info.describe())
            freqs = dominant_frequencies(info)
            if freqs:
                lines.append("  最强频点：" + "，".join(
                    f"{f:.0f}Hz({p:.2f})" for f, p in freqs[:5]))
            code = dtmf_decode(info)
            if code:
                lines.append(f"  DTMF 试解：{code}")
    return "\n".join(lines)
