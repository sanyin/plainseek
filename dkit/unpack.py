"""UPX 自动脱壳：**在内存里跑壳的 stub，把解压好的镜像 dump 出来**。

## 为什么做成"内存脱壳"而不是调 upx -d

1. 调外部 `upx -d` 需要**先有一个可读的 .exe 文件**。实测遇到杀软（Kaspersky）把样本锁住时，
   `open()` 直接 Access denied，`upx` 也读不了——但"从压缩包里流式读进内存"是可行的；
2. 题目常把壳改过（换个节名、动过 stub），`upx -d` 会报 "not packed by UPX"；
   而**跑一遍 stub 再 dump** 对"改过的 UPX"同样有效；
3. 脱壳本来就是"执行到 OEP 再 dump"——模拟执行正好能干这事，且不需要真跑样本。

## 做法

1. 把镜像按 PE 的节布局映射进 unicorn（复用 `emu.load_image`）；
2. 从入口跑 stub，**一旦 RIP 离开壳所在的节就停**（UPX 的 stub 全在 `UPX1` 里，
   解压完会跳进 `UPX0`——那一刻就是 OEP）；
3. 把各节的**内存内容**按 RVA 写回一个"平铺镜像"（`PointerToRawData = RVA`），
   并把入口改成 OEP、把节名归一化；
4. 这样重新拼出来的 PE 能被 `pe.PeImage.parse` 正常解析，
   静态分析（字符串/导入/反汇编）和再模拟都能直接用。

## 已知边界

* 只处理"节里有解压后代码"的**普通 UPX**（x86/x64）。遇到 UPX 的 LZMA 变体、
  或壳里带 SEH 异常分发导致模拟卡住的，会如实报"脱壳失败"而不是硬编一个结果；
* 脱壳后如果程序还依赖"壳修好的 IAT/重定位"，本工具后续 `map_stubs` 会按
  导入表重新打桩（这一点反而比真实环境更适合分析）。
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from . import emu, pe

#: UPX 的入口点特征（x86 / x64 stub 开头）
ENTRY_SIGS = (b"\x53\x56\x57\x55\x48\x8d",       # x64
              b"\x60\xbe",                        # x86 pushad; mov esi,
              b"\x60\x8b\x74\x24\x24")


def looks_like_upx(img) -> Tuple[bool, List[str]]:
    """判断是不是 UPX（返回 是否 + 判据列表，判据要能给人看）。"""
    reasons: List[str] = []
    names = [s.name for s in getattr(img, "sections", [])]
    if any(n.startswith("UPX") for n in names):
        reasons.append(f"节名 {[n for n in names if n.startswith('UPX')]} 是 UPX 特征")
    try:
        head = bytes(emu.read_mem(img, img.entry, 8))
    except Exception:
        head = b""
    for sig in ENTRY_SIGS:
        if head.startswith(sig):
            reasons.append(f"入口字节 {head[:6].hex(' ')} 命中 UPX stub 签名")
            break
    # 高熵 + 空节（UPX0 在文件里没有数据）也是强证据
    for sec in getattr(img, "sections", []):
        if sec.name.upper().startswith("UPX") and not sec.raw_size:
            reasons.append(f"{sec.name} 在文件里 raw=0（解压后代码的落点）")
            break
    return (len(reasons) >= 2), reasons


def _dump_flat(img, uc, oep: int) -> bytes:
    """把"内存里的镜像"拼成一个可解析的平铺 PE（文件偏移 == RVA）。"""
    size = max((s.vaddr - img.image_base) + max(s.vsize, s.raw_size, 0x200)
               for s in img.sections)
    image = bytearray(size)
    # 头部：直接用文件里的原始头（size_of_headers 以内）
    header_len = min(getattr(img, "size_of_headers", 0x400) or 0x400, len(img.blob))
    image[0:header_len] = img.blob[0:header_len]
    e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
    coff = e_lfanew + 4
    opt_size = struct.unpack_from("<H", image, coff + 16)[0]
    opt = coff + 20
    is_64 = struct.unpack_from("<H", image, opt)[0] == 0x20B
    sec_off = opt + opt_size
    n_sec = struct.unpack_from("<H", image, coff + 2)[0]
    for i in range(n_sec):
        base = sec_off + i * 40
        name = bytes(image[base:base + 8])
        # 节头布局：Name(8) VirtualSize(+8) VirtualAddress(+12)
        #          SizeOfRawData(+16) PointerToRawData(+20)
        # ⚠ 之前把 +12 读成 (VirtualSize, VirtualAddress) 了，结果 vsize 拿成了
        # SizeOfRawData（UPX0 在文件里是 0），dump 出来只有 0x200 字节。
        vsize, vaddr = struct.unpack_from("<II", image, base + 8)
        raw = bytes(uc.mem_read(img.image_base + vaddr, max(vsize, 0x200)))
        image[vaddr:vaddr + len(raw)] = raw
        # 平铺：raw_ptr = RVA（file offset == RVA），raw_size = vsize
        struct.pack_into("<I", image, base + 16, max(vsize, 0x200))
        struct.pack_into("<I", image, base + 20, vaddr)
        # 节名归一化：UPX0/UPX1 → .text/.data（避免下游再被判成"加壳"）
        if name.upper().startswith(b"UPX"):
            new = b".text\x00\x00\x00" if i == 0 else b".data\x00\x00\x00"
            image[base:base + 8] = new
    # 入口改成 OEP
    struct.pack_into("<I", image, opt + 16,
                     oep - img.image_base if oep >= img.image_base else oep)
    # 清掉"文件内 raw=0 的空节"造成的 SizeOfImage 差异：保持原值即可
    return bytes(image)


def unpack_in_memory(blob: bytes, max_ins: int = 4_000_000,
                     verbose: bool = False) -> Tuple[Optional[bytes], int, List[str]]:
    """跑壳的 stub 直到跳进解压区，返回 ``(平铺镜像, OEP, 说明)``。

    失败时第一项为 ``None``，说明里写清原因。
    """
    notes: List[str] = []
    try:
        img = emu.load_image(blob)
    except Exception as exc:
        return None, 0, [f"不是可解析的 PE/ELF：{exc}"]
    ok, reasons = looks_like_upx(img)
    if not ok:
        return None, 0, ["不像 UPX：" + ("；".join(reasons) or "无特征")]
    notes.extend(reasons)
    # 壳所在的节：名字以 UPX 开头且**文件里有数据**的那一个（stub 在里头）
    stub = None
    for sec in img.sections:
        if sec.name.upper().startswith("UPX") and sec.raw_size:
            stub = sec
            break
    if stub is None:
        stub = max(img.sections, key=lambda s: s.raw_size)
    lo, hi = stub.vaddr, stub.vaddr + max(stub.vsize, stub.raw_size)
    notes.append(f"壳 stub 节 {stub.name}：0x{lo:x}~0x{hi:x}")
    # 跑 stub，**一旦 RIP 离开 stub 节就停**（那一刻通常就是 OEP）
    res = emu.run_function(img, img.entry, max_ins=max_ins, snapshot=False,
                           stop_outside=(lo, hi), api=True)
    uc = res.get("_uc")
    oep = int(res.get("oep") or 0)
    notes.append(f"第一次停止：{res.get('stop')}；候选 OEP≈0x{oep:x}")
    if not uc or not oep:
        return None, 0, notes + ["没能拿到 OEP（壳可能在等系统调用/反调试）"]
    if lo <= oep < hi:
        return None, 0, notes + ["RIP 还在壳节里，脱壳没完成"]

    # **解压密度自检**：第一次跳出壳节可能只是"中间跳转"（壳分好几段搬运），
    # 这时解压区还是空的。做法很直接：量一下解压区的非零密度，太稀就**重跑到指令上限**
    # （让整段解压跑完），仍用第一次的候选 OEP 当入口。
    # 实测看雪/吾爱这类题里，UPX 的 stub 会先跳到一小段引导代码，直接 dump 会得到空壳。
    target = None
    for sec in img.sections:
        # 解压落点 = **文件里没有数据**的那个节（UPX0，raw_size == 0）
        if sec.raw_size == 0 and sec.vsize > 0x1000:
            target = sec
            break
    if target is None:
        for sec in img.sections:
            if not sec.name.upper().startswith("UPX") and sec.vsize > 0x1000:
                target = sec
                break
    density = 1.0
    if target is not None:
        try:
            head = bytes(uc.mem_read(img.image_base + target.vaddr,
                                     min(target.vsize, 0x8000)))
            density = sum(1 for b in head if b) / max(1, len(head))
        except Exception:
            density = 0.0
        notes.append(f"解压区 {target.name} 非零密度 {density:.2%}")
    if density < 0.05:
        notes.append("密度太低 → 重跑到指令上限，让解压彻底完成")
        res2 = emu.run_function(img, img.entry, max_ins=max_ins, snapshot=False,
                                api=True)
        uc = res2.get("_uc") or uc
        notes.append(f"第二次停止：{res2.get('stop')}")
        try:
            head = bytes(uc.mem_read(img.image_base + target.vaddr,
                                     min(target.vsize, 0x8000)))
            notes.append(f"解压区非零密度（重跑后）{sum(1 for b in head if b)/max(1,len(head)):.2%}")
        except Exception:
            pass
    flat = _dump_flat(img, uc, oep)
    notes.append(f"已 dump 平铺镜像 {len(flat)} 字节（入口改为 0x{oep:x}）")
    # 自检：dump 出来的东西必须能被自己的解析器读回来
    try:
        again = pe.PeImage.parse(flat)
        notes.append(f"自检：重新解析成功，{len(again.sections)} 个节，"
                     f"入口=0x{again.entry:x}")
    except Exception as exc:
        notes.append(f"⚠ 自检失败（dump 可能不完整）：{exc}")
    return flat, oep, notes
