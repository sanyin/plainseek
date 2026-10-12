"""模拟执行取证（Unicorn + 自解析 ELF）：把"必须跑一遍才知道"的常量挖出来。

投稿包实测暴露的最大缺口就是这个：**答案不在文件里，而在"程序跑起来之后"**。

* R03：解密用的置换表是运行时用 LCG + Fisher-Yates 生成的 → 只能重放/模拟执行；
* R05：TEA 的 delta 等常量被改过，标准值在二进制里出现 0 次 → 要跑轮函数或反推立即数；
* R08：先自修改代码（SMC）解密出真代码，再执行 → 不解密就反汇编不到东西。

本模块提供三件套，够覆盖上面这类题：

1. `ElfImage`：自己解析 ELF（程序头 / 节表 / 入口 / 架构），不依赖 pyelftools；
   顺手给出"哪些节可执行""哪些是 .rodata/.bss"——**运行时生成的表通常落在 .bss**；
2. `xrefs()`：给定一段锚点字符串（如 `"[+] Correct!"`），找出代码里引用它的地址，
   再顺着调用关系定位 main / verify —— 这样脚本就不必硬编码地址（题目一变就废）；
3. `run_function()`：用 Unicorn 按 PT_LOAD 铺内存、铺栈、按 SysV x86-64 传参
   （rdi, rsi, rdx, rcx, r8, r9），跑到"返回哨兵地址"或指令数上限为止，
   支持读回寄存器与任意内存（**这就是把 .bss 里生成的表取出来的方式**）。

设计取舍：只做 x86-64（CTF 逆向题的绝对主流），遇到别的架构直接明说"不支持"，
而不是猜。syscall / 未映射内存一律**停下来并报原因**，绝不静默继续——
静默继续会给你一个看起来合理但其实错的值，那比报错有害得多。
"""

from __future__ import annotations

import collections
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

PT_LOAD, PT_DYNAMIC = 1, 2
PF_X, PF_W, PF_R = 1, 2, 4
EM_X86_64, EM_386, EM_AARCH64 = 0x3E, 0x03, 0xB7
ET_EXEC, ET_DYN = 2, 3


@dataclass
class Segment:
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int
    data: bytes

    @property
    def executable(self) -> bool:
        return bool(self.flags & PF_X)

    @property
    def writable(self) -> bool:
        return bool(self.flags & PF_W)

    def describe(self) -> str:
        perm = "".join(c if self.flags & bit else "-"
                       for c, bit in (("R", PF_R), ("W", PF_W), ("X", PF_X)))
        return (f"vaddr=0x{self.vaddr:x} filesz=0x{self.filesz:x} "
                f"memsz=0x{self.memsz:x} {perm}")


@dataclass
class Section:
    name: str
    addr: int
    offset: int
    size: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & 0x4)

    @property
    def writable(self) -> bool:
        return bool(self.flags & 0x1)


@dataclass
class ElfImage:
    blob: bytes
    bits: int = 64
    machine: int = EM_X86_64
    etype: int = ET_EXEC
    entry: int = 0
    segments: List[Segment] = field(default_factory=list)
    sections: List[Section] = field(default_factory=list)
    base: int = 0                      # ET_DYN 时实际加载基址

    # ------------------------------------------------------------ 解析
    @classmethod
    def parse(cls, blob: bytes, base: Optional[int] = None) -> "ElfImage":
        if blob[:4] != b"\x7fELF":
            raise ValueError("不是 ELF 文件")
        bits = 64 if blob[4] == 2 else 32
        endian = "<" if blob[5] == 1 else ">"
        img = cls(blob=blob, bits=bits)
        if bits == 64:
            e_type, e_machine, _v, e_entry, e_phoff, _e_shoff = struct.unpack_from(
                endian + "HHIQQQ", blob, 16)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
                struct.unpack_from(endian + "HHHHH", blob, 54)
            ph_fmt, ph_size = endian + "IIQQQQQQ", 56
            sh_fmt, sh_size = endian + "IIQQQQIIQQ", 64
        else:
            e_type, e_machine, _v, e_entry, e_phoff, _e_shoff = struct.unpack_from(
                endian + "HHIIII", blob, 16)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
                struct.unpack_from(endian + "HHHHH", blob, 40)
            ph_fmt, ph_size = endian + "IIIIIIII", 32
            sh_fmt, sh_size = endian + "IIIIIIIIII", 40
        img.machine, img.etype, img.entry = e_machine, e_type, e_entry
        img.base = base if base is not None else (0x400000 if e_type == ET_DYN else 0)
        # 程序头 → 可加载段。
        # 64 位布局：p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
        # 32 位布局：p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
        for i in range(e_phnum):
            off = e_phoff + i * (e_phentsize or ph_size)
            if off + ph_size > len(blob):
                break
            fields = struct.unpack_from(ph_fmt, blob, off)
            if fields[0] != PT_LOAD:
                continue
            if bits == 64:
                p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz = fields[1:7]
            else:
                p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags = fields[1:7]
            img.segments.append(Segment(
                offset=p_offset, vaddr=p_vaddr + img.base, filesz=p_filesz,
                memsz=p_memsz, flags=p_flags,
                data=blob[p_offset:p_offset + p_filesz]))
        # 节表 → 主要为了拿节名（.bss / .rodata 在哪）
        names = b""
        if e_shstrndx and e_shstrndx < e_shnum:
            off = _e_shoff + e_shstrndx * (e_shentsize or sh_size)
            if off + sh_size <= len(blob):
                str_off, str_size = struct.unpack_from(
                    (endian + "IIQQQQIIQQ") if bits == 64 else (endian + "IIIIIIIIII"),
                    blob, off)[4:6]
                names = blob[str_off:str_off + str_size]
        for i in range(e_shnum):
            off = _e_shoff + i * (e_shentsize or sh_size)
            if off + sh_size > len(blob):
                break
            sh = struct.unpack_from(sh_fmt, blob, off)
            name_off = sh[0]
            name = ""
            if names and name_off < len(names):
                end = names.find(b"\x00", name_off)
                name = names[name_off:end if end > 0 else name_off + 16].decode(
                    "latin-1", "replace")
            # 64/32 位节头前六个字段布局一致：name, type, flags, addr, offset, size
            img.sections.append(Section(name=name, addr=sh[3] + img.base,
                                        offset=sh[4], size=sh[5], flags=sh[2]))
        return img

    # ------------------------------------------------------------ 查询
    def writable_regions(self) -> List[Segment]:
        return [s for s in self.segments if s.writable]

    def bss_hint(self) -> Optional[Tuple[int, int]]:
        """猜 .bss 的 (地址, 大小)：运行时生成的表通常就在这里。"""
        for sec in self.sections:
            if sec.name == ".bss" and sec.size:
                return sec.addr + self.base, sec.size
        for seg in self.segments:
            if seg.writable and seg.memsz > seg.filesz:
                return seg.vaddr + seg.filesz, seg.memsz - seg.filesz
        return None

    def describe(self) -> str:
        arch = {EM_X86_64: "x86-64", EM_386: "i386",
                EM_AARCH64: "aarch64"}.get(self.machine, f"machine=0x{self.machine:x}")
        kind = {ET_EXEC: "ET_EXEC(固定地址)", ET_DYN: "ET_DYN(PIE/共享库)",
                }.get(self.etype, f"type={self.etype}")
        lines = [f"ELF {self.bits} 位 {arch} {kind} entry=0x{self.entry + self.base:x}",
                 f"  可加载段 {len(self.segments)} 个："]
        for seg in self.segments:
            lines.append("    " + seg.describe())
        bss = self.bss_hint()
        if bss:
            lines.append(f"  .bss 推测 @ 0x{bss[0]:x} 大小 0x{bss[1]:x}"
                         f"（运行时生成的表一般在这里）")
        names = [s.name for s in self.sections if s.name in
                 (".text", ".rodata", ".data", ".bss", ".init_array")]
        if names:
            lines.append("  关键节：" + "，".join(
                f"{s.name}@0x{s.addr + self.base:x}" for s in self.sections
                if s.name in names))
        return "\n".join(lines)


def xrefs(img: ElfImage, needle: bytes, window: int = 0x4000) -> List[int]:
    """找代码里引用 ``needle`` 的地址（RIP 相对 lea/mov 与绝对地址两种都覆盖）。

    CTF 题目改一改字符串/顺序，硬编码的地址就全废了；用"锚点字符串 → 引用点"
    定位，脚本才活得久。返回的是**代码地址**（不是数据地址）。
    """
    hits: List[int] = []
    for target in find_bytes(img.blob, needle):
        target_addr = None
        for seg in img.segments:
            if seg.offset <= target < seg.offset + seg.filesz:
                target_addr = target - seg.offset + seg.vaddr
                break
        if target_addr is None:
            continue
        want = struct.pack("<I", target_addr & 0xFFFFFFFF)
        if img.bits == 32:
            for code in img.segments:
                if not code.executable:
                    continue
                start = 0
                while True:
                    idx = code.data.find(want, start)
                    if idx < 0:
                        break
                    hits.append(code.vaddr + idx)
                    start = idx + 1
        else:
            # RIP 相对：lea reg, [rip+disp32] —— 遍历所有 4 字节窗口算一下
            for code in img.segments:
                if not code.executable:
                    continue
                for idx in range(len(code.data) - 8):
                    disp = struct.unpack_from("<i", code.data, idx + 3)[0]
                    if code.vaddr + idx + 7 + disp == target_addr:
                        op = code.data[idx]
                        if op in (0x48, 0x4C):          # REX.W / REX.WR
                            hits.append(code.vaddr + idx)
    return sorted(set(hits))


def find_bytes(blob: bytes, needle: bytes) -> List[int]:
    out, start = [], 0
    while True:
        idx = blob.find(needle, start)
        if idx < 0:
            return out
        out.append(idx)
        start = idx + 1


# ------------------------------------------------------------------ 模拟执行

_SENTINEL = 0x7FF00000                 # 假返回地址（在映射出来的栈区里）：跑回这里就算"函数返回了"


class EmuError(RuntimeError):
    pass


def _mem_size(seg) -> int:
    """ELF 段用 filesz/memsz，PE 节用 raw_size/vsize —— 这里统一。"""
    return max(getattr(seg, "memsz", 0) or 0, getattr(seg, "filesz", 0) or 0,
               getattr(seg, "vsize", 0) or 0, getattr(seg, "raw_size", 0) or 0)


def _free_region(img, size: int, candidates: Sequence[int]) -> int:
    """在候选地址里挑一块不和镜像冲突的区域（IAT 桩 / 堆要用）。"""
    taken = [(s.vaddr, s.vaddr + _mem_size(s)) for s in img.segments]
    for cand in candidates:
        if all(cand + size <= lo or cand >= hi for lo, hi in taken):
            return cand
    return candidates[-1]


def load_image(blob: bytes):
    """按文件头自动选 PE / ELF 解析器（`emu` 命令和 `run_main` 都用它）。"""
    from . import pe as _pe
    if blob[:2] == b"MZ":
        return _pe.PeImage.parse(blob)
    if blob[:4] == b"\x7fELF":
        return ElfImage.parse(blob)
    raise EmuError("既不是 PE 也不是 ELF，无法模拟执行")


def _setup_teb(uc, bits: int, image_base: int, stack_base: int, stack_top: int
               ) -> Tuple[str, int, int]:
    """铺一个最小的 **TEB/PEB**（Windows 程序启动早期一定会读它）。

    踩过的坑：Windows 的 CRT 启动代码里有 ``mov rax, gs:[0x30]``（取 PEB）这种指令，
    不铺 TEB 的话 unicorn 直接报 ``UC_ERR_MAP``，模拟在第 13 条指令就死了。

    这里铺的东西同时有**第二个作用**：反调试。经典反调试就是读
    ``PEB->BeingDebugged``（x64 偏移 0x02）和 ``PEB->NtGlobalFlag``（偏移 0xBC），
    我们把它们全部写成 0，程序就会认为"没有调试器"。

    x64 用 GS 段基址指向 TEB；x86 用 FS 段基址，并且要额外填 SEH 链
    （``FS:[0]``）与栈边界（``FS:[4]``/``FS:[8]``）。
    """
    from unicorn import x86_const as xc
    teb = 0x7FFD0000 if bits == 64 else 0x7FFD0000
    peb = teb + 0x1000
    tls = teb + 0x1800
    if bits == 32:
        # ⚠ Unicorn 2.x 在 **32 位模式下会静默忽略 FS_BASE/GS_BASE 的写入**
        #（id 250/251 是 deprecated no-op），而 PE 一开局就 `mov eax, fs:[0]` 读 SEH 链。
        # 所以 32 位只能反过来利用"FS 基址 = 0"这个事实：**把 TEB 直接铺在地址 0**，
        # 让 fs:[x] 正好等于 [x]。代价是空指针解引用不再报错（会读到 TEB 内容），
        # 这个取舍是值得的——不然 32 位 PE 几乎全都在第 6 条指令就崩。
        teb, peb, tls = 0x0, 0x1000, 0x1800
    try:
        uc.mem_map(teb & ~0xFFF, 0x3000)
    except Exception:
        pass
    zero = b"\x00" * 0x1000
    uc.mem_write(teb, zero)
    uc.mem_write(peb, zero)
    uc.mem_write(tls, zero)
    if bits == 64:
        uc.reg_write(xc.UC_X86_REG_GS_BASE, teb)
        uc.mem_write(teb + 0x30, struct.pack("<Q", peb))      # TEB->ProcessEnvironmentBlock
        uc.mem_write(teb + 0x58, struct.pack("<Q", tls))      # TEB->ThreadLocalStoragePointer
        uc.mem_write(peb + 0x10, struct.pack("<Q", image_base))
        stack_base_addr = 0x08
    else:
        # 32 位：FS 基址没法设置，只能让 teb=0（见上面注释）
        uc.mem_write(teb + 0x18, struct.pack("<I", teb))      # TEB self（FS:[0x18]）
        uc.mem_write(teb + 0x30, struct.pack("<I", peb))
        uc.mem_write(teb + 0x2C, struct.pack("<I", tls))      # TLS 数组
        uc.mem_write(peb + 0x08, struct.pack("<I", image_base))
        uc.mem_write(teb + 0x00, struct.pack("<I", 0xFFFFFFFF))   # SEH 链尾
        uc.mem_write(teb + 0x04, struct.pack("<I", stack_top))
        uc.mem_write(teb + 0x08, struct.pack("<I", stack_base))
        stack_base_addr = 0x04
        del xc
    del stack_base_addr
    # PEB->BeingDebugged / NtGlobalFlag 保持 0（反调试探测会看到"没有调试器"）
    return (f"已铺 TEB@{teb:#x} / PEB@{peb:#x}（BeingDebugged=0），gs/fs 段基址已设置",
            peb, teb)


def run_function(img, addr: int, args: Sequence[int] = (),
                 max_ins: int = 200000, trace: bool = False,
                 stop_on_syscall: bool = True, snapshot: bool = True,
                 snap_limit: int = 4 << 20, stdin: bytes = b"",
                 argv: Optional[Sequence[str]] = None,
                 api: bool = True, tail_len: int = 24,
                 stop_at: Sequence[int] = (), coverage: bool = False,
                 pre_write: Sequence[Tuple[int, bytes]] = (),
                 api_setup=None) -> Dict[str, object]:
    """模拟执行 ``addr`` 处的函数（ELF x86-64 与 PE x86/x64 都支持）。

    * 按段/节铺内存（权限照抄），额外给一块栈；
    * 参数：x64 走 rdi/rsi/rdx/rcx/r8/r9（SysV）或 rcx/rdx/r8/r9（Win64，取决于格式）；
      x86 一律按 cdecl 压栈；
    * PE 的**导入表会被接管**：每个 API 的 IAT 槽改成一段桩，命中桩就由
      `winapi.ApiEmulator` 实现它的语义（`strcmp`/`memcmp`/`scanf`/`printf`/反调试探测…）——
      所以 Windows CrackMe 那种"读输入→比较→打印 Correct"的逻辑**不用运行程序就能判对错**；
    * 返回地址压一个假哨兵地址，跑到它就停下 → ``ret`` 是 eax/rax；
    * 命中未映射内存 / 指令数超限会停下并说明原因（**不静默继续**）；
    * ``snapshot=True`` 时做**前后内存差分**，报出"这个函数改写了哪块内存"
      （``changes``），并在其中自动标记"``0..n-1`` 的排列"（``tables``）——
      运行时生成的置换表 / S 盒 / 字符表都是这个特征。
    """
    try:
        from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32, UC_HOOK_CODE,
                             UC_HOOK_MEM_UNMAPPED, UC_HOOK_INSN)
        from unicorn import x86_const as xc
    except Exception as exc:                             # pragma: no cover
        raise EmuError(f"需要 unicorn（pip install unicorn）：{exc}")

    bits = int(getattr(img, "bits", 64))
    is_pe = hasattr(img, "image_base")
    if not is_pe and getattr(img, "machine", EM_X86_64) != EM_X86_64:
        raise EmuError("ELF 侧目前只支持 x86-64；PE 支持 x86/x64")
    if bits == 64:
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        rsp, rip, rax, rbp = (xc.UC_X86_REG_RSP, xc.UC_X86_REG_RIP,
                              xc.UC_X86_REG_RAX, xc.UC_X86_REG_RBP)
        arg_regs = [xc.UC_X86_REG_RCX, xc.UC_X86_REG_RDX, xc.UC_X86_REG_R8,
                    xc.UC_X86_REG_R9] if is_pe else \
                   [xc.UC_X86_REG_RDI, xc.UC_X86_REG_RSI, xc.UC_X86_REG_RDX,
                    xc.UC_X86_REG_RCX, xc.UC_X86_REG_R8, xc.UC_X86_REG_R9]
        word, sp_mask = 8, 0xFFFFFFFFFFFFFFFF
        stack_base, stack_top = 0x7FF00000, 0x7FF20000
        sentinel = 0x7FF00000
    else:
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        rsp, rip, rax, rbp = (xc.UC_X86_REG_ESP, xc.UC_X86_REG_EIP,
                              xc.UC_X86_REG_EAX, xc.UC_X86_REG_EBP)
        arg_regs = []
        word, sp_mask = 4, 0xFFFFFFFF
        stack_base, stack_top = 0x00010000, 0x00030000
        sentinel = 0x00010000

    page = 0x1000
    # PE 的头部（DOS/NT/节表）在真实加载器里也是映射进来的，而且**不属于任何节**。
    # 很多程序会 `GetModuleHandleA(NULL)` 之后去读自己的 MZ/PE 头（反调试、校验和、
    # 找资源都这么干），不铺这一段就会在 `cmp word [eax], 'MZ'` 处直接崩。
    if is_pe:
        header_size = 0x1000
        try:
            e_lfanew = struct.unpack_from("<I", img.blob, 0x3C)[0]
            header_size = max(0x400, e_lfanew + 0x200)
        except Exception:
            pass
        base = getattr(img, "image_base", 0x400000)
        start = base & ~(page - 1)
        end = (base + header_size + page - 1) & ~(page - 1)
        try:
            uc.mem_map(start, max(page, end - start))
            uc.mem_write(base, img.blob[:header_size])
        except Exception:
            pass
    for seg in img.segments:
        start = seg.vaddr & ~(page - 1)
        end = (seg.vaddr + _mem_size(seg) + page - 1) & ~(page - 1)
        if end <= start:
            continue
        # 先把"整块范围"映射出来（**按并集**：被壳改过的 PE 经常有重叠节，
        # 例如 cxk0 覆盖 SH_LYD，逐节 mem_map 会互相撞、后一个静默失败，
        # 结果后面的节只映射了一半，程序一访问就 UC_ERR_MAP）
        try:
            uc.mem_map(start, end - start)
        except Exception:
            pass                                          # 已被别的节覆盖：正常
        data = seg.data or b""
        if data:
            try:
                uc.mem_write(seg.vaddr, data)
            except Exception:
                # 跨节写入失败时，按页裁剪着写，尽量把能写的写进去
                for off in range(0, len(data), page):
                    chunk = data[off:off + page]
                    try:
                        uc.mem_write(seg.vaddr + off, chunk)
                    except Exception:
                        break
    uc.mem_map(stack_base, stack_top - stack_base)
    sp = stack_top - 0x800
    uc.reg_write(rsp, sp)
    uc.reg_write(rbp, sp)
    # **调用前预置内存**：直接调用某个函数（GUI 题的校验函数、keygen 用的辅助函数）时，
    # 往往要先把"全局输入缓冲/参数结构"摆好。没有这个能力就只能从程序入口跑，
    # 而 GUI 题从入口跑会卡在消息循环里（实测吾爱那批题全是这个情况）。
    for _addr, _data in (pre_write or ()):
        try:
            uc.mem_write(int(_addr), bytes(_data))
        except Exception:
            pass
    teb_note = ""
    peb_addr = 0
    if is_pe:
        teb_note, peb_addr, _teb_addr = _setup_teb(
            uc, bits, getattr(img, "image_base", 0x400000), stack_base, stack_top)

    api_emu = None
    # ⚠ 注意：**导入表为空也要建 ApiEmulator**。自解压壳会把导入表抹掉/运行时重建，
    # 这种程序恰恰最需要"假系统 DLL + PEB->Ldr 链表"才能跑起来。
    # 之前写成 `if api and img.imports:`，结果壳这类样本直接跳过了整套能力。
    if api and (getattr(img, "imports", None) is not None):
        from . import winapi
        stub_base = _free_region(img, 0x2000,
                                 (0x10000000, 0x20000000, 0x30000000, 0x50000000))
        api_emu = winapi.ApiEmulator(uc, img, stdin=stdin, argv=list(argv or []),
                                     time_source=0x1000)
        api_emu._stub_base = stub_base
        api_emu._stub_page = stub_base + 0x100000
        api_emu._heap_base = stub_base + 0x200000
        api_emu._heap_ptr = api_emu._heap_base + 0x1000
        if getattr(img, "imports", None):
            api_emu.map_stubs()
        # **自定义 API 行为**：GUI 题的取值 API（GetWindowTextA 等）在模拟环境里拿不到
        # 真实文本，宿主要能"替它写答案"——否则 `strlen<=5` 那种分支直接走错误路径，
        # 校验代码根本执行不到。回调收到 ApiEmulator，可以覆盖任意 _api_xxx 处理器。
        if api_setup is not None:
            try:
                api_setup(api_emu)
            except Exception:
                pass
        stub_lo, stub_hi = stub_base, stub_base + 0x2000
        # 造"假系统 DLL" + PEB->Ldr 链表：让**自己解析导出表**的壳/loader 也能跑
        # （它们走 fs:[0x18]→PEB→Ldr→找 kernel32→解析导出表这条路，
        #  只铺 TEB/PEB 不够，必须在链表里放几个"有真实导出表"的假模块）
        if is_pe and bits == 32:
            from . import fakedll
            try:
                modules = fakedll.install(uc, api_emu)
                # 注意：**不要把主模块放进链表头部**。真实加载器确实会把 EXE 也列进去，
                # 但实测这个自写壳是按"第一个条目"或"基址"取模块的，一旦第一个条目是
                # 主程序自己，它就去解析主程序的导出表（本来就没有）→ 拿到 NULL 崩在 14 条指令。
                # 保持"假系统 DLL 在前"的布局反而能让它顺着找下去（实测 35 万条指令）。
                fakedll.build_ldr(uc, list(modules.items()), peb_addr, api_emu._heap)
                teb_note += (f"；已铺假系统 DLL（{len(modules)} 个）"
                             f"与 PEB->Ldr 链表")
            except Exception as exc:
                teb_note += f"；假 DLL 铺设失败：{type(exc).__name__}: {exc}"
    else:
        stub_lo = stub_hi = -1

    if bits == 64:
        for reg, val in zip(arg_regs, args):
            uc.reg_write(reg, int(val) & sp_mask)
    else:
        # x86 cdecl：参数从右到左压栈，最后压返回地址
        for val in reversed([int(a) & 0xFFFFFFFF for a in args]):
            sp -= 4
            uc.mem_write(sp, struct.pack("<I", val))
        uc.reg_write(rsp, sp)
    sp = uc.reg_read(rsp)
    if bits == 64:
        sp -= 8
        uc.mem_write(sp, struct.pack("<Q", sentinel))
    else:
        sp -= 4
        uc.mem_write(sp, struct.pack("<I", sentinel))
    uc.reg_write(rsp, sp)
    uc.reg_write(rip, addr)
    before: Dict[int, bytes] = {}
    if snapshot:
        for lo, hi, _perm in uc.mem_regions():
            if hi - lo > snap_limit or lo >= stack_base:      # 跳过巨段和栈
                continue
            try:
                before[lo] = bytes(uc.mem_read(lo, hi - lo + 1))
            except Exception:
                pass

    state = {"ins": 0, "stop": "跑完指令上限", "done": False, "trace": [],
             "exit": None, "tail": collections.deque(maxlen=tail_len),
             "hit": None, "null_call": None}
    stop_set = {int(a) for a in (stop_at or ())}
    visited: Optional[set] = set() if coverage else None

    def on_code(uc_, address, size, _user):
        state["ins"] += 1
        state["tail"].append(address)
        if visited is not None:
            # 记录**真实执行过的地址**。这是对付"跳进指令中间"花指令的唯一可靠办法：
            # 线性反汇编会从函数头一路顺着解，永远碰不到那些"半路跳进来"的垃圾字节；
            # 而执行轨迹知道每一条真实指令的边界。
            visited.add(address)
        if stop_set and address in stop_set:
            # 断点：停在指定地址，方便把"比较现场"的参数/寄存器取出来
            state["hit"] = address
            state["stop"] = f"断点命中 0x{address:x}"
            state["done"] = True
            uc_.emu_stop()
            return
        if address < 0x1000:            # 执行流跑进了**低地址（我们为 32 位铺的 TEB 假页）**：
            # 这几乎一定是"调用了 NULL 函数指针"（GetProcAddress 没解析到、
            # 或者某个 API 返回 0 被当函数指针用了）。
            # ⚠ 必须**显式报错**：假页把地址 0 映射上了，不拦的话程序会在一片零字节里
            # 一路 `add [eax], al` 跑下去，最后报出 "UC_ERR_MAP 在 0x2f2f" 这种
            # 完全看不出原因的错误（实测两个不同题目都栽在这里，排查了很久）。
            prev = state["tail"][-2] if len(state["tail"]) > 1 else 0
            state["stop"] = (f"执行流进入低地址 0x{address:x}（TEB 假页）——"
                             f"疑似调用了 NULL 函数指针，调用点约 0x{prev:x}")
            state["null_call"] = prev
            state["done"] = True
            uc_.emu_stop()
            return
        if trace and len(state["trace"]) < 400:
            state["trace"].append(address)
        # `int 0x29`（Windows 的 __fastfail）：反调试常用的一招，会让模拟器报
        # "Unhandled CPU exception"。它本身就是"故意让进程异常死掉"，
        # 对逆向毫无信息量，所以这里**直接跳过这 2 个字节**继续跑，
        # 并把这件事记下来（否则会误以为是模拟器缺指令）。
        try:
            two = bytes(uc_.mem_read(address, 2))
        except Exception:
            two = b""
        if two == b"\xcd\x29":
            state.setdefault("skipped_fastfail", 0)
            state["skipped_fastfail"] += 1
            uc_.reg_write(rip, address + 2)
        if api_emu is not None and address in api_emu._stub_of:
            # 按"桩表"判断，而不是按某个地址范围：
            # 桩可能来自 IAT（0x10000000 附近）、GetProcAddress 动态分配、或**假系统 DLL 的导出表**
            # （0x71100000 起）。只认范围会漏掉后两种，执行就会跑进 NOP 区然后崩。
            try:
                api_emu.dispatch(address)
            except Exception as exc:                      # 含程序调用 exit()
                name = type(exc).__name__
                if name == "_ExitRequested":
                    state["exit"] = getattr(exc, "code", 0)
                    state["stop"] = f"程序主动退出（exit code {state['exit']}）"
                else:
                    state["stop"] = f"API 模拟异常：{exc}"
                state["done"] = True
                uc_.emu_stop()
            return
        if address == sentinel:
            state["stop"] = "函数返回"
            state["done"] = True
            uc_.emu_stop()
        elif state["ins"] > max_ins:
            state["stop"] = f"超过指令上限 {max_ins}"
            state["done"] = True
            uc_.emu_stop()

    def on_unmapped(uc_, _type, address, _size, _value, _user):
        state["stop"] = f"访问未映射内存 0x{address:x}"
        state["done"] = True
        uc_.emu_stop()
        return True

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)
    if stop_on_syscall and bits == 64 and not is_pe:
        def on_syscall(uc_, _user):
            state["stop"] = (f"遇到 syscall（rax={uc_.reg_read(rax)}）"
                             f"——需要自己 hook 掉或改成静态还原")
            state["done"] = True
            uc_.emu_stop()
        try:
            uc.hook_add(UC_HOOK_INSN, on_syscall, None, 1, 0, xc.UC_X86_INS_SYSCALL)
        except Exception:
            pass
    try:
        uc.emu_start(addr, sentinel, 0, max_ins + 16)
    except Exception as exc:
        # 崩溃时也把寄存器现场留下来 —— 光有 RIP 看不出"它在访问什么"，
        # 有寄存器就能立刻算出那条指令的目标地址。实测正是靠这个才发现
        # 壳的指针是循环后半段才变脏的（断点命中的第一次迭代一切正常）。
        fault_regs: Dict[str, int] = {}
        for name, long_ in (("eax", "RAX"), ("ebx", "RBX"), ("ecx", "RCX"),
                            ("edx", "RDX"), ("esi", "RSI"), ("edi", "RDI"),
                            ("esp", "RSP"), ("ebp", "RBP")):
            try:
                const = getattr(xc, f"UC_X86_REG_{name.upper()}" if bits == 32
                                else f"UC_X86_REG_{long_}")
                fault_regs[name] = uc.reg_read(const)
            except Exception:
                continue
        state["fault_regs"] = fault_regs
        try:
            where = uc.reg_read(rip)
            regs_text = " ".join(f"{k}=0x{v:x}" for k, v in fault_regs.items())
            state["stop"] = (f"模拟异常：{exc}（在 0x{where:x}，"
                             f"第 {state['ins']} 条指令"
                             + (f"；现场 {regs_text}" if regs_text else "") + "）")
        except Exception:
            state["stop"] = f"模拟异常：{exc}"
    # unicorn 在 PC == until 时"执行前"就停了，钩子不一定触发；
    # 所以这里补一次判断：IP 落在哨兵上（或栈指针比初始值高）就是 ret 回来了。
    ip = uc.reg_read(rip)
    if ip == sentinel or uc.reg_read(rsp) > stack_top - 0x800:
        if state["exit"] is None:
            state["stop"] = "函数返回"
        state["done"] = True
    ret_value = uc.reg_read(rax)
    # 断点命中时把常用寄存器一起返回 —— 抓"比较现场"就靠它
    reg_names = (("eax", "RAX"), ("ebx", "RBX"), ("ecx", "RCX"), ("edx", "RDX"),
                 ("esi", "RSI"), ("edi", "RDI"), ("esp", "RSP"), ("ebp", "RBP"))
    regs: Dict[str, int] = {}
    for short, long_ in reg_names:
        try:
            # 32 位寄存器名本身就是 EAX/EBX…，别再拼一个 E 上去（之前拼成 EEAX 全落空）
            const = getattr(xc, f"UC_X86_REG_{short.upper()}" if bits == 32
                            else f"UC_X86_REG_{long_}")
            regs[short] = uc.reg_read(const)
        except Exception:
            continue
    changes: List[Tuple[int, bytes]] = []
    tables: List[Tuple[int, int]] = []
    new_regions: List[Tuple[int, bytes]] = []
    if snapshot:
        # ① **运行期间新映射的内存**：脱壳/自解压的目标缓冲区几乎都是运行时
        #    `VirtualAlloc` 出来的，而 before 快照是在运行前拍的 —— 只比"老区域"
        #    会得出"内存改写 0 块"的错误结论（实测自写壳就是这样：跑了 11 万条指令
        #    却报告零改写）。所以这里把新区域也捞出来，作为"解出来的东西"。
        known = set(before)
        for lo, hi, _perm in uc.mem_regions():
            if lo in known or lo >= stack_base or lo < 0x1000:
                continue
            if api_emu is not None and (lo == api_emu._stub_base
                                        or lo == api_emu._heap_base):
                continue
            if lo == getattr(img, "image_base", 0):
                continue
            size = min(hi - lo + 1, snap_limit)
            try:
                data = bytes(uc.mem_read(lo, size))
            except Exception:
                continue
            if data.count(0) == len(data):            # 全零区域不算"解出来的东西"
                continue
            new_regions.append((lo, data))
            changes.append((lo, data))
        for lo, old in before.items():
            try:
                new = bytes(uc.mem_read(lo, len(old)))
            except Exception:
                continue
            if new == old:
                continue
            # 先找出"连续不同"的片段，再把间隔 ≤ 4 字节的片段合并
            # （洗牌表通常被少量没变的字节切碎，合并后才看得出它是整张表）
            runs: List[List[int]] = []
            i = 0
            while i < len(new):
                if i >= len(old) or new[i] != old[i]:
                    j = i
                    while j < len(new) and (j >= len(old) or new[j] != old[j]):
                        j += 1
                    if runs and i - runs[-1][1] <= 5:
                        runs[-1][1] = j
                    else:
                        runs.append([i, j])
                    i = j
                else:
                    i += 1
            for a, b in runs:
                if b - a >= 8:
                    changes.append((lo + a, new[a:b]))
        for at, blob in changes:
            if len(blob) > 8192:
                continue
            # 改写区间里可能同时有表、种子、填充，所以要在区间**内部**找窗口：
            # 只要存在一段长度 n 的窗口恰好是 0..n-1 的排列，就认为找到了表。
            for start in range(len(blob)):
                found = 0
                for n in range(8, len(blob) - start + 1):
                    window = blob[start:start + n]
                    if max(window) < n and len(set(window)) == n:
                        found = n
                if found:
                    tables.append((at + start, found))
    return {"ret": ret_value, "rax": ret_value, "ins": state["ins"],
            "stop": state["stop"], "trace": state["trace"], "_uc": uc,
            "changes": changes, "tables": tables, "exit": state["exit"],
            "new_regions": new_regions,
            "tail": list(state["tail"]), "hit": state["hit"], "regs": regs,
            "null_call": state.get("null_call"), "teb_note": teb_note,
            "coverage": visited if visited is not None else set(),
            "comparisons": list(api_emu.comparisons) if api_emu else [],
            "stdout": api_emu.stdout() if api_emu else "",
            "api_notes": api_emu.notes if api_emu else []}


#: 判断"哪里是校验函数"的线索字符串（逆向题里翻来覆去就这几个词）
CHECK_MARKERS = (b"Correct", b"correct", b"Wrong", b"wrong", b"Nope", b"nope",
                 b"Congratulations", b"congrat", b"Success", b"success",
                 b"Flag:", b"flag:", b"Key:", b"key:", b"Input", b"input:",
                 b"Password", b"password", b"Invalid", b"invalid",
                 "恭喜".encode(), "正确".encode(), "错误".encode(), "失败".encode(),
                 "请输入".encode(), "密码".encode(), "成功".encode())


def find_check_functions(img, markers: Sequence[bytes] = CHECK_MARKERS,
                         top: int = 8) -> List[Tuple[int, str, int]]:
    """在 PE/ELF 里猜"哪个函数是校验函数"，返回 ``[(函数入口, 依据, 命中数), …]``。

    依据排序（越靠前越硬）：

    1. **符号表**里有 ``main``/``check``/``verify``/``validate`` 这类名字；
    2. **异常目录（.pdata）**：把"引用了 Correct/Wrong/请输入 这类字符串的指令"
       回溯到它所属的函数（strip 过的 x64 PE 也照样能用）；
    3. 退而求其次：把那些字符串所在函数附近的入口当候选。

    为什么需要它：Windows 的 CRT 启动链（``mainCRTStartup`` → ``_initterm`` → ``main``）
    模拟起来很长，而逆向题真正想让你看的往往就是 ``main`` 里那段比较。
    直接定位到它、把输入喂进去，比硬啃 CRT 靠谱得多。
    """
    from . import pe as _pe
    scored: Dict[int, Tuple[str, int]] = {}
    # 1) 符号名
    names = getattr(img, "symbols", {}) or {}
    for name, addr in names.items():
        low = name.lower()
        if any(k in low for k in ("check", "verify", "validate", "main",
                                  "flag", "crackme", "key")):
            if not any(skip in low for skip in ("_init", "crt", "frame_dummy",
                                                "__libc", "register_tm")):
                scored[addr] = (f"符号名 {name}", 6)
    for name, addr in getattr(img, "exports", []) or []:
        low = name.lower()
        if any(k in low for k in ("check", "verify", "validate", "main")):
            scored.setdefault(addr, (f"导出表 {name}", 6))
    # 2) 字符串引用 → 所属函数
    xref_fn = None
    if hasattr(img, "function_of"):
        xref_fn = img.function_of
    for marker in markers:
        if hasattr(img, "executable_ranges"):
            hits = _pe.string_xrefs(img, marker)
        else:
            hits = xrefs(img, marker)
        for at in hits:
            fn = xref_fn(at) if xref_fn else None
            if fn is None:
                continue
            entry = fn[0]
            old = scored.get(entry)
            if old is None:
                scored[entry] = (f"引用了 {marker.decode('latin-1', 'replace')!r}",
                                 3)
            else:
                scored[entry] = (old[0], old[1] + 3)
    out = [(addr, why, weight) for addr, (why, weight) in scored.items()]
    out.sort(key=lambda item: (-item[2], item[0]))
    return out[:top]


def guess_expected_input(comparisons, stdin: bytes = b"") -> List[str]:
    """从抓到的比较参数里，猜"程序到底期望什么输入"。

    逻辑很朴素但极有效：一次 ``strcmp(a, b)`` 里，如果一边是我们喂进去的输入
    （或它的前缀），**另一边就是程序期望的值**——很多 CrackMe 的序列号/密码
    就是这样直接摆在比较参数上的。返回去重后的候选字符串列表。
    """
    fed = (stdin or b"").split(b"\n")[0].strip()
    out: List[str] = []
    for api, a, b in comparisons:
        for x, y in ((a, b), (b, a)):
            if not y:
                continue
            printable = all(32 <= c < 127 for c in y)
            if not printable or len(y) < 3:
                continue
            if fed and (x == fed or x.startswith(fed) or fed.startswith(x[:len(fed)])
                        or x[:4] == fed[:4]):
                text = y.decode("latin-1")
                if text not in out:
                    out.append(text)
            elif not fed:
                text = y.decode("latin-1")
                if text not in out:
                    out.append(text)
    return out[:12]


def trace_blocks(coverage: Iterable[int], gap: int = 24
                 ) -> List[Tuple[int, int]]:
    """把"执行过的地址集合"合并成连续块，返回 ``[(起, 止), …]``。

    ``gap``：地址间隔小于它就算同一块（跳转/分支会造成小空洞，没必要切碎）。
    """
    addrs = sorted(coverage)
    if not addrs:
        return []
    blocks: List[List[int]] = [[addrs[0], addrs[0]]]
    for a in addrs[1:]:
        if a - blocks[-1][1] <= gap:
            blocks[-1][1] = a
        else:
            blocks.append([a, a])
    return [(lo, hi) for lo, hi in blocks]


def trace_disasm(img, coverage: Iterable[int], limit: int = 4000,
                 gap: int = 24) -> List[Tuple[int, str, str]]:
    """**按真实执行边界**反汇编：返回 ``[(地址, 助记符, 操作数), …]``。

    和"线性反汇编"的区别：每个块都从**真正被执行过的首地址**开始解码，
    所以"跳进指令中间"的花指令不会把后面全带偏——这正是看雪第七题那类
    自写壳能挡住普通反汇编的原因。
    """
    import capstone
    mode = capstone.CS_MODE_64 if int(getattr(img, "bits", 64)) == 64 \
        else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    out: List[Tuple[int, str, str]] = []
    for lo, hi in trace_blocks(coverage, gap=gap):
        for sec in img.segments:
            if sec.vaddr <= lo < sec.vaddr + len(sec.data or b""):
                data = sec.data[lo - sec.vaddr:hi - sec.vaddr + 16]
                for ins in md.disasm(data, lo):
                    if ins.address > hi:
                        break
                    out.append((ins.address, ins.mnemonic, ins.op_str))
                    if len(out) >= limit:
                        return out
                break
    return out


def run_main(blob: bytes, stdin: bytes = b"", max_ins: int = 2000000,
             argv: Sequence[str] = (), addr: int = 0, locate: str = "auto",
             stop_at: Sequence[int] = (), coverage: bool = False
             ) -> Dict[str, object]:
    """**把题目程序自己跑起来**，喂一段输入，看它输出什么。

    这是逆向题最硬的证据形式：不看代码怎么写的，直接问程序"这个输入对不对"。
    返回 ``{'stdout', 'exit', 'result', 'entry_used', 'entry_why', ...}``，
    其中 ``result`` 是判定结果：

    * ``True``  —— 输出里出现明显的成功字样（Correct/OK/Success/恭喜/正确/通过…）；
    * ``False`` —— 出现失败字样（Wrong/Nope/Error/失败/错误…）；
    * ``None``  —— 没看出明确的成败字样（那就要看 stdout 自己判断）。

    入口怎么选（``locate``）：

    * ``symbol`` —— 用符号表里的 ``main``/``check`` 这类名字（最稳）；
    * ``auto``   —— 先符号，再"引用 Correct/Wrong/请输入 的函数"（x64 PE 用 .pdata
      回溯函数边界），最后才退回 CRT 入口；
    * ``entry``  —— 直接用 PE/ELF 的入口点（CRT 依赖重的程序容易在初始化阶段崩）。
    """
    img = load_image(blob)
    entry, why = addr, "命令行指定" if addr else ""
    if not entry:
        candidates = []
        if locate in ("auto", "symbol"):
            candidates = find_check_functions(img)
        if len(candidates) > 1:
            # **短模拟比选**：光看"引用了 Correct/错误 字样"常常选出错的入口
            # （实测吾爱 2022 春节之二：权重并列的两个候选里，选中那个跑 223 条就返回，
            #  真正的 main 在旁边——两个候选都引用了成败字样，静态权重分不出来）。
            # 办法很直接：各跑一小段，谁跑得远/谁有输出，谁就是真入口。
            best = None
            for cand_addr, cand_why, _w in candidates[:3]:
                try:
                    probe = run_function(img, cand_addr,
                                         max_ins=min(20000, max_ins),
                                         stdin=stdin, argv=list(argv),
                                         snapshot=False, stop_on_syscall=False)
                except Exception:
                    continue
                score = (1 if probe.get("stdout") else 0, int(probe.get("ins") or 0))
                if best is None or score > best[0]:
                    best = (score, cand_addr, cand_why)
            if best:
                entry, why = best[1], best[2] + "（短模拟比选：跑得最远/有输出）"
        elif candidates:
            entry, why, _weight = candidates[0]
        if not entry:
            entry, why = img.entry, "程序入口（CRT 启动链）"
    res = run_function(img, entry, max_ins=max_ins, stdin=stdin, argv=list(argv),
                       snapshot=False, stop_on_syscall=False, stop_at=stop_at,
                       coverage=coverage)
    text = str(res.get("stdout") or "")
    lower = text.lower()
    success = any(k in lower for k in
                  ("correct", "right", "success", "congrat", "yes!", "ok!", "you win",
                   "恭喜", "正确", "通过", "成功"))
    failure = any(k in lower for k in
                  ("wrong", "nope", "incorrect", "error", "failed", "fail",
                   "错误", "失败", "不正确"))
    result = True if (success and not failure) else \
             False if (failure and not success) else None
    return {"image": img, "stdout": text, "exit": res.get("exit"),
            "stop": res.get("stop"), "ins": res.get("ins"), "ret": res.get("ret"),
            "api_notes": res.get("api_notes") or [], "result": result,
            "entry_used": entry, "entry_why": why,
            "hit": res.get("hit"), "regs": res.get("regs") or {},
            "coverage": res.get("coverage") or set(),
            "fault_regs": res.get("fault_regs") or {},
            "comparisons": res.get("comparisons") or [],
            "expected": guess_expected_input(res.get("comparisons") or [], stdin),
            "raw": res}



def find_permutation(uc, addr: int, size: int, n: Optional[int] = None,
                     limit: int = 1 << 20) -> List[Tuple[int, int]]:
    """在刚跑完的内存里找**置换表**：一段 ``0..n-1`` 各出现一次的字节。

    这类"运行时生成的表"是 CTF 逆向的常客（洗牌、S 盒、字符表）。
    不需要知道它在哪：扫一遍可写内存，凡是满足"恰好是 0..n-1 的排列"的窗口
    都报出来（返回 ``[(地址, n), …]``）。``n`` 给定时只找该长度。
    """
    hits: List[Tuple[int, int]] = []
    sizes = [n] if n else list(range(16, 257))
    for size_n in sizes:
        try:
            buf = bytes(uc.mem_read(addr, limit))
        except Exception:
            return hits
        need = size_n
        want = set(range(need))
        for i in range(0, len(buf) - need + 1):
            window = buf[i:i + need]
            if len(set(window)) == need and max(window) < need:
                if set(window) == want:
                    hits.append((addr + i, need))
                    if len(hits) > 64:
                        return hits
    return hits


def read_mem(img: ElfImage, addr: int, size: int,
             uc=None) -> bytes:
    """读回模拟执行后的内存（例如 .bss 里刚生成的置换表）。

    没有现成的 ``uc`` 时，退回"直接读文件里的段"（静态数据也能这么读）。
    """
    if uc is not None:
        try:
            return bytes(uc.mem_read(addr, size))
        except Exception:
            pass
    for seg in img.segments:
        if seg.vaddr <= addr < seg.vaddr + seg.filesz:
            off = addr - seg.vaddr
            return seg.data[off:off + size]
    return b""


def immediates(img: ElfImage, addr: int, count: int = 64,
               length: int = 4000) -> List[int]:
    """从一个函数的机器码里扫出**立即数常量**（mov/lea/add/sub/cmp 后面那些）。

    用途：**"常量被改过的密码算法"**（R05 那种）——标准 delta 搜不到，
    但轮函数的立即数里一定躺着改过的值。这里把候选捞出来，具体哪个是 delta
    由调用方（或人）对着算法结构确认。

    优先用 capstone 按真实指令边界取（没有 capstone 时退回字节扫描，
    会混进一些误读，但至少不会漏）。
    """
    data = b""
    for seg in img.segments:
        if seg.vaddr <= addr < seg.vaddr + seg.filesz:
            data = seg.data[addr - seg.vaddr:addr - seg.vaddr + length]
            break
    if not data:
        return []
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        out: List[int] = []
        seen = set()
        for ins in md.disasm(data, addr):
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    val = int(op.imm) & 0xFFFFFFFFFFFFFFFF
                    if val and val not in seen:
                        seen.add(val)
                        out.append(val)
            if len(out) >= count:
                break
        return out[:count]
    except Exception:
        pass
    out = []
    i = 0
    while i < len(data) - 10:
        if data[i] in (0x48, 0x49, 0x4C, 0x4D) and data[i + 1] == 0xB8:
            out.append(struct.unpack_from("<Q", data, i + 2)[0])
            i += 10
            continue
        if data[i] in (0xB8, 0xB9, 0xBA, 0xBB, 0xBE, 0xBF):
            out.append(struct.unpack_from("<I", data, i + 1)[0])
            i += 5
            continue
        i += 1
        if len(out) >= count:
            break
    return out[:count]


def report(blob: bytes, anchors: Sequence[bytes] = ()) -> str:
    """给一个 ELF 做"模拟执行取证"前的侦察报告（CLI ``emu --info`` 用）。"""
    img = ElfImage.parse(blob)
    lines = [img.describe()]
    for anchor in anchors:
        hits = xrefs(img, anchor)
        where = "，".join(f"0x{h:x}" for h in hits[:6]) or "没找到"
        lines.append(f"  锚点 {anchor!r} → 引用点 {where}")
    bss = img.bss_hint()
    if bss:
        lines.append(f"  提示：想取运行时的表，就用 "
                     f"`emu <file> --call <函数地址> --dump 0x{bss[0]:x}:64`")
    return "\n".join(lines)
