"""PE(Windows) 文件解析：只做逆向要用到的部分，不依赖 pefile。

为什么要自己写：吾爱破解/看雪上的 CrackMe 绝大多数是 Windows PE，而本工具原先只有
ELF 的模拟执行能力。要让"一条龙"能吃这些题，第一件事就是**把 PE 的地图读出来**：
镜像基址、每个节的地址/大小/权限、入口、导入表（IAT 里每一项对应哪个 API）。

设计上刻意和 `emu.ElfImage` 保持同样的字段名（``segments`` / ``entry`` / ``machine`` /
``bits`` / ``writable_regions()`` / ``bss_hint()``），这样模拟执行那一套代码可以同时吃
ELF 和 PE，不用为两种格式各写一遍。

几个容易踩的点（都在代码里处理了）：

* ``VirtualAddress`` 是 **RVA**，真地址要加 ``ImageBase``；
* 节的 ``VirtualSize`` 和 ``SizeOfRawData`` 经常不等：前者是内存里的大小（可能大于
  文件里的数据，尾部要补零），后者是文件里的字节数；
* 节在内存里的对齐是 ``SectionAlignment``（通常 0x1000），文件里是 ``FileAlignment``
  （通常 0x200），所以 RVA → 文件偏移必须按节换算，不能直接减；
* 导入表用 ``FirstThunk`` 作为 IAT 的地址，而 ``OriginalFirstThunk`` 指向名字表——
  有些加壳/改过的 PE 会把前者抹掉，这时要退回用后者。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_FILE_DLL = 0x2000

SUBSYSTEM = {2: "GUI", 3: "控制台", 9: "Windows CE", 10: "EFI"}

#: 常见节的默认权限（真实权限来自节 Characteristics，这里只是兜底）
_CHAR_EXECUTE, _CHAR_READ, _CHAR_WRITE = 0x20000000, 0x40000000, 0x80000000


@dataclass
class Section:
    name: str
    vaddr: int                 # 已加 ImageBase 的虚拟地址
    vsize: int
    raw_size: int
    raw_ptr: int
    characteristics: int
    data: bytes = b""

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & _CHAR_EXECUTE) or \
            bool(self.characteristics & 0x00000020)         # CODE

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & _CHAR_WRITE) or \
            bool(self.characteristics & 0x80000000)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & _CHAR_READ) or \
            bool(self.characteristics & 0x40000000)

    def flags(self) -> int:
        f = 0
        if self.readable:
            f |= 4
        if self.writable:
            f |= 2
        if self.executable:
            f |= 1
        return f

    def describe(self) -> str:
        perm = "".join(c if self.flags() & b else "-"
                       for c, b in (("R", 4), ("W", 2), ("X", 1)))
        return (f"{self.name:<8} vaddr=0x{self.vaddr:x} vsize=0x{self.vsize:x} "
                f"raw=0x{self.raw_size:x}@{self.raw_ptr:#x} {perm}")


@dataclass
class Import:
    dll: str
    name: str                  # 序号导入时形如 "#123"
    iat: int                   # IAT 槽的虚拟地址（模拟执行时往这里写桩地址）
    ordinal: Optional[int] = None

    def __str__(self) -> str:
        return f"{self.dll}!{self.name}"


@dataclass
class PeImage:
    """和 ElfImage 保持同构的最小 PE 视图。"""

    blob: bytes
    bits: int = 64
    machine: int = IMAGE_FILE_MACHINE_AMD64
    is_dll: bool = False
    image_base: int = 0
    entry_rva: int = 0
    size_of_image: int = 0
    subsystem: int = 3
    sections: List[Section] = field(default_factory=list)
    imports: List[Import] = field(default_factory=list)
    exports: List[Tuple[str, int]] = field(default_factory=list)
    symbols: Dict[str, int] = field(default_factory=dict)     # 名字 → 虚拟地址
    functions: List[Tuple[int, int, str]] = field(default_factory=list)
    is_dotnet: bool = False
    dotnet_version: str = ""
    is_packed_hint: str = ""

    #: 供 emu 使用的别名（与 ElfImage 一致）
    @property
    def entry(self) -> int:
        return self.image_base + self.entry_rva

    @property
    def segments(self) -> List[Section]:
        return self.sections

    @property
    def base(self) -> int:
        return self.image_base

    # ------------------------------------------------------------ 解析
    @classmethod
    def parse(cls, blob: bytes) -> "PeImage":
        if len(blob) < 0x40 or blob[:2] != b"MZ":
            raise ValueError("不是 PE 文件（缺 MZ 头）")
        e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
        if e_lfanew + 24 > len(blob) or blob[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("不是 PE 文件（缺 PE 签名）")
        coff = e_lfanew + 4
        machine, nsections, _ts, ptr_sym, n_sym, opt_size, chars = \
            struct.unpack_from("<HHIIIHH", blob, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", blob, opt)[0]
        if magic not in (0x10B, 0x20B):
            raise ValueError(f"未知可选头 magic 0x{magic:x}")
        bits = 64 if magic == 0x20B else 32
        img = cls(blob=blob, bits=bits, machine=machine,
                  is_dll=bool(chars & IMAGE_FILE_DLL))
        if bits == 64:
            img.image_base = struct.unpack_from("<Q", blob, opt + 24)[0]
            dd_off = opt + 112
        else:
            img.image_base = struct.unpack_from("<I", blob, opt + 28)[0]
            dd_off = opt + 96
        img.entry_rva = struct.unpack_from("<I", blob, opt + 16)[0]
        img.size_of_image = struct.unpack_from("<I", blob, opt + 56)[0]
        img.subsystem = struct.unpack_from("<H", blob, opt + 68)[0]
        num_dd = struct.unpack_from("<I", blob, dd_off - 4)[0]
        dirs: List[Tuple[int, int]] = []
        for i in range(min(16, num_dd)):
            rva, size = struct.unpack_from("<II", blob, dd_off + i * 8)
            dirs.append((rva, size))

        sec_off = opt + opt_size
        for i in range(nsections):
            off = sec_off + i * 40
            if off + 40 > len(blob):
                break
            raw_name, vsize, vaddr, raw_size, raw_ptr, *_rest, characteristics = \
                struct.unpack_from("<8sIIIIIIHHI", blob, off)
            name = raw_name.split(b"\x00", 1)[0].decode("latin-1", "replace")
            # 长节名（MinGW/GCC 常见）：名字写成 "/N"，真正的名字在字符串表偏移 N 处
            if name.startswith("/") and name[1:].isdigit() and ptr_sym and n_sym:
                strtab = ptr_sym + n_sym * 18
                at = strtab + int(name[1:])
                if at < len(blob):
                    end = blob.find(b"\x00", at)
                    if end > at:
                        name = blob[at:end].decode("latin-1", "replace")
            data = blob[raw_ptr:raw_ptr + raw_size] if raw_size else b""
            img.sections.append(Section(
                name=name, vaddr=img.image_base + vaddr, vsize=vsize,
                raw_size=raw_size, raw_ptr=raw_ptr,
                characteristics=characteristics, data=data))

        # 导入表：DataDirectory[1]
        if len(dirs) > 1 and dirs[1][0]:
            img.imports = cls._parse_imports(img, blob, dirs[1][0])
        # 导出表：DataDirectory[0]（有些题把校验函数导出，或需要靠它定位）
        if dirs and dirs[0][0]:
            img.exports = cls._parse_exports(img, blob, dirs[0][0])
        # COFF 符号表：MinGW 编译的 PE 经常保留它，里面有 main / check 这类名字。
        # 有符号就等于"白送一张函数地图"——比从入口一路模拟 CRT 靠谱得多。
        if ptr_sym and n_sym:
            img.symbols = cls._parse_coff_symbols(img, blob, ptr_sym, n_sym)
        # 异常目录（.pdata）：x64 PE 里**每个函数的起止地址**都在这儿。
        # 就算符号被 strip 了，靠它也能把"某条指令属于哪个函数"算出来——
        # 这是从"引用 Correct 字符串的指令"回溯到"校验函数入口"的关键。
        if len(dirs) > 3 and dirs[3][0] and bits == 64:
            img.functions = cls._parse_pdata(img, blob, dirs[3][0], dirs[3][1])
        # .NET（CLR）头：DataDirectory[14]。这类题的关键逻辑在 IL 里，
        # **模拟执行帮不上忙**（unicorn 不会跑 IL），只能靠反编译/读元数据，
        # 所以要在报告里明确说出来，免得用户对着"跑不起来"发呆。
        if len(dirs) > 14 and dirs[14][0]:
            img.is_dotnet = True
            off = cls._rva_to_off(img, dirs[14][0])
            if off is not None and off + 16 <= len(blob):
                _cb, major, minor = struct.unpack_from("<IHH", blob, off)
                img.dotnet_version = f"{major}.{minor}"
        img.is_packed_hint = cls._packed_hint(img)
        return img

    @classmethod
    def _parse_pdata(cls, img: "PeImage", blob: bytes, rva: int,
                     size: int) -> List[Tuple[int, int, str]]:
        """解析 x64 的 RUNTIME_FUNCTION 表 → ``[(起始, 结束, 名字), …]``。"""
        out: List[Tuple[int, int, str]] = []
        off = cls._rva_to_off(img, rva)
        if off is None:
            return out
        count = min(size // 12 if size else 4096, 200000)
        for i in range(count):
            ent = off + i * 12
            if ent + 12 > len(blob):
                break
            begin, end, _unwind = struct.unpack_from("<III", blob, ent)
            if begin == 0 and end == 0:
                break
            out.append((img.image_base + begin, img.image_base + end, ""))
        # 把 COFF 符号名补进去（有符号时白送名字）
        if img.symbols:
            by_addr = {}
            for name, addr in img.symbols.items():
                by_addr.setdefault(addr, name)
            named = []
            for begin, end, _n in out:
                named.append((begin, end, by_addr.get(begin, "")))
            out = named
        return out

    def function_of(self, addr: int) -> Optional[Tuple[int, int, str]]:
        """某条指令落在哪个函数里（靠 .pdata / 符号表；没有就返回 None）。"""
        for begin, end, name in self.functions:
            if begin <= addr < end:
                return (begin, end, name)
        # 退一步：把符号里"不超过该地址的最近一个"当函数起点
        best = None
        for name, sym in self.symbols.items():
            if sym <= addr and (best is None or sym > best[0]):
                best = (sym, name)
        if best:
            return (best[0], 0, best[1])
        # 32 位 PE 没有 .pdata，符号也常被 strip —— 用"函数序言 + 填充"启发式补上。
        # 这一步很关键：靠它才能从"引用了 Correct/请输入 那条指令"回溯到校验函数入口。
        # 64 位同样需要它：`function_of` 前面那两条都失败时（没有 .pdata、没有符号，
        # 例如自己用汇编器拼出来的 PE），没有它 `candidate_entries` 会一个候选都找不到。
        start = self.guess_function_start(addr)
        if start is not None:
            return (start, 0, "")
        return None

    def guess_function_start(self, addr: int, max_back: int = 0x1000,
                             ) -> Optional[int]:
        """函数起点推断（32/64 位通用）。

        PE 里"某条指令属于哪个函数"本来靠 ``.pdata``（x64）或符号表；两者都没有时
        只能自己猜。三条线索按优先级：

        1. 标准序言：x86 ``55 8B EC``（``push ebp; mov ebp,esp``）；
           x64 ``48 83 EC``（``sub rsp,imm8``）/ ``48 8B C4``（``mov rax,rsp``）/
           ``40 55``（``push rbp``，REX 前缀的 push）；
        2. MSVC 开 /Oy（省帧指针）后带 SEH 的 x86 开头 ``6A xx 68``；
        3. **16 字节对齐 + 前面是填充**（0xCC / 0x90 / 0x00）——编译器按 16 字节对齐
           函数并在缝隙里塞 ``int3``/``nop``，所以"填充块之后的第一个对齐地址"
           通常就是函数头。这条对 32/64 位都成立，是最兜底的线索。
        """
        for sec in self.sections:
            if not (sec.vaddr <= addr < sec.vaddr + len(sec.data)):
                continue
            data = sec.data
            off = addr - sec.vaddr
            lo = max(0, off - max_back)
            # 线索 3：往前找**连续 ≥3 字节**的填充块（0xCC/0x90），取其后 16 字节对齐的位置。
            # ⚠ 这里**不能把 0x00 当填充**：指令里的立即数经常带 0x00
            # （例如 x64 的 `movabs reg, imm64`），一旦把它当填充，就会把函数头
            # 猜成函数中间的某个对齐地址——实测这会让"从 Correct 那句开始跑"，
            # 结果喂什么输入都输出 Correct（自检里立刻抓到了这个回归）。
            # ⚠ 两个循环都要用 `lo - 1` 作为终点：`range(off-1, lo, -1)` **取不到 lo 本身**，
            # 于是"函数起点正好落在节首（偏移 0）"的情况永远找不出来
            # （实测自检里那个 x64 合成 PE 的函数就在 .text+0，一直返回 None）。
            best_aligned = None
            for i in range(off - 1, lo - 1, -1):
                if data[i] in (0xCC, 0x90):
                    run = 0
                    j = i
                    while j >= lo and data[j] in (0xCC, 0x90):
                        run += 1
                        j -= 1
                    if run >= 3:
                        cand = sec.vaddr + j + 1
                        aligned = (cand + 15) & ~15
                        if aligned <= addr:
                            best_aligned = aligned
                        break
            # 线索 1/2：从近到远找序言
            for i in range(off - 1, lo - 1, -1):
                if data[i:i + 3] == b"\x55\x8b\xec":            # push ebp; mov ebp,esp
                    return sec.vaddr + i
                if data[i:i + 3] == b"\x48\x83\xec":            # x64 sub rsp, imm8
                    return sec.vaddr + i
                if data[i:i + 3] == b"\x48\x8b\xc4":            # x64 mov rax, rsp
                    return sec.vaddr + i
                if data[i:i + 2] == b"\x40\x55":                # x64 push rbp
                    return sec.vaddr + i
                if data[i] == 0x6A and i + 3 < len(data) and data[i + 2] == 0x68:
                    return sec.vaddr + i
            return best_aligned
        return None

    @classmethod
    def _parse_coff_symbols(cls, img: "PeImage", blob: bytes,
                            ptr_sym: int, n_sym: int) -> Dict[str, int]:
        """解析 COFF 符号表 → ``{函数名: 虚拟地址}``（只收函数类型的符号）。"""
        out: Dict[str, int] = {}
        strtab_off = ptr_sym + n_sym * 18
        if strtab_off + 4 > len(blob):
            return out
        for i in range(min(n_sym, 100000)):
            off = ptr_sym + i * 18
            if off + 18 > len(blob):
                break
            raw, value, sec_num, stype, _storage, _naux = \
                struct.unpack_from("<8sIhHBB", blob, off)
            if sec_num <= 0 or stype & 0x20 == 0:          # 只要"函数"且在某节里
                continue
            if raw[:4] == b"\x00\x00\x00\x00":             # 名字在字符串表里
                name_off = struct.unpack_from("<I", raw, 4)[0]
                start = strtab_off + name_off
                if start >= len(blob):
                    continue
                end = blob.find(b"\x00", start)
                name = blob[start:end].decode("latin-1", "replace")
            else:
                name = raw.split(b"\x00", 1)[0].decode("latin-1", "replace")
            if not name or name.startswith("."):
                continue
            if sec_num - 1 < len(img.sections):
                base = img.sections[sec_num - 1].vaddr
                out.setdefault(name, base + value)
        return out

    @staticmethod
    def _rva_to_off(img: "PeImage", rva: int) -> Optional[int]:
        for sec in img.sections:
            start = sec.vaddr - img.image_base
            if start <= rva < start + max(sec.vsize, sec.raw_size):
                return sec.raw_ptr + (rva - start)
        return rva if rva < len(img.blob) else None

    @classmethod
    def _parse_imports(cls, img: "PeImage", blob: bytes, rva: int) -> List[Import]:
        out: List[Import] = []
        ptr = 8 if img.bits == 64 else 4
        base_off = cls._rva_to_off(img, rva)
        if base_off is None:
            return out
        for i in range(512):                    # 描述符数组，以全 0 结束
            off = base_off + i * 20
            if off + 20 > len(blob):
                break
            oft, _ts, _fc, name_rva, first_thunk = struct.unpack_from("<IIIII", blob, off)
            if not (oft or name_rva or first_thunk):
                break
            name_off = cls._rva_to_off(img, name_rva)
            dll = ""
            if name_off is not None:
                end = blob.find(b"\x00", name_off)
                dll = blob[name_off:end].decode("latin-1", "replace")
            thunk_rva = oft or first_thunk
            iat_rva = first_thunk
            thunk_off = cls._rva_to_off(img, thunk_rva)
            if thunk_off is None:
                continue
            for j in range(4096):
                toff = thunk_off + j * ptr
                if toff + ptr > len(blob):
                    break
                value = struct.unpack_from("<Q" if ptr == 8 else "<I", blob, toff)[0]
                if value == 0:
                    break
                high = 1 << (63 if ptr == 8 else 31)
                iat = img.image_base + iat_rva + j * ptr
                if value & high:
                    ordinal = value & 0xFFFF
                    out.append(Import(dll=dll, name=f"#{ordinal}", iat=iat,
                                      ordinal=ordinal))
                else:
                    hint_off = cls._rva_to_off(img, value & 0x7FFFFFFF)
                    fname = ""
                    if hint_off is not None:
                        end = blob.find(b"\x00", hint_off + 2)
                        fname = blob[hint_off + 2:end].decode("latin-1", "replace")
                    out.append(Import(dll=dll, name=fname or f"?0x{value:x}", iat=iat))
        return out

    @classmethod
    def _parse_exports(cls, img: "PeImage", blob: bytes, rva: int) -> List[Tuple[str, int]]:
        off = cls._rva_to_off(img, rva)
        out: List[Tuple[str, int]] = []
        if off is None or off + 40 > len(blob):
            return out
        # ⚠ 这里必须用**真实结构布局**：Characteristics/TimeDateStamp 是 4 字节，
        # MajorVersion/MinorVersion 是 **2 字节**，其余才是 4 字节。
        # 早先写成全 4 字节（"<IIIIIIIIIII"），字段会整体错位——Name 被当成 Base、
        # NumberOfNames 被当成 AddressOfFunctions……结果 exports 永远是空的。
        # （这个 bug 是"自己造 PE 喂给自己的解析器"时才暴露出来的，真实 PE 上不易察觉）
        (_, _, _, _, name_rva, base, nfunc, nname, funcs_rva, names_rva, ords_rva) = \
            struct.unpack_from("<IIHHIIIIIII", blob, off)
        funcs_off = cls._rva_to_off(img, funcs_rva)
        names_off = cls._rva_to_off(img, names_rva)
        ords_off = cls._rva_to_off(img, ords_rva)
        if funcs_off is None or names_off is None or ords_off is None:
            return out
        for i in range(min(nname, 4096)):
            try:
                n_rva = struct.unpack_from("<I", blob, names_off + i * 4)[0]
                ordinal = struct.unpack_from("<H", blob, ords_off + i * 2)[0]
                f_rva = struct.unpack_from("<I", blob, funcs_off + ordinal * 4)[0]
            except struct.error:
                break
            n_off = cls._rva_to_off(img, n_rva)
            if n_off is None:
                continue
            end = blob.find(b"\x00", n_off)
            name = blob[n_off:end].decode("latin-1", "replace")
            out.append((name, img.image_base + f_rva))
        return out

    @staticmethod
    def _packed_hint(img: "PeImage") -> str:
        """给一个"可能加壳/被打包"的提示（只做最粗的判断，详情交给签名模块）。"""
        names = {s.name.lower() for s in img.sections}
        for sig, what in (("upx0", "UPX"), ("upx1", "UPX"), (".themida", "Themida"),
                          (".vmp0", "VMProtect"), (".vmp1", "VMProtect"),
                          (".aspack", "ASPack"), (".mpress1", "MPRESS"),
                          ("enigma1", "Enigma"), (".petite", "Petite"),
                          (".nsp0", "NsPack"), (".boom", "Themida/Boom")):
            if sig in names:
                return what
        if not img.imports:
            return "无导入表（可能被壳抹掉/或被保护）"
        return ""

    # ------------------------------------------------------------ 查询
    def writable_regions(self) -> List[Section]:
        return [s for s in self.sections if s.writable]

    def bss_hint(self) -> Optional[Tuple[int, int]]:
        for sec in self.sections:
            if sec.name.lower() in (".bss", ".data"):
                return sec.vaddr, max(sec.vsize, sec.raw_size)
        for sec in self.sections:
            if sec.writable:
                return sec.vaddr, max(sec.vsize, sec.raw_size)
        return None

    def executable_ranges(self) -> List[Tuple[int, int]]:
        return [(s.vaddr, s.vaddr + max(s.vsize, s.raw_size))
                for s in self.sections if s.executable]

    def import_by_iat(self) -> Dict[int, Import]:
        return {imp.iat: imp for imp in self.imports}

    def describe(self) -> str:
        arch = {IMAGE_FILE_MACHINE_I386: "x86(32)", IMAGE_FILE_MACHINE_AMD64: "x64",
                IMAGE_FILE_MACHINE_ARM64: "arm64"}.get(self.machine,
                                                       f"machine=0x{self.machine:x}")
        kind = "DLL" if self.is_dll else "EXE"
        sub = SUBSYSTEM.get(self.subsystem, f"subsystem={self.subsystem}")
        lines = [f"PE {self.bits} 位 {arch} {kind} {sub} "
                 f"ImageBase=0x{self.image_base:x} entry=0x{self.entry:x} "
                 f"SizeOfImage=0x{self.size_of_image:x}",
                 f"  节 {len(self.sections)} 个："]
        if self.is_dotnet:
            lines.append(f"  ⚠ 这是 **.NET 程序**（CLR 头 v{self.dotnet_version or '?'}）："
                         f"校验逻辑在 IL 里，**模拟执行帮不上忙**——用 dnSpy/ILSpy 反编译；"
                         f"本工具仍能帮你扫字符串、加解密常量")
        for sec in self.sections[:16]:
            lines.append("    " + sec.describe())
        if self.imports:
            dlls: Dict[str, int] = {}
            for imp in self.imports:
                dlls[imp.dll] = dlls.get(imp.dll, 0) + 1
            top = "，".join(f"{d}({n})" for d, n in
                           sorted(dlls.items(), key=lambda kv: -kv[1])[:6])
            lines.append(f"  导入 {len(self.imports)} 项，来自：{top}")
        if self.exports:
            lines.append(f"  导出 {len(self.exports)} 项："
                         + "，".join(f"{n}@0x{a:x}" for n, a in self.exports[:8]))
        if self.is_packed_hint:
            lines.append(f"  ⚠ 打包/保护特征：{self.is_packed_hint}")
        return "\n".join(lines)


# ---------------------------------------------------------------- 辅助

def find_bytes_in_image(img, needle: bytes) -> List[int]:
    """在节的原始数据里找字节，返回**虚拟地址**（PE/ELF 都能用）。"""
    out: List[int] = []
    for sec in img.segments:
        if not sec.data:
            continue
        start = 0
        while True:
            idx = sec.data.find(needle, start)
            if idx < 0:
                break
            out.append(sec.vaddr + idx)
            start = idx + 1
    return out


def string_xrefs(img, needle: bytes, window: int = 0x2000) -> List[int]:
    """找"引用了某个字符串"的代码地址——PE 上定位 main/校验函数最实用的招。

    x64 下字符串引用主要是两种：``lea reg, [rip+disp]``（RIP 相对）和
    ``mov reg, imm64``（编译器用 `movabs` 直接把 64 位绝对地址放进寄存器，
    自检里的合成 PE 就是这种）。x86 下是 ``push imm32`` / ``mov reg, imm32``。
    **三种都要覆盖**——只认 RIP 相对时，用 `movabs` 的 x64 程序会一个引用点都找不到
    （实测自检里"候选校验入口"这条就是因此失败的）。
    """
    hits: List[int] = []
    targets = find_bytes_in_image(img, needle)
    if not targets:
        return hits
    for target in targets:
        for sec in img.segments:
            if not sec.executable or not sec.data:
                continue
            data = sec.data
            if img.bits == 64:
                # ① RIP 相对：lea reg, [rip+disp32]（指令 7 字节，disp 在 +3）
                for idx in range(len(data) - 7):
                    disp = struct.unpack_from("<i", data, idx + 3)[0]
                    if sec.vaddr + idx + 7 + disp == target:
                        hits.append(sec.vaddr + idx)
                # ② 绝对 64 位：movabs reg, imm64 / mov [mem], imm64
                want64 = struct.pack("<Q", target)
                start = 0
                while True:
                    idx = data.find(want64, start)
                    if idx < 0:
                        break
                    hits.append(sec.vaddr + idx)
                    start = idx + 1
            else:
                want = struct.pack("<I", target)
                start = 0
                while True:
                    idx = data.find(want, start)
                    if idx < 0:
                        break
                    hits.append(sec.vaddr + idx)
                    start = idx + 1
    return sorted(set(hits))


def report(blob: bytes, anchors: Sequence[bytes] = ()) -> str:
    img = PeImage.parse(blob)
    lines = [img.describe()]
    for anchor in anchors:
        hits = string_xrefs(img, anchor)
        where = "，".join(f"0x{h:x}" for h in hits[:6]) or "没找到"
        lines.append(f"  锚点 {anchor!r} → 引用点 {where}")
    if img.imports:
        interesting = [i for i in img.imports if i.name in (
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "memcmp", "strcmp",
            "scanf", "scanf_s", "gets", "fgets", "ReadFile", "MessageBoxA")]
        if interesting:
            lines.append("  关键 API：" + "，".join(str(i) for i in interesting[:8]))
    return "\n".join(lines)
