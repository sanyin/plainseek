"""伪造系统 DLL：让"自己解析 API"的程序也能跑（壳、loader、shellcode 都靠这招）。

## 为什么必须要它

实测三道卡住的题（看雪第一题、看雪第七题的自写壳、吾爱 2022 春节之二）**同一个根因**：
它们不走导入表，而是

```
1. 读 fs:[0x18] 拿 TEB → [TEB+0x30] 拿 PEB → [PEB+0x0C] 拿 PEB_LDR_DATA
2. 顺着 InLoadOrderModuleList 遍历，按 BaseDllName 找到 "kernel32.dll"
3. 读出它的 DllBase，自己解析 PE 导出表，按名字取函数地址
4. call 那个地址
```

我原来只铺了 TEB/PEB（为了让 `fs:[x]` 不崩），但没有 **Ldr 链表**，第 2 步就走进垃圾内存 →
报 `UC_ERR_MAP`；就算把链表补上，第 3 步解析到的也是**空的导出表**，取不到函数地址。
Qiling、Speakeasy 这类模拟框架的答案就是：**造一个假的系统 DLL**——有正常的 PE 头、
有导出表、每个导出名指向一段"桩"。程序自己怎么解析都能拿到地址，而桩由宿主实现语义。

## 这个实现做了什么

* `build_fake_dll(name, exports)`：拼一个最小 PE32 镜像 —— DOS/NT 头 + 一个 RWX 节，
  节里放：每个导出函数 16 字节的桩区、导出目录（AddressOfFunctions/Names/NameOrdinals）、
  名字表、DLL 名。**名字表按字典序排好**（`GetProcAddress` 常做二分查找，乱序会取错）。
* `install(uc, api, names)`：把这些假 DLL 映射到固定基址，并把每个导出名的桩地址登记进
  `ApiEmulator._stub_of`，于是"程序自己解析出来的地址"落到桩上，也能被宿主接管。
* `build_ldr(uc, modules)`：铺 PEB_LDR_DATA + 三条链表（InLoadOrder / InMemoryOrder /
  InInitializationOrder），每个模块一个 ``LDR_DATA_TABLE_ENTRY``（含 ``DllBase``、
  ``BaseDllName``/``FullDllName`` 的 UNICODE_STRING）。壳按名字找 kernel32 就能找到。

基址选在 0x71000000 起（32 位）——刻意避开镜像常见的 0x400000、我的自留地 0x10000000
与栈 0x10000~0x30000。
"""

from __future__ import annotations

import struct
from typing import Dict, Iterable, List, Sequence, Tuple

#: 假 DLL 基址（32 位）。每个模块留 0x10000。
MODULE_BASES: Dict[str, int] = {
    "ntdll.dll": 0x71000000,
    "kernel32.dll": 0x71100000,
    "user32.dll": 0x71200000,
    "msvcrt.dll": 0x71300000,
    "advapi32.dll": 0x71400000,
    "gdi32.dll": 0x71500000,
    "shell32.dll": 0x71600000,
    "ole32.dll": 0x71700000,
    "comctl32.dll": 0x71800000,
    "ws2_32.dll": 0x71900000,
}
MODULE_SIZE = 0x10000
#: 实际映射的字节数。
#: **留余量 + 填满间隙是必要的**，实测两种情况都会踩：
#: ① 壳解析导出表时会顺着读过头（读到 base+0x10005，正好越过模块末尾就 UC_ERR_MAP）；
#: ② 有的壳会**从某个地址开始向上线性扫描内存**找 PE 头/特征，模块之间如果留了空洞，
#:    它扫进空洞就直接崩。模块基址彼此相距 0x100000，所以这里就映射满 0x100000，
#:    让"扫过一个模块"立刻落进下一个模块。
MAPPED_SIZE = 0x100000
_HEADERS = 0x400                     # 头部占一节之前的 0x400 字节
_STUB_SIZE = 16                      # 每个导出函数占 16 字节


def build_fake_dll(name: str, exports: Sequence[str],
                   base: int) -> Tuple[bytes, Dict[str, int]]:
    """拼一个能"被正常解析"的最小 PE32：返回 ``(镜像字节, {导出名: 桩地址})``。

    镜像布局：``[0x400, 0x400+len(exports)*16)`` 是桩区，桩后面依次放导出目录、
    名字表、序号表、DLL 名字。节只用一个 RWX 节，够用且省事。
    """
    exports = sorted(set(exports))                 # GetProcAddress 常做二分，必须有序
    stub_start = _HEADERS
    stubs = {n: base + stub_start + i * _STUB_SIZE
             for i, n in enumerate(exports)}
    image = bytearray(MODULE_SIZE)

    # ---- 桩区：全填 0x90（NOP），走到桩上会被宿主的代码钩子接住
    for addr in stubs.values():
        off = addr - base
        image[off:off + _STUB_SIZE] = b"\x90" * _STUB_SIZE

    # ---- 导出目录
    exp_off = stub_start + len(exports) * _STUB_SIZE
    funcs_off = exp_off + 40
    names_off = funcs_off + len(exports) * 4
    ords_off = names_off + len(exports) * 4
    dllname_off = ords_off + len(exports) * 2
    dllname = name.encode("ascii") + b"\x00"
    image[dllname_off:dllname_off + len(dllname)] = dllname
    name_rvas: List[int] = []
    cursor = (dllname_off + len(dllname) + 1) & ~1
    for n in exports:
        raw = n.encode("ascii") + b"\x00"
        image[cursor:cursor + len(raw)] = raw
        name_rvas.append(cursor)                 # 名字表里存的也是 RVA
        cursor += len(raw)
    # 导出目录里的所有字段**必须是 RVA（相对 ImageBase 的偏移）**，
    # 不能填 VA。第一版在这里填成了 base+off，壳按标准解析就跑到未映射区域去了
    # （表现为 240 条指令后 UC_ERR_MAP；教训：自造 PE 一定要用标准字段语义并反向验证）。
    for i, n in enumerate(exports):
        struct.pack_into("<I", image, funcs_off + i * 4, stubs[n] - base)
        struct.pack_into("<I", image, names_off + i * 4, name_rvas[i])
        struct.pack_into("<H", image, ords_off + i * 2, i)
    struct.pack_into("<IIHHIIIIIII", image, exp_off,
                     0, 0, 0, 0, dllname_off, 1, len(exports), len(exports),
                     funcs_off, names_off, ords_off)

    # ---- 头部（DOS + PE + 可选头 + 一个节的节表）
    # 布局要点：e_lfanew 指向 "PE\0\0"，**COFF 头在签名之后**。
    # （第一版把签名和 COFF 头写在同一个偏移，签名被覆盖，自己写的 PE 自己的解析器都读不了——
    #   所以这里写完一定要用 pe.PeImage.parse 反过来验一遍）
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    pe_off = 0x40
    image[pe_off:pe_off + 4] = b"PE\x00\x00"
    coff = pe_off + 4
    opt_size = 224
    opt = coff + 20
    struct.pack_into("<HHIIIHH", image, coff, 0x14C, 1, 0, 0, 0, opt_size, 0x2102)
    struct.pack_into("<H", image, opt, 0x10B)                    # PE32
    struct.pack_into("<I", image, opt + 16, base + stub_start)    # AddressOfEntryPoint
    struct.pack_into("<I", image, opt + 28, base)                 # ImageBase
    struct.pack_into("<I", image, opt + 32, 0x1000)               # SectionAlignment
    struct.pack_into("<I", image, opt + 36, 0x200)                # FileAlignment
    struct.pack_into("<I", image, opt + 56, MODULE_SIZE)          # SizeOfImage
    struct.pack_into("<I", image, opt + 60, _HEADERS)             # SizeOfHeaders
    struct.pack_into("<H", image, opt + 68, 2)                    # GUI，无所谓
    struct.pack_into("<I", image, opt + 92, 16)                   # NumberOfRvaAndSizes
    struct.pack_into("<II", image, opt + 96, exp_off, 40)         # DataDirectory[0]=导出（RVA）
    sec = opt + opt_size
    image[sec:sec + 8] = b".text\x00\x00\x00"
    # ⚠ 节头里的 VirtualAddress 是 **RVA**（相对 ImageBase），不是 VA。
    # 第一版填了 base，任何 PE 解析器算出来都是 2×base（我自己的解析器就报
    # vaddr=0xe2000000），壳自然也读不到导出表。
    struct.pack_into("<IIII", image, sec + 8, MODULE_SIZE, 0, MODULE_SIZE, 0)
    struct.pack_into("<I", image, sec + 36, 0xE0000020)
    return bytes(image), stubs


def build_ldr(uc, modules: Sequence[Tuple[str, int]], peb: int,
              heap_alloc, ring_includes_head: bool = False) -> int:
    """铺 ``PEB_LDR_DATA`` 与三条模块链表，并把 ``PEB->Ldr`` 指过去。

    ``modules`` 是 ``[(dll 名, 基址), …]``，第一个会被放在链表头（模拟加载顺序）。
    每个模块条目是一个 ``LDR_DATA_TABLE_ENTRY``：
    ``+0x00/+0x08/+0x10`` 三条 LIST_ENTRY、``+0x18`` DllBase、``+0x20`` SizeOfImage、
    ``+0x24`` FullDllName、``+0x2C`` BaseDllName（后两个是 UNICODE_STRING）。
    返回链表头地址（调试用）。
    """
    entry_size = 0x60
    ldr = heap_alloc(0x400)                      # PEB_LDR_DATA 结构
    uc.mem_write(ldr, b"\x00" * 0x400)
    entries: List[int] = []
    for dll, base in modules:
        ent = heap_alloc(entry_size)
        uc.mem_write(ent, b"\x00" * entry_size)
        # UNICODE_STRING：Length / MaximumLength / Buffer
        raw = dll.encode("utf-16-le")
        buf = heap_alloc(len(raw) + 2)
        uc.mem_write(buf, raw + b"\x00\x00")
        for name_off in (0x24, 0x2C):
            uc.mem_write(ent + name_off, struct.pack("<HHI", len(raw), len(raw) + 2,
                                                     buf))
        uc.mem_write(ent + 0x18, struct.pack("<I", base))
        uc.mem_write(ent + 0x20, struct.pack("<I", MODULE_SIZE))
        entries.append(ent)
    # 链表成环方式**两种语义都要照顾**，实测不同壳的遍历写法不一样：
    #
    #   ring_includes_head=True（标准 Windows 布局）：末项 Flink 指向表头、
    #   首项 Blink 指向表头；遍历写成 while (e != 表头) 的壳需要它。
    #
    #   ring_includes_head=False（默认）：各条目之间自成环（末项指回首项），
    #   表头同时指向首/末项；有些自写壳的遍历条件是"回到第一个条目就停"，
    #   用标准布局反而找不到目标（实测看雪第七题：标准布局 14 条指令就崩，
    #   自成环能跑 35 万条）。
    #
    # 两种布局无法同时满足，所以做成参数；默认选实测更能让样本跑起来的那种。
    lists = [(ldr + 0x0C, 0x00),      # InLoadOrderModuleList
             (ldr + 0x14, 0x08),      # InMemoryOrderModuleList
             (ldr + 0x1C, 0x10)]      # InInitializationOrderModuleList
    for head, off in lists:
        chain = [ent + off for ent in entries]
        for i, node in enumerate(chain):
            if ring_includes_head:
                nxt = chain[i + 1] if i + 1 < len(chain) else head
                prv = chain[i - 1] if i > 0 else head
            else:
                nxt = chain[(i + 1) % len(chain)]
                prv = chain[(i - 1) % len(chain)]
            uc.mem_write(node + 0, struct.pack("<I", nxt))
            uc.mem_write(node + 4, struct.pack("<I", prv))
        uc.mem_write(head, struct.pack("<II", chain[0], chain[-1]))
    uc.mem_write(peb + 0x0C, struct.pack("<I", ldr))       # PEB->Ldr
    return ldr


def install(uc, api, extra_exports: Iterable[str] = ()) -> Dict[str, int]:
    """把所有假 DLL 映射进内存，并把导出名登记到宿主的桩表里。

    返回 ``{模块名: 基址}``。**登记这一步是关键**：程序自己解析导出表拿到的地址，
    正是我们这里登记的桩地址，于是宿主能接住这次调用。
    """
    # 每个模块导出什么：kernel32/ntdll 给全套 API 名（含 CRT 那些），
    # 其它 DLL 也给一份——反正壳只按名字找，多给几个名字没坏处。
    from . import winapi
    names = sorted(set(winapi._STDCALL_ARGS) | set(extra_exports))
    crt_names = sorted(set(winapi.CRT_EXPORT_NAMES))
    mapping: Dict[str, int] = {}
    for dll, base in MODULE_BASES.items():
        want = crt_names if dll in ("msvcrt.dll",) else names
        if dll == "msvcrt.dll":
            want = sorted(set(crt_names) | set(names))
        image, stubs = build_fake_dll(dll, want, base)
        try:
            uc.mem_map(base, MAPPED_SIZE)
            uc.mem_write(base + MODULE_SIZE, b"\x00" * (MAPPED_SIZE - MODULE_SIZE))
        except Exception:
            pass
        uc.mem_write(base, image)
        for export_name, addr in stubs.items():
            api._stub_of[addr] = export_name
        mapping[dll] = base
    return mapping
