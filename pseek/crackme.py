"""CrackMe 静态辅助：定位比较点，并把"它到底拿什么在比"读出来。

为什么需要：吾爱破解那批 CrackMe 里，**GUI 程序（Qt/MFC/Delphi）占大多数**。
模拟执行对它们帮助有限——校验发生在"点按钮"之后，要把窗口消息循环也模拟出来才谈得上
跑通，这连 Speakeasy 那类专业框架都做不好。所以对 GUI 题，正确的路线是**静态**：

1. 找到 `strcmp`/`memcmp`/`lstrcmp`/`CompareString` 这类比较函数的**调用点**；
2. 把调用点附近的实参还原出来（`push offset "..."` / `lea rcx, [rip+...]` / `mov edx, imm`）；
3. 能读成字符串的就直接显示——**很多 CrackMe 的注册码/密码就摆在比较参数上**。

这套思路和"hook strcmp 拿序列号"是同一件事，只是一个在运行时做（见 `emu`），
一个在静态做（这里）。两边的结论能互相印证。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

#: 值得关注的比较类函数（名字按导入表里的样子匹配，忽略大小写）
COMPARE_FUNCS = (
    "strcmp", "strncmp", "strcmpi", "stricmp", "lstrcmp", "lstrcmpi", "memcmp",
    "comparestringa", "comparestringw", "wcscmp", "wcsncmp", "_stricmp",
    "strnicmp", "_mbsicmp", "strcasecmp", "strncasecmp",
)
#: 读取输入/密码的 API：出现它们说明这块代码在处理用户输入
INPUT_FUNCS = (
    "getwindowtexta", "getwindowtextw", "getdlgitemtexta", "getwindowtextlengtha",
    "scanf", "scanf_s", "gets", "fgets", "readfile", "readconsolea", "getcommandlinea",
)
#: 结果类字符串：出现它们说明这块代码在分支"对/错"
RESULT_HINTS = ("correct", "wrong", "right", "success", "fail", "error", "nope",
                "good", "bad", "congrat", "ok", "成功", "失败", "错误", "正确",
                "恭喜", "注册成功", "注册失败")


@dataclass
class CompareSite:
    at: int
    func: str
    operands: List[Tuple[str, object]] = field(default_factory=list)   # (类型, 值)
    strings: List[str] = field(default_factory=list)

    def describe(self) -> str:
        ops = []
        for kind, value in self.operands:
            if kind == "str":
                ops.append(f'"{value}"')
            else:
                ops.append(f"0x{value:x}")
        return (f"0x{self.at:x}  {self.func}({', '.join(ops)})"
                + (f"   ← 可读字符串：{self.strings}" if self.strings else ""))


def _read_cstr(img, addr: int, limit: int = 256) -> Optional[bytes]:
    for sec in img.segments:
        if sec.vaddr <= addr < sec.vaddr + len(sec.data):
            off = addr - sec.vaddr
            end = sec.data.find(b"\x00", off)
            if end < 0 or end - off > limit:
                return None
            return sec.data[off:end]
    return None


def _looks_like_string(data: Optional[bytes]) -> bool:
    if not data or len(data) < 3:
        return False
    return all(32 <= c < 127 or c in (9, 10, 13) for c in data)


def xrefs_to_iat(img, iat: int, window: int = 16) -> List[int]:
    """找"调用某个导入函数"的代码地址（x86 的 ``call [imm32]`` 与 x64 的 ``call [rip+x]``）。"""
    hits: List[int] = []
    for sec in img.segments:
        if not getattr(sec, "executable", False) or not sec.data:
            continue
        data = sec.data
        if img.bits == 32:
            want = struct.pack("<I", iat)
            start = 0
            while True:
                idx = data.find(want, start)
                if idx < 0:
                    break
                # call/jmp dword ptr [imm32] = FF 15 / FF 25
                if idx >= 2 and data[idx - 2] == 0xFF and data[idx - 1] in (0x15, 0x25):
                    hits.append(sec.vaddr + idx - 2)
                else:
                    hits.append(sec.vaddr + idx)
                start = idx + 1
        else:
            for idx in range(len(data) - 6):
                if data[idx] == 0xFF and data[idx + 1] in (0x15, 0x25):
                    disp = struct.unpack_from("<i", data, idx + 2)[0]
                    if sec.vaddr + idx + 6 + disp == iat:
                        hits.append(sec.vaddr + idx)
    return sorted(set(hits))


def analyze_site(img, site_addr: int, back: int = 0x60) -> CompareSite:
    """反汇编比较点前面的若干条指令，把实参（寄存器/栈上的值）还原出来。"""
    import capstone
    mode = capstone.CS_MODE_64 if img.bits == 64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    site = CompareSite(at=site_addr, func="?")
    for sec in img.segments:
        if not (sec.vaddr <= site_addr < sec.vaddr + len(sec.data)):
            continue
        start = max(sec.vaddr, site_addr - back)
        code = sec.data[start - sec.vaddr:site_addr - sec.vaddr]
        regs: Dict[str, object] = {}
        for ins in md.disasm(code, start):
            op, ops = ins.mnemonic, ins.op_str
            if op in ("mov", "lea"):
                parts = [p.strip() for p in ops.split(",")]
                if len(parts) == 2 and parts[0] in (
                        "eax", "ebx", "ecx", "edx", "esi", "edi",
                        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9"):
                    src = parts[1]
                    if src.startswith("0x") and "[" not in src:
                        regs[parts[0]] = int(src, 16)
                    elif "[rip" in src or "[rip" in src.lower():
                        # lea rcx, [rip + 0x1234]
                        try:
                            disp = int(src.split("+")[-1].strip(" ]"), 16)
                            regs[parts[0]] = ins.address + ins.size + disp
                        except ValueError:
                            pass
                    elif "[" in src:
                        regs[parts[0]] = None
            elif op == "push":
                if ops.startswith("0x"):
                    regs.setdefault("_stack", [])
                    regs["_stack"].append(int(ops, 16))          # type: ignore[union-attr]
        # 收集参数：x64 看 rcx/rdx/r8/r9，x86 看 push 顺序
        if img.bits == 64:
            for r in ("rcx", "rdx", "r8", "r9"):
                if r in regs and regs[r]:
                    addr = int(regs[r])                             # type: ignore[arg-type]
                    raw = _read_cstr(img, addr)
                    if _looks_like_string(raw):
                        site.operands.append(("str", raw.decode("latin-1")))
                        site.strings.append(raw.decode("latin-1"))
                    else:
                        site.operands.append(("imm", addr))
        else:
            pushes = regs.get("_stack") or []
            for value in reversed(pushes[-4:]):                     # type: ignore[union-attr]
                raw = _read_cstr(img, int(value))
                if _looks_like_string(raw):
                    site.operands.append(("str", raw.decode("latin-1")))
                    site.strings.append(raw.decode("latin-1"))
                else:
                    site.operands.append(("imm", int(value)))
        break
    return site


def find_compare_sites(img, limit: int = 40) -> List[CompareSite]:
    sites: List[CompareSite] = []
    for imp in getattr(img, "imports", []) or []:
        low = (imp.name or "").lower().lstrip("_")
        if not any(low.startswith(f.lstrip("_")) for f in COMPARE_FUNCS):
            continue
        for at in xrefs_to_iat(img, imp.iat):
            site = analyze_site(img, at)
            site.func = imp.name
            sites.append(site)
            if len(sites) >= limit:
                return sites
    return sites


def find_result_strings(img) -> List[Tuple[int, str]]:
    """扫出"对/错"这类结果字符串（用来快速判断程序会说哪几句话）。"""
    out: List[Tuple[int, str]] = []
    for sec in img.segments:
        data = sec.data or b""
        low = data.lower()
        for hint in RESULT_HINTS:
            # 中文提示按 GBK 编码去搜（吾爱破解那批题大量是 GBK 中文串）
            for enc in ("latin-1", "gbk"):
                try:
                    needle = hint.encode(enc)
                except UnicodeEncodeError:
                    continue
                start = 0
                while True:
                    idx = low.find(needle, start)
                    if idx < 0:
                        break
                    lo = data.rfind(b"\x00", max(0, idx - 64), idx)
                    hi = data.find(b"\x00", idx)
                    text = data[lo + 1:hi if hi > 0 else idx + 64]
                    if 3 <= len(text) <= 96:
                        try:
                            decoded = text.decode("gbk") if any(c > 127 for c in text) \
                                else text.decode("latin-1")
                        except UnicodeDecodeError:
                            decoded = text.decode("latin-1", "replace")
                        item = (sec.vaddr + lo + 1, decoded)
                        if item not in out:
                            out.append(item)
                    start = idx + 1
    return out[:40]


#: 结果类字符串：出现它们说明这块代码在分支"对/错"
RESULT_HINTS = ("correct", "wrong", "right", "success", "fail", "error", "nope",
                "good", "bad", "congrat", "ok", "成功", "失败", "错误", "正确",
                "恭喜", "注册成功", "注册失败")
#: 运行库/框架自带的噪声字符串：命中这些的"比较点"基本都是库内部逻辑，不是题目逻辑
NOISE = (
    "runtime error", "tloss", "sing error", "domain error", "r6018", "r6017",
    "r6002", "r6008", "r6009", "runtime error!", "getlasterror", "seterrormode",
    "setlasterror", "combobox", "ime", "menu", "button", "static", "edit",
    "msctls_", "systab", "toolbarwindow", "msvcrt", "libgcc", "gcc2_compiled",
    "getprocaddress", "loadlibrary", "kernel32", "user32", "advapi32",
    "microsoft", "borland", "delphi", "qt_", "mfc", "afx", "java", "python",
    ".dll", ".pdb", "??_7", "??_c@", "program: ", "<program name unknown>",
    "abnormal program termination", "floating point", "stack overflow",
    "pure virtual", "bad_alloc", "invalid argument", "string too long",
)


def is_noise(text: str) -> bool:
    low = text.strip().lower()
    if len(low) < 2:
        return True
    return any(n in low for n in NOISE)


def interesting_strings(img, min_len: int = 4, limit: int = 60,
                       include_code: bool = False) -> List[Tuple[int, str, str]]:
    """扫出**可能有价值**的字符串：ASCII、GBK 中文、UTF-16LE 都覆盖，并过滤库噪声。

    为什么必须覆盖 GBK/UTF-16：国产 CrackMe 的提示（"注册码错误""恭喜你成功了"）
    基本都是 GBK 中文或宽字符，只扫 ASCII 会把最有价值的线索漏掉。

    为什么默认**跳过可执行节**：代码段里的"可打印字节序列"几乎全是指令编码的巧合
    （实测能刷出满屏 ``'VQPV'``、``'t.;t$$t('`` 这种），把真正的线索淹掉。
    返回 ``[(地址, 文本, 编码), …]``。
    """
    out: List[Tuple[int, str, str]] = []
    seen = set()
    for sec in img.segments:
        data = sec.data or b""
        if getattr(sec, "executable", False) and not include_code:
            continue
        # (a) ASCII 串
        cur = bytearray()
        cur_at = sec.vaddr
        for i, byte in enumerate(data + b"\x00"):
            if 32 <= byte < 127:
                if not cur:
                    cur_at = sec.vaddr + i
                cur.append(byte)
                continue
            if len(cur) >= min_len:
                text = cur.decode("latin-1")
                if text not in seen and not is_noise(text):
                    seen.add(text)
                    out.append((cur_at, text, "ascii"))
            cur = bytearray()
        # (b) GBK 中文串（连续 ≥2 个汉字或含汉字的中英混排）
        i = 0
        while i < len(data) - 4:
            if data[i] >= 0x81 and data[i] <= 0xFE and \
                    0x40 <= data[i + 1] <= 0xFE:
                j = i
                while j < len(data) - 1:
                    b0, b1 = data[j], data[j + 1]
                    if 0x81 <= b0 <= 0xFE and 0x40 <= b1 <= 0xFE:
                        j += 2
                    elif 32 <= b0 < 127:
                        j += 1
                    else:
                        break
                chunk = data[i:j]
                if len(chunk) >= 4:
                    try:
                        text = chunk.decode("gbk")
                    except UnicodeDecodeError:
                        text = ""
                    if text and any("\u4e00" <= c <= "\u9fff" for c in text) \
                            and text not in seen and not is_noise(text):
                        seen.add(text)
                        out.append((sec.vaddr + i, text, "gbk"))
                i = j if j > i else i + 1
            else:
                i += 1
        # (c) UTF-16LE 串（Dialog/资源里常见）
        i = 0
        while i < len(data) - 8:
            if 32 <= data[i] < 127 and data[i + 1] == 0:
                j = i
                while j < len(data) - 1 and 32 <= data[j] < 127 and data[j + 1] == 0:
                    j += 2
                if j - i >= min_len * 2:
                    text = data[i:j].decode("utf-16-le", "replace")
                    if text not in seen and not is_noise(text):
                        seen.add(text)
                        out.append((sec.vaddr + i, text, "utf16"))
                i = j
            else:
                i += 1
        if len(out) >= limit * 4:
            break
    return out[:limit]


def xrefs_to_code(img, target: int, window: int = 0x8000) -> List[int]:
    """找"调用/跳转到某个地址"的代码位置（``call rel32`` / ``jmp rel32``）。

    为什么需要它：编译器常把导入函数做成一个**跳板**（``GetWindowTextA: jmp [IAT]``），
    真正的调用者写的是 ``call 跳板``。只找"IAT 的引用"就只会找到跳板自己，
    找不到业务逻辑——实测在吾爱那批题上，`find_input_sites` 就因此返回空。
    """
    hits: List[int] = []
    for sec in img.segments:
        if not getattr(sec, "executable", False) or not sec.data:
            continue
        data = sec.data
        for idx in range(len(data) - 5):
            if data[idx] in (0xE8, 0xE9):                # call/jmp rel32
                rel = struct.unpack_from("<i", data, idx + 1)[0]
                if sec.vaddr + idx + 5 + rel == target:
                    hits.append(sec.vaddr + idx)
    return hits


def find_callers_of_import(img, name: str, include_thunk: bool = True
                           ) -> List[int]:
    """给一个导入函数名，找出**所有**调用它的代码位置（含经跳板的调用）。"""
    out: List[int] = []
    for imp in getattr(img, "imports", []) or []:
        if (imp.name or "").lower() != name.lower():
            continue
        thunks = xrefs_to_iat(img, imp.iat)
        for thunk in thunks:
            if include_thunk:
                out.append(thunk)
            out.extend(xrefs_to_code(img, thunk))
        # 有些程序直接 `call [IAT]`（没有跳板）
        out.extend(xrefs_to_iat(img, imp.iat))
    return sorted(set(out))


def find_input_sites(img) -> List[Tuple[int, str]]:
    """找"读用户输入"的调用点（GetWindowText/scanf/ReadFile…）——GUI 题的入口就在附近。"""
    out: List[Tuple[int, str]] = []
    for imp in getattr(img, "imports", []) or []:
        low = (imp.name or "").lower().lstrip("_")
        if not any(low.startswith(f.lstrip("_")) for f in INPUT_FUNCS):
            continue
        # 走"跳板"的调用也要算进来（见 xrefs_to_code 的说明）
        for at in find_callers_of_import(img, imp.name, include_thunk=False):
            out.append((at, imp.name))
    return out


def report(img, limit: int = 20) -> str:
    lines = ["【CrackMe 静态辅助】"]
    dotnet = getattr(img, "is_dotnet", False)
    gui = getattr(img, "subsystem", 3) == 2
    if dotnet:
        lines.append("  ⚠ .NET 程序：比较逻辑在 IL 里，建议 dnSpy/ILSpy；"
                     "下面的字符串线索仍然有用")
    elif gui:
        lines.append("  ⚠ GUI 程序：模拟执行要连窗口消息一起模拟（不现实），"
                     "建议走这里的静态路线")
    inputs = find_input_sites(img)
    if inputs:
        lines.append(f"  读取输入的调用点 {len(inputs)} 处"
                     f"（GUI 题的校验函数通常就在这些点的调用者附近）：")
        for at, name in inputs[:limit]:
            lines.append(f"    0x{at:x}  {name}")
    sites = find_compare_sites(img)
    if sites:
        lines.append(f"  比较点 {len(sites)} 处（列表里的库内部比较已尽量过滤）：")
        for site in sites[:limit]:
            if site.strings and all(is_noise(s) for s in site.strings):
                continue
            lines.append("    " + site.describe())
        interesting = [s for s in sites if s.strings
                       and not all(is_noise(t) for t in s.strings)]
        if interesting:
            lines.append("  ★ 比较参数里直接能读成字符串的：")
            for site in interesting:
                for text in site.strings:
                    if not is_noise(text):
                        lines.append(f"      {text!r}   （在 0x{site.at:x}）")
    else:
        lines.append("  没找到明显的字符串比较点（可能是自写比较 / 走 VM / 先做变换）")
    results = find_result_strings(img)
    results = [(a, t) for a, t in results if not is_noise(t)]
    if results:
        lines.append("  程序里的成败提示字符串：")
        for addr, text in results[:10]:
            lines.append(f"    0x{addr:x}  {text!r}")
    strings = interesting_strings(img, limit=25)
    if strings:
        lines.append("  其它可疑字符串（已过滤运行库噪声；中文/宽字符也在内）：")
        for addr, text, enc in strings[:25]:
            lines.append(f"    0x{addr:x}  [{enc}] {text!r}")
    return "\n".join(lines)
