"""最小 Windows/Linux C 运行库与 Win32 API 模拟层（给 `emu` 用）。

为什么需要它：吾爱破解上的 CrackMe 基本都是"读输入 → 比较 → 打印 Correct/Wrong"的
Windows PE。要让工具**不运行程序也能让它自己判对错**，就得把 `scanf`/`strcmp`/`memcmp`/
`printf` 这些调用"接住"。这正是 Speakeasy（FireEye 的模拟执行框架）和 Qiling 的核心做法：
**把导入表里每个 API 指向一段桩代码，命中桩就由宿主实现它的语义**。

和它们比的取舍（说清楚比吹牛有用）：

* 只实现**逆向题真的会用到的**那一小撮：字符串/内存函数、格式化输入输出、malloc、
  少量 Win32（控制台读写、命令行、反调试探测、时间、弹窗）。不追求覆盖全 API；
* 时间类 API 一律返回**固定值**：一是让模拟结果可复现，二是顺手废掉"时间差反调试"
  （R07 那题的 400 ms 墙钟预算就是这么绕过去的）。反调试探测一律返回"没有调试器"；
* 未实现的 API 返回 0，并且**只提示一次**（不静默忽略也不刷屏）；
* 调用约定按 32/64 位分开处理：x64 走寄存器 + 调用者清栈；x86 下 CRT 是 cdecl（调用者清栈，
  桩只做普通 ``ret``），而 kernel32/user32 这些是 stdcall（桩要 ``ret N`` 自己清）。

输入用一个"游标"喂进去：``%s`` 取一个空白分隔的词，``gets``/``fgets`` 取一行。
输出被收集到列表里，供调用方判定"程序是不是打印了 Correct"。
"""

from __future__ import annotations

import struct
from typing import Callable, Dict, List, Optional, Tuple

#: stdcall（32 位下由被调用者清栈）的常见 Win32 函数 → 参数个数（字节数 = 4×n）
_STDCALL_ARGS: Dict[str, int] = {
    "ExitProcess": 1, "GetStdHandle": 1, "WriteFile": 5, "ReadFile": 5,
    "WriteConsoleA": 5, "WriteConsoleW": 5, "ReadConsoleA": 5,
    "GetCommandLineA": 0, "GetCommandLineW": 0, "GetModuleHandleA": 1,
    "GetModuleHandleW": 1, "VirtualAlloc": 4, "VirtualProtect": 4, "VirtualFree": 3,
    "IsDebuggerPresent": 0, "CheckRemoteDebuggerPresent": 2, "Sleep": 1,
    "GetTickCount": 0, "QueryPerformanceCounter": 1, "QueryPerformanceFrequency": 1,
    "MessageBoxA": 4, "MessageBoxW": 4, "GetLastError": 0, "SetLastError": 1,
    "CreateFileA": 7, "CloseHandle": 1, "GetFileSize": 2, "SetFilePointer": 4,
    "GetStartupInfoA": 1, "SetUnhandledExceptionFilter": 1, "GetCurrentProcess": 0,
    "GetCurrentProcessId": 0, "GetCurrentThreadId": 0, "TerminateProcess": 2,
    "RegOpenKeyExA": 5, "RegQueryValueExA": 6, "RegCloseKey": 1, "RegSetValueExA": 6,
    "OutputDebugStringA": 1, "LoadLibraryA": 1, "GetProcAddress": 2,
    "GetEnvironmentVariableA": 3, "GetSystemDirectoryA": 2, "GetTempPathA": 2,
    "lstrlenA": 1, "lstrcmpA": 2, "wsprintfA": 3, "GetVersion": 0,
    "CreateFileW": 7, "DeleteFileA": 1, "DeleteFileW": 1, "CreateMutexW": 3,
    "OpenMutexA": 3, "WriteProcessMemory": 5, "ReadProcessMemory": 5,
    "GetThreadContext": 2, "SetThreadContext": 2, "VirtualQuery": 3,
    "GetModuleHandleExA": 3, "LoadLibraryW": 1, "GetProcAddress": 2,
    "VirtualAllocEx": 5, "CreateRemoteThread": 7, "ResumeThread": 1,
    "SuspendThread": 1, "OpenThread": 3, "GetExitCodeThread": 2,
    # --- 下面这些是实测 32 位 crackme 时补齐的：漏一个就会少清 4 字节栈，
    #     调用几次之后栈错位、ret 直接飞进栈里（报 UC_ERR_MAP 在 0x2f7c 这种地址）
    "GetFileType": 1, "SetHandleCount": 1, "HeapAlloc": 3, "HeapCreate": 3,
    "HeapFree": 3, "HeapReAlloc": 4, "HeapDestroy": 1, "GetProcessHeap": 0,
    "GetVersionExA": 1, "RtlUnwind": 4, "WideCharToMultiByte": 8,
    "MultiByteToWideChar": 6, "GetACP": 0, "GetOEMCP": 0, "GetCPInfo": 2,
    "LocalAlloc": 2, "LocalFree": 1, "GlobalAlloc": 2, "GlobalFree": 1,
    "GetLocalTime": 1, "GetSystemTime": 1, "GetTickCount64": 0,
    "GetModuleFileNameA": 3, "GetCurrentDirectoryA": 2, "SetCurrentDirectoryA": 1,
    "FindFirstFileA": 2, "FindNextFileA": 2, "FindClose": 1,
    "GetFullPathNameA": 4, "FreeEnvironmentStringsA": 1, "GetEnvironmentStrings": 0,
    "FreeLibrary": 1, "UnhandledExceptionFilter": 1, "SetUnhandledExceptionFilter": 1,
    "GetSystemInfo": 1, "GlobalMemoryStatus": 1, "GetSystemMetrics": 1,
    "SetConsoleCtrlHandler": 2, "SetConsoleMode": 2, "GetConsoleMode": 2,
    "GetConsoleCP": 0, "GetConsoleOutputCP": 0, "FlushConsoleInputBuffer": 1,
    "GetKeyState": 1, "GetAsyncKeyState": 1, "GetDesktopWindow": 0,
    "GetDC": 1, "ReleaseDC": 2, "GetWindowTextA": 3, "GetWindowTextLengthA": 1,
    "SendMessageA": 4, "PostQuitMessage": 1, "DefWindowProcA": 4,
    "RegisterClassA": 1, "CreateWindowExA": 12, "ShowWindow": 2, "UpdateWindow": 1,
    "GetMessageA": 4, "TranslateMessage": 1, "DispatchMessageA": 1,
    "LoadIconA": 2, "LoadCursorA": 2, "SetWindowLongA": 3, "GetWindowLongA": 2,
    "BeginPaint": 2, "EndPaint": 2, "TextOutA": 5, "SetBkMode": 2, "SetTextColor": 2,
    "SelectObject": 2, "CreateSolidBrush": 1, "DeleteObject": 1, "GetStockObject": 1,
    "InvalidateRect": 3, "GetClientRect": 2, "SetTimer": 4, "KillTimer": 2,
    "ExitWindowsEx": 2, "ShellExecuteA": 6, "WinExec": 2, "GetTempFileNameA": 4,
    "GetDiskFreeSpaceA": 5, "GetDriveTypeA": 1, "GetLogicalDrives": 0,
    "IsBadReadPtr": 2, "IsBadWritePtr": 2, "IsBadCodePtr": 1,
    "EnterCriticalSection": 1, "LeaveCriticalSection": 1,
    "InitializeCriticalSection": 1, "DeleteCriticalSection": 1,
    "TlsAlloc": 0, "TlsGetValue": 1, "TlsSetValue": 2, "TlsFree": 1,
    "GetCurrentThread": 0, "DuplicateHandle": 7, "CreateThread": 6,
    "WaitForSingleObject": 2, "SleepEx": 2, "SwitchToThread": 0,
    # 控制台/对话框/时间这一类在"读输入、打印结果"的题里天天出现，
    # 漏一个就会少清 4 字节栈，几十条指令后 `ret` 就飞了（实测栽在 SetConsoleTitleA 上）
    "SetConsoleTitleA": 1, "SetConsoleTitleW": 1, "GetConsoleWindow": 0,
    "SetConsoleTextAttribute": 2, "GetConsoleScreenBufferInfo": 2,
    "SetConsoleCursorPosition": 2, "GetConsoleCursorInfo": 2,
    "FillConsoleOutputCharacterA": 4, "WriteConsoleOutputA": 5,
    "WriteConsoleOutputCharacterA": 4, "ScrollConsoleScreenBufferA": 5,
    "CreateMutexA": 3, "ReleaseMutex": 1, "OpenProcess": 3,
    "GetExitCodeProcess": 2, "CreateProcessA": 10, "WinMain": 4,
    "DialogBoxParamA": 5, "DialogBoxParamW": 5, "EndDialog": 2,
    "GetDlgItem": 2, "SetDlgItemTextA": 3, "GetDlgItemTextA": 4,
    "SendDlgItemMessageA": 5, "MessageBeep": 1, "SetFocus": 1,
    "EnableWindow": 2, "IsWindowVisible": 1, "DestroyWindow": 1,
    "GetParent": 1, "SetWindowPos": 7, "MoveWindow": 6,
    "CreateDialogParamA": 5, "LoadStringA": 4, "LoadMenuA": 2,
    "CheckDlgButton": 3, "IsDlgButtonChecked": 2, "GetDlgCtrlID": 1,
    "SetWindowTextA": 2, "GetClassNameA": 3, "GetWindowRect": 2,
    "GetSystemTimeAsFileTime": 1, "FileTimeToLocalFileTime": 2,
    "FileTimeToSystemTime": 2, "SystemTimeToFileTime": 2, "CompareFileTime": 2,
    "GetTimeZoneInformation": 1, "GetDateFormatA": 6, "GetTimeFormatA": 6,
    "QueryPerformanceFrequency": 1, "GetTickCount": 0, "timeGetTime": 0,
    "GetComputerNameA": 2, "GetUserNameA": 2, "GlobalUnlock": 1, "LocalUnlock": 1,
    "SetEndOfFile": 1, "GetFileAttributesA": 1, "SetFileAttributesA": 2,
    "CopyFileA": 3, "MoveFileA": 2, "RemoveDirectoryA": 1, "CreateDirectoryA": 2,
    # 临界区/一次性初始化这一族：CRT 与 C++ 运行时的初始化里天天出现，
    # 而且**很多程序是"先为某个本地函数压 3 个参数、再 call 这个 API 顺手清栈"**，
    # 参数个数错一个就会让后面的 ret 弹出垃圾（实测看雪第一题就栽在这：
    # 缺 InitializeCriticalSectionEx → 清 0 字节 → 3 个参数留在栈上 → ret 跳到 0）。
    "InitializeCriticalSection": 1, "InitializeCriticalSectionEx": 3,
    "InitializeCriticalSectionAndSpinCount": 2, "DeleteCriticalSection": 1,
    "EnterCriticalSection": 1, "LeaveCriticalSection": 1,
    "TryEnterCriticalSection": 1, "InitOnceExecuteOnce": 4,
    "InitOnceBeginInitialize": 4, "InitOnceComplete": 3,
    "SleepConditionVariableCS": 3, "WakeAllConditionVariable": 1,
    "WakeConditionVariable": 1, "CreateEventA": 4, "CreateEventW": 4,
    "SetEvent": 1, "ResetEvent": 1, "WaitForMultipleObjects": 4,
    # 这几个是"动态解析路径"上实测缺过的（缺了就只能靠反推，而动态解析的反推不可靠）
    "IsProcessorFeaturePresent": 1, "LoadLibraryExA": 3, "LoadLibraryExW": 3,
    "FlushInstructionCache": 3, "GetStartupInfoW": 1, "GetStartupInfoA": 1,
    # FLS/TLS 与安全 cookie：MSVC 的"线程安全静态初始化"(__declspec(thread)/魔术静态)
    # 一定会用到，缺一个就会让动态解析拿到 0（实测看雪第一题卡在 FlsAlloc）
    "FlsAlloc": 1, "FlsFree": 1, "FlsGetValue": 1, "FlsSetValue": 2,
    "TlsGetValue": 1, "TlsSetValue": 2, "TlsFree": 1, "TlsAlloc": 0,
    "EncodePointer": 1, "DecodePointer": 1, "RaiseException": 4,
    "RtlUnwind": 4, "RtlCaptureContext": 1, "RtlVirtualUnwind": 6,
    "RtlLookupFunctionEntry": 3, "CompareStringW": 6, "CompareStringOrdinal": 5,
    "GetModuleFileNameW": 3, "GetCurrentPackageFullName": 2,
    "AppPolicyGetProcessTerminationMethod": 2, "GetFileVersionInfoSizeW": 2,
    # ETW：现代 MSVC CRT / C++ 运行时会动态解析这一族做"提供程序注册"，
    # 不实现就会拿到 0 当句柄（实测看雪第一题卡在 EventRegister）
    "EventRegister": 4, "EventUnregister": 1, "EventSetInformation": 4,
    "EventWriteTransfer": 8, "EventActivityIdControl": 2,
    "EventEnabled": 2, "EventWrite": 5,
    # UCRT 的 `__stdio_common_*`：现代 MSVC 的 printf/scanf **全部**走这一族
    # （由 CRT 用 GetProcAddress 动态解析）。它们是 **cdecl 之外的标准 stdcall**，
    # 但都在 ucrtbase 里、导入表里常常查不到，所以必须显式写元数——
    # 漏一个就会少数参数、栈歪掉（实测看雪第一题：`__stdio_common_vfprintf` 5 个参数）
    "__stdio_common_vfprintf": 5, "__stdio_common_vfprintf_p": 5,
    "__stdio_common_vfprintf_s": 5, "__stdio_common_vsprintf": 6,
    "__stdio_common_vsprintf_p": 6, "__stdio_common_vsprintf_s": 6,
    "__stdio_common_vsnprintf_s": 8, "__stdio_common_vsnwprintf_s": 8,
    "__stdio_common_vswprintf": 5, "__stdio_common_vswprintf_s": 5,
    "__stdio_common_vfwprintf": 5, "__stdio_common_vfwprintf_s": 5,
    "__stdio_common_vfscanf": 5, "__stdio_common_vsscanf": 6,
    "__stdio_common_vswscanf": 5,
}

#: 32 位下这些 DLL 的导出按 stdcall 处理
_STDCALL_DLLS = ("kernel32", "user32", "advapi32", "shell32", "gdi32", "ntdll",
                 "ole32", "oleaut32", "ws2_32", "comctl32", "shlwapi")


class _ExitRequested(Exception):
    def __init__(self, code: int):
        self.code = code


#: CRT(msvcrt) 侧会出现在导出表里的名字 —— 造"假 msvcrt"时按这份名单建导出目录。
#: 壳/loader 自己解析导出表时，能从这里拿到它想要的 CRT 函数地址。
CRT_EXPORT_NAMES = (
    "strlen", "strcmp", "strncmp", "strcmpi", "stricmp", "strcpy", "strncpy",
    "strcat", "strncat", "strchr", "strrchr", "strstr", "strcspn", "strspn",
    "strpbrk", "strdup", "memcmp", "memcpy", "memmove", "memset", "memchr",
    "printf", "fprintf", "sprintf", "vsprintf", "snprintf", "_snprintf",
    "puts", "putchar", "putc", "fputs", "fputc", "fwrite", "fread", "fflush",
    "fclose", "fopen", "setvbuf", "scanf", "sscanf", "gets", "fgets", "read",
    "atoi", "atol", "atof", "strtol", "strtoul", "malloc", "calloc", "realloc",
    "free", "exit", "_exit", "abort", "atexit", "_onexit", "rand", "srand",
    "time", "clock", "getenv", "system", "qsort", "bsearch", "tolower",
    "toupper", "isdigit", "isalpha", "isalnum", "isspace", "toupper",
    "__iob_func", "_iob", "__acrt_iob_func", "_errno", "__errno", "_lock",
    "_unlock", "_fileno", "_isatty", "_setmode", "__p__commode",
    "__set_app_type", "_amsg_exit", "_initterm", "_initterm_e",
    "__getmainargs", "__wgetmainargs", "_cexit", "_c_exit", "_exit",
)


#: 判断"是不是 CRT 函数"用的名字集合（32 位下 CRT 是 **cdecl**，其余系统 API 基本是
#: **stdcall**）。**动态解析出来的名字在导入表里查不到**，早先版本因此把 stdcall 判成
#: False、一个字节也不清，栈一路歪下去——实测看雪第一题就是这样：
#: 程序先为某个本地函数压了 3 个参数，再 `call` 一个 GetProcAddress 解析出来的 API
#: 顺手清栈；我们没清，最后 `ret` 弹出 0 跳到地址 0。
_CRT_LIKE = {n.lower().lstrip("_") for n in CRT_EXPORT_NAMES}

#: **元数冲突时听谁的**（32 位 stdcall 清栈用）：
#:
#: * ``"table_first"``（**默认**）—— 信手写参数表。实测"调用点压了几个"这条证据
#:   在真实程序里并不可靠：参数可能由 `mov [esp+k], val` 传入、或与别的调用混在一起，
#:   数出来的值经常是错的（实测把 `FlsAlloc` 数成 8 个、`GetProcAddress` 数成 1 个）。
#: * ``"call_site_first"`` —— 信调用点。仅当你想对比排查时才切换。
#:
#: 无论哪种策略，**名字不在表里**时都会退回到"调用点反推"（否则只能不清栈）。
ARITY_POLICY = "table_first"


def _count_pushes_before_impl(code: bytes, base: int, call_off: int) -> int:
    """数出 `call` 前面**连续的 push** 个数（用 capstone 正规解码）。

    ⚠ 以前是"按字节回退"手写的：``push [ebp+disp8]`` 其实是 **3 字节**（FF 75 xx），
    我按 2 字节回退，于是**每遇到一个这种 push 就会少数一个参数**——实测看雪第一题的
    UCRT `__stdio_common_vfprintf` 蹦床压了 5 个参数、我只数出 4，
    少清 4 字节、栈一路歪掉。这类"指令长度算错"只能靠真正的解码器解决。
    """
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86,
                         capstone.CS_MODE_64 if base > 0x100000000
                         else capstone.CS_MODE_32)
        instrs = list(md.disasm(code, base))
    except Exception:
        instrs = []
    if not instrs:
        return 0
    # 找到最后一条位于 call 之前的 call 指令
    idx = None
    for i, ins in enumerate(instrs):
        if ins.address - base >= call_off:
            break
        if ins.mnemonic.startswith("call"):
            idx = i
    if idx is None:
        return 0
    count = 0
    j = idx - 1
    while j >= 0 and instrs[j].mnemonic == "push":
        count += 1
        j -= 1
    if count:
        return count
    # **严格两段式**：CRT 里大量存在这种蹦床——
    #     push a3 / push a2 / push a1 / call 本地函数（裸 ret）/ call esi（真正的 API）
    # 紧邻 `call esi` 前面是那条本地 call（0 个 push），跳过它恰好再数一段连续的 push。
    # ⚠ 千万别"把窗口里所有 push 都算上"：那样会把别的调用的 push 也算进来，
    # 实测把 `FlsAlloc` 数成 8 个、`GetProcAddress` 数成 1 个，比不数还糟。
    if j >= 0 and instrs[j].mnemonic.startswith("call"):
        j -= 1
        while j >= 0 and instrs[j].mnemonic == "push":
            count += 1
            j -= 1
    return count


class ApiEmulator:
    """把导入的 API 实现成"宿主函数"。同时兼容 PE(x86/x64) 与 ELF(x86-64)。"""

    def __init__(self, uc, image, stdin: bytes = b"", argv: Optional[List[str]] = None,
                 on_output: Optional[Callable[[str], None]] = None,
                 on_note: Optional[Callable[[str], None]] = None,
                 time_source: int = 0x1000):
        self.uc = uc
        self.image = image
        self.bits = getattr(image, "bits", 64)
        self.stdin = stdin or b""
        #: 每次 API 调用的"栈台账"（谁调的、清了多少、返回地址在哪）——排查栈错位用
        self.esp_log: List[Dict[str, object]] = []
        self.stdin_pos = 0
        self.argv = argv or []
        self.output: List[bytes] = []
        self.notes: List[str] = []
        self.time_source = time_source
        self.exit_code: Optional[int] = None
        self.last_error = 0
        self._on_output = on_output
        self._on_note = on_note
        self._unknown: Dict[str, int] = {}
        #: 记录程序内部做过的字符串/内存比较 —— CrackMe 的"期望值"通常就藏在这里。
        #: 这就是"hook strcmp 拿序列号"的自动化版本，对"直接比较输入"的题一击必杀。
        self.comparisons: List[Tuple[str, bytes, bytes]] = []
        self._stub_base = 0x10000000 if self.bits == 32 else 0x70000000
        self._stub_page = self._stub_base + 0x100000
        self._heap_base = self._stub_base + 0x200000
        self._heap_ptr = self._heap_base + 0x1000
        self._heap_mapped = 0
        self._stub_of: Dict[int, str] = {}          # 桩地址 → API 名

    # ------------------------------------------------------------ 铺设
    def map_stubs(self) -> None:
        """把导入表每一项的 IAT 槽改写成"我们自己的桩地址"，并记录映射。

        这一步是整件事的地基：不接管 IAT，`call [IAT]` 就会跳到 0 或者未映射内存，
        模拟执行立刻崩；接管之后，命中桩地址就等于"这个 API 被调用了"。
        """
        uc = self.uc
        page = 0x1000
        imports = list(getattr(self.image, "imports", []))
        if not imports:
            return
        addr = self._stub_base
        uc.mem_map(self._stub_base, 0x2000)
        for i, imp in enumerate(imports):
            stub = addr + i * 16
            self._stub_of[stub] = imp.name or "?"
            try:
                if self.bits == 64:
                    uc.mem_write(imp.iat, struct.pack("<Q", stub))
                else:
                    uc.mem_write(imp.iat, struct.pack("<I", stub))
            except Exception:
                continue
        del page

    def _heap(self, size: int) -> int:
        """模拟堆分配：从一块自留地往里切（不做回收，够用即可）。

        注意这里对 ``mem_map`` 失败要**兜住**：Windows 的 VirtualAlloc 有时会要一块
        很大的内存或者指定地址，直接映射会撞上已映射区域，报 UC_ERR_MAP 把整场模拟打断。
        """
        size = max(16, min(int(size), 0x8000000))          # 上限 128MB，防疯分配
        need = size + 0x1000
        if self._heap_mapped < need:
            try:
                self.uc.mem_map(self._heap_base, 0x100000)
                self._heap_mapped = 0x100000
            except Exception:
                # 撞车了就换一块地，而不是崩掉
                self._heap_base += 0x200000
                self._heap_ptr = self._heap_base + 0x1000
                try:
                    self.uc.mem_map(self._heap_base, 0x100000)
                    self._heap_mapped = 0x100000
                except Exception:
                    return self._heap_ptr
        addr = self._heap_ptr
        self._heap_ptr += (size + 15) & ~15
        if self._heap_ptr >= self._heap_base + self._heap_mapped:
            self._heap_ptr = addr        # 堆用完了就不动（题目一般用不到这么多）
        return addr

    # ------------------------------------------------------------ 寄存器/内存
    def _reg(self, name: str) -> int:
        from unicorn import x86_const as xc
        if self.bits == 32:
            return self.uc.reg_read(getattr(xc, f"UC_X86_REG_E{name}"))
        return self.uc.reg_read(getattr(xc, f"UC_X86_REG_R{name}"))

    def _set_reg(self, name: str, value: int) -> None:
        from unicorn import x86_const as xc
        if self.bits == 32:
            self.uc.reg_write(getattr(xc, f"UC_X86_REG_E{name}"), value & 0xFFFFFFFF)
        else:
            self.uc.reg_write(getattr(xc, f"UC_X86_REG_R{name}"),
                              value & 0xFFFFFFFFFFFFFFFF)

    def _sp(self) -> int:
        from unicorn import x86_const as xc
        return self.uc.reg_read(xc.UC_X86_REG_ESP if self.bits == 32
                                else xc.UC_X86_REG_RSP)

    def _set_sp(self, value: int) -> None:
        from unicorn import x86_const as xc
        self.uc.reg_write(xc.UC_X86_REG_ESP if self.bits == 32
                          else xc.UC_X86_REG_RSP, value)

    def _ip(self) -> int:
        from unicorn import x86_const as xc
        return self.uc.reg_read(xc.UC_X86_REG_EIP if self.bits == 32
                                else xc.UC_X86_REG_RIP)

    def _set_ip(self, value: int) -> None:
        from unicorn import x86_const as xc
        self.uc.reg_write(xc.UC_X86_REG_EIP if self.bits == 32
                          else xc.UC_X86_REG_RIP, value)

    def read_cstr(self, addr: int, limit: int = 4096) -> bytes:
        if not addr:
            return b""
        out = bytearray()
        try:
            while len(out) < limit:
                chunk = self.uc.mem_read(addr + len(out), 1)
                if not chunk or chunk[0] == 0:
                    break
                out.append(chunk[0])
        except Exception:
            pass
        return bytes(out)

    def write_cstr(self, addr: int, data: bytes, nul: bool = True) -> None:
        self.uc.mem_write(addr, data + (b"\x00" if nul else b""))

    def read_wide(self, addr: int, limit: int = 4096) -> bytes:
        raw = bytearray()
        try:
            for i in range(limit):
                ch = self.uc.mem_read(addr + i * 2, 2)
                if ch == b"\x00\x00":
                    break
                raw += ch
        except Exception:
            pass
        return bytes(raw)

    # ------------------------------------------------------------ 参数
    def args(self, n: int) -> List[int]:
        """按调用约定取参数：x64 走 rcx/rdx/r8/r9 + 栈；x86 全在栈上。"""
        out: List[int] = []
        if self.bits == 64:
            from unicorn import x86_const as xc
            regs = (xc.UC_X86_REG_RCX, xc.UC_X86_REG_RDX, xc.UC_X86_REG_R8,
                    xc.UC_X86_REG_R9)
            for i in range(n):
                if i < 4:
                    out.append(self.uc.reg_read(regs[i]))
                else:
                    sp = self._sp() + 0x28 + (i - 4) * 8      # 影子空间 32 字节 + 返回地址
                    out.append(struct.unpack("<Q", self.uc.mem_read(sp, 8))[0])
        else:
            sp = self._sp() + 4
            for i in range(n):
                out.append(struct.unpack("<I", self.uc.mem_read(sp + i * 4, 4))[0])
        return out

    def finish(self, ret_value: int, nargs: int, stdcall: bool) -> None:
        """把返回值放进 EAX/RAX，然后**按调用约定把栈还原**再返回调用点。

        这里顺便记一笔"栈台账"（`self.esp_log`）：谁调的、清了多少字节、
        返回地址在哪。排查"栈被清过头/清少了"这种问题时，这份台账比盲猜有用得多
        （看雪第一题就是靠它定位到具体某个 API 的）。
        """
        try:
            sp_before = self._sp()
            ra = struct.unpack("<I" if self.bits == 32 else "<Q",
                               self.uc.mem_read(sp_before, self.bits // 8))[0]
        except Exception:
            sp_before, ra = 0, 0
        self._finish_inner(ret_value, nargs, stdcall)
        if getattr(self, "esp_log", None) is not None and len(self.esp_log) < 4000:
            self.esp_log.append({
                "name": getattr(self, "_cur", "?"),
                "nargs": nargs, "stdcall": stdcall,
                "esp_before": sp_before, "esp_after": self._sp(),
                "ret": ra,
                "pushed_guess": self.guess_nargs_for(ra),
            })

    def guess_nargs_for(self, ret_addr: int) -> int:
        """给任意返回地址反推"这个调用点前面压了几个参数"（用于台账对比）。"""
        if not ret_addr:
            return 0
        try:
            code = bytes(self.uc.mem_read(ret_addr - 32, 32))
        except Exception:
            return 0
        # call 指令的起始偏移（相对窗口起点），再交给 capstone 正规解码去数 push
        call_off = None
        for i in range(len(code) - 2, -1, -1):
            if code[i] == 0xE8 or (code[i] == 0xFF and i + 1 < len(code)
                                   and (code[i + 1] & 0x38) == 0x10):
                call_off = i
                break
        if call_off is None:
            return 0
        return _count_pushes_before_impl(code, ret_addr - 32, call_off)

    def _finish_inner(self, ret_value: int, nargs: int, stdcall: bool) -> None:
        """从桩里"返回"：x64/ cdecl 只弹返回地址；stdcall 还要自己清参数。"""
        sp = self._sp()
        ret = struct.unpack("<Q" if self.bits == 64 else "<I",
                            self.uc.mem_read(sp, 8 if self.bits == 64 else 4))[0]
        if self.bits == 32 and stdcall:
            sp += 4 + nargs * 4
        elif self.bits == 64:
            sp += 8
        else:
            sp += 4
        self._set_sp(sp)
        self._set_reg("AX" if self.bits == 32 else "AX", ret_value)
        self._set_ip(ret)

    # ------------------------------------------------------------ 输入输出
    def _next_token(self) -> bytes:
        while self.stdin_pos < len(self.stdin) and self.stdin[self.stdin_pos:self.stdin_pos + 1].isspace():
            self.stdin_pos += 1
        start = self.stdin_pos
        while (self.stdin_pos < len(self.stdin)
               and not self.stdin[self.stdin_pos:self.stdin_pos + 1].isspace()):
            self.stdin_pos += 1
        return self.stdin[start:self.stdin_pos]

    def _next_line(self, keep_newline: bool = False) -> bytes:
        """取一行输入。

        **`fgets` 要保留末尾的换行符**（真实语义就是这样），很多题会写
        ``fgets(buf, n, stdin); buf[strcspn(buf, "\\n")] = 0;`` ——
        如果我们提前把 ``\\n`` 吃掉，长度判断就会差 1，程序直接走失败分支。
        ``gets`` 则相反，它会把换行符丢掉。
        """
        end = self.stdin.find(b"\n", self.stdin_pos)
        if end < 0:
            line = self.stdin[self.stdin_pos:]
            self.stdin_pos = len(self.stdin)
            return line
        line = self.stdin[self.stdin_pos:end + (1 if keep_newline else 0)]
        self.stdin_pos = end + 1
        return line

    def emit(self, data: bytes) -> None:
        self.output.append(data)
        if self._on_output:
            try:
                self._on_output(data.decode("utf-8", "replace"))
            except Exception:
                pass

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)
            if self._on_note:
                self._on_note(text)

    def stdout(self) -> str:
        """把程序输出解码成文本。

        **必须做编码兜底**：国产 CrackMe（尤其吾爱破解 2012 那批）输出的是 GBK 中文，
        直接按 UTF-8 解会变成一片乱码，连"恭喜成功/失败"这种关键词都匹配不上，
        于是成败判定直接失效。所以按 utf-8 → gbk → big5 → latin-1 依次尝试。
        """
        raw = b"".join(self.output)
        for enc in ("utf-8", "gbk", "big5"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("latin-1", "replace")

    # ------------------------------------------------------------ 分发
    def guess_nargs(self) -> int:
        """从**调用点**反推 stdcall 的参数个数（表里没写的时候用）。

        做法：返回地址就压在栈顶，`call` 指令在它前面几个字节。往前扫出那条 call
        （``FF 15 imm32`` / ``FF D0-D7`` / ``E8 rel32``），再数它前面**连续的 push**：
        编译器给 stdcall 传参就是一路 push，所以连续 push 的个数基本等于参数个数。

        为什么必须做这件事：32 位 stdcall 由**被调用方清栈**，参数个数猜错就会让
        ESP 差 4 的倍数，调用几次之后 ``ret`` 就飞进栈里（实测表现是
        "UC_ERR_MAP 在 0x2f7c"这种莫名其妙的地方）。宁可猜个近似值也不能默认 0。
        """
        try:
            sp = self._sp()
            ret = struct.unpack("<I", self.uc.mem_read(sp, 4))[0]
        except Exception:
            return 0
        code = b""
        try:
            # 窗口要够大：CRT 蹦床里"5 个 push + 一条本地 call"就跨 22 字节，
            # 以前只读 16 字节 → 数不全 push → 元数取默认值 → 栈歪（实测看雪第一题）
            code = bytes(self.uc.mem_read(ret - 64, 64))
        except Exception:
            return 0
        # 找 call 指令的起始偏移（相对 ret-64）
        call_off = None
        for i in range(len(code) - 2, -1, -1):
            if code[i] == 0xFF and i + 1 < len(code) and \
                    (code[i + 1] & 0x38) == 0x10:
                call_off = i
                break
            if code[i] == 0xE8:
                call_off = i
                break
        if call_off is None:
            return 0
        # 从 call 往前数连续的 push —— 交给 capstone 正规解码
        # （手写的"按字节回退"会把 `push [ebp+disp8]`（3 字节）当成 2 字节，少数一个参数）
        count = _count_pushes_before_impl(code, ret - 64, call_off)
        if count:
            return count
        # 一条 push 都没有？可能是 MSVC 开了优化后的写法：
        # 函数开头一次性 `sub esp, N` 预留空间，之后用 `mov [esp+k], val` 传参。
        # 这时"参数字节数 = 最大的 k + 4"，把 k 找出来就能反推参数个数。
        # （实测就是这里漏掉了 SetConsoleTitleA，少清 4 字节栈、几十条指令后 ret 飞掉）
        max_k = -1
        for j in range(call_off - 1, max(0, call_off - 40), -1):
            # 88/89/C6/C7 05/0C/14/1C/24/2C/34/3C/44/4C ... 简化为扫 "mov [esp+k],"
            if code[j:j + 1] in (b"\x89", b"\xc7") and j + 2 < len(code):
                modrm = code[j + 1]
                if (modrm & 0xC7) == 0x04:           # mod=00/01/10, rm=100 → [esp+disp]
                    disp = 0
                    if (modrm & 0xC0) == 0x40:
                        disp = code[j + 2]
                    elif (modrm & 0xC0) == 0x80:
                        disp = struct.unpack_from("<i", code, j + 2)[0]
                    if 0 <= disp <= 0x40:
                        max_k = max(max_k, disp)
        if max_k >= 0:
            return (max_k + 4) // 4
        return 0

    def dispatch(self, addr: int) -> None:
        """在桩地址上被调用：实现 API 语义，然后返回到调用点。"""
        name = self._stub_of.get(addr)
        self._cur = name          # 供"栈台账"记录名字
        if name is None:
            # 不是我们的桩：直接当 ret 处理，避免模拟卡死
            self.finish(0, 0, False)
            return
        dll = ""
        for imp in getattr(self.image, "imports", []):
            if imp.name == name:
                dll = (imp.dll or "").lower()
                break
        stdcall = (self.bits == 32 and any(d in dll for d in _STDCALL_DLLS))
        if self.bits == 32 and not dll:
            # 导入表里查不到这个名字 → 它是**运行时动态解析**出来的（GetProcAddress/
            # 自己解析导出表）。这种情况不能默认"不清栈"：32 位 Windows 上系统 API
            # 基本都是 stdcall，只有 CRT 那一族是 cdecl。
            stdcall = name.lower().lstrip("_") not in _CRT_LIKE
            self.note(f"{name} 不在导入表里（动态解析）：按 "
                      f"{'stdcall' if stdcall else 'cdecl'} 处理清栈")
        nargs = _STDCALL_ARGS.get(name, 0)
        if self.bits == 32 and stdcall:
            # 调用点证据（跨中间的本地 call 一起数 push）。CRT 的蹦床写法
            # ``push 参数 → call 本地裸ret → call 真正的 API`` 里，参数正是由那次 API 清掉的；
            # 手写参数表再全也会漏，所以冲突时的取舍很关键，见 ARITY_POLICY。
            guessed = self.guess_nargs()
            known = name in _STDCALL_ARGS
            if guessed and 1 <= guessed <= 12:
                if not known:
                    nargs = guessed
                    self.note(f"{name} 不在参数表里：从调用点反推参数个数={guessed}"
                              f"（stdcall 清栈用，猜错会让栈错位）")
                elif guessed != nargs and ARITY_POLICY == "call_site_first":
                    self.note(f"{name}：表里写 {nargs} 个参数，调用点压了 {guessed} 个"
                              f" → 按调用点清栈（ARITY_POLICY=call_site_first）")
                    nargs = guessed
            elif not known:
                # **没证据就别清栈**：宁可漏清（栈慢慢变浅）也不要错清
                # （错清会让 ret 直接跳到垃圾地址，更难查）。
                stdcall = False
                self.note(f"⚠ {name} 参数个数未知且反推失败：不清栈（按 cdecl 处理），"
                          f"若后续出现「栈错位」症状请手工补参数表")
        try:
            # 方法名映射：`_api_<原名>` 优先（带下划线的 API 如 `__iob_func`、`_lock`
            # 只能靠精确匹配；早先版本先试 `api_<原名>` 再试"去掉下划线"的变体，
            # 结果这一类 API 全部落空、被当成"未实现"返回 0，程序拿着 NULL 的 FILE*
            # 直接崩在 `or dword[bx+18],0x8000`——坑记在这里。
            handler = (getattr(self, "_api_" + name, None)
                       or getattr(self, "api_" + name, None)
                       or getattr(self, "_api_" + name.replace("_", ""), None))
            if handler is not None:
                value, used = handler()
            else:
                value, used = self._api_unknown(name), nargs
        except _ExitRequested:
            raise
        except Exception as exc:                     # API 实现里的 bug 不该让整场模拟失败
            self.note(f"{name} 模拟出错（按返回 0 处理）：{exc}")
            value, used = 0, nargs
        self.finish(value if value is not None else 0, used if used else nargs,
                    stdcall)

    def _api_unknown(self, name: str) -> int:
        if name not in self._unknown:
            self._unknown[name] = 0
            if len(self._unknown) <= 12:
                self.note(f"未实现的 API：{name}（返回 0）")
        return 0

    # ---------------------------------------------------- 字符串/内存（CRT）
    def _api_strlen(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        return len(self.read_cstr(ptr)), 1

    def _api_lstrlenA(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        return len(self.read_cstr(ptr)), 1

    def _record_cmp(self, api: str, a: bytes, b: bytes) -> None:
        """把一次比较记下来（供上层指出"程序期望什么"）。"""
        if len(self.comparisons) < 64:
            self.comparisons.append((api, a[:128], b[:128]))

    def _api_strcmp(self) -> Tuple[int, int]:
        a, b = self.args(2)
        x, y = self.read_cstr(a), self.read_cstr(b)
        self._record_cmp("strcmp", x, y)
        if x == y:
            return 0, 2
        # 返回"第一个不同字节之差"的符号，够模拟大多数分支
        for i in range(min(len(x), len(y))):
            if x[i] != y[i]:
                return (1 if x[i] > y[i] else -1) & (0xFFFFFFFF if self.bits == 32
                                                     else 0xFFFFFFFFFFFFFFFF), 2
        return (1 if len(x) > len(y) else -1), 2

    def _api_lstrcmpA(self) -> Tuple[int, int]:
        return self._api_strcmp()

    def _api_strncmp(self) -> Tuple[int, int]:
        a, b, n = self.args(3)
        x, y = self.read_cstr(a), self.read_cstr(b)
        self._record_cmp("strncmp", x[:n], y[:n])
        return (0 if x[:n] == y[:n] else 1), 3

    def _api_memcmp(self) -> Tuple[int, int]:
        a, b, n = self.args(3)
        try:
            x = bytes(self.uc.mem_read(a, n))
            y = bytes(self.uc.mem_read(b, n))
        except Exception:
            return 0, 3
        self._record_cmp("memcmp", x, y)
        if x == y:
            return 0, 3
        for i in range(min(len(x), len(y))):
            if x[i] != y[i]:
                return (1 if x[i] > y[i] else -1), 3
        return 0, 3

    def _api_strncpy(self) -> Tuple[int, int]:
        dst, src, n = self.args(3)
        data = self.read_cstr(src, n)[:n]
        self.uc.mem_write(dst, data + b"\x00" * max(0, n - len(data)))
        return dst, 3

    def _api_strcpy(self) -> Tuple[int, int]:
        dst, src = self.args(2)
        self.write_cstr(dst, self.read_cstr(src))
        return dst, 2

    def _api_strcat(self) -> Tuple[int, int]:
        dst, src = self.args(2)
        cur = self.read_cstr(dst)
        self.write_cstr(dst, cur + self.read_cstr(src))
        return dst, 2

    def _api_memcpy(self) -> Tuple[int, int]:
        dst, src, n = self.args(3)
        try:
            self.uc.mem_write(dst, bytes(self.uc.mem_read(src, n)))
        except Exception:
            pass
        return dst, 3

    def _api_memset(self) -> Tuple[int, int]:
        dst, val, n = self.args(3)
        try:
            self.uc.mem_write(dst, bytes([val & 0xFF]) * n)
        except Exception:
            pass
        return dst, 3

    def _api_strchr(self) -> Tuple[int, int]:
        ptr, ch = self.args(2)
        data = self.read_cstr(ptr)
        idx = data.find(bytes([ch & 0xFF]))
        return (ptr + idx) if idx >= 0 else 0, 2

    def _api_strstr(self) -> Tuple[int, int]:
        a, b = self.args(2)
        data, needle = self.read_cstr(a), self.read_cstr(b)
        idx = data.find(needle)
        return (a + idx) if idx >= 0 else 0, 2

    def _api_atoi(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        text = self.read_cstr(ptr).decode("latin-1", "replace")
        try:
            return int(text.strip() or "0"), 1
        except ValueError:
            num = ""
            for ch in text.strip():
                if ch.isdigit() or (ch in "+-" and not num):
                    num += ch
                else:
                    break
            return (int(num) if num else 0), 1

    def _api_atol(self) -> Tuple[int, int]:
        return self._api_atoi()

    def _api_malloc(self) -> Tuple[int, int]:
        (size,) = self.args(1)
        return self._heap(max(16, size)), 1

    def _api_calloc(self) -> Tuple[int, int]:
        count, size = self.args(2)
        addr = self._heap(max(16, count * size))
        try:
            self.uc.mem_write(addr, b"\x00" * (count * size))
        except Exception:
            pass
        return addr, 2

    def _api_free(self) -> Tuple[int, int]:
        return 0, 1

    def _api_exit(self) -> Tuple[int, int]:
        raise _ExitRequested(self.args(1)[0] & 0xFF)

    def _api_abort(self) -> Tuple[int, int]:
        raise _ExitRequested(3)

    def _api_ExitProcess(self) -> Tuple[int, int]:
        raise _ExitRequested(self.args(1)[0] & 0xFF)

    # ---------------------------------------------------- 解析格式串
    def _format(self, fmt: bytes, arg_index: int) -> Tuple[bytes, int]:
        """把 printf 这类变参函数格式化出来（支持 %s %d %u %x %X %c %p %%，宽度和 l 修饰）。"""
        out = bytearray()
        i = 0
        used = arg_index
        while i < len(fmt):
            ch = fmt[i:i + 1]
            if ch != b"%":
                out += ch
                i += 1
                continue
            i += 1
            if i >= len(fmt):
                break
            spec = fmt[i:i + 1]
            if spec == b"%":
                out += b"%"
                i += 1
                continue
            # 跳过标志/宽度/精度
            while i < len(fmt) and fmt[i:i + 1] in b"-+ #0123456789.*":
                i += 1
            while i < len(fmt) and fmt[i:i + 1] in b"hlLqjzt":
                i += 1
            spec = fmt[i:i + 1]
            i += 1
            value = self.args(used + 1)[used] if used < 24 else 0
            used += 1
            if spec == b"s":
                out += self.read_cstr(value)
            elif spec in (b"d", b"i"):
                signed = value - (1 << (32 if self.bits == 32 else 64)) \
                    if value >> (31 if self.bits == 32 else 63) else value
                out += str(signed).encode()
            elif spec == b"u":
                out += str(value & 0xFFFFFFFF).encode()
            elif spec in (b"x", b"X", b"p"):
                text = f"{value & 0xFFFFFFFF:x}"
                out += (text.upper() if spec == b"X" else text).encode()
            elif spec == b"c":
                out += bytes([value & 0xFF])
            else:
                out += b"?" + spec
        return bytes(out), used

    def _api_printf(self) -> Tuple[int, int]:
        (fmt,) = self.args(1)
        text, used = self._format(self.read_cstr(fmt), 1)
        self.emit(text)
        return len(text), used

    def _api_fprintf(self) -> Tuple[int, int]:
        _stream, fmt = self.args(2)
        text, used = self._format(self.read_cstr(fmt), 2)
        self.emit(text)
        return len(text), used

    def _api_sprintf(self) -> Tuple[int, int]:
        dst, fmt = self.args(2)
        text, used = self._format(self.read_cstr(fmt), 2)
        self.write_cstr(dst, text)
        return len(text), used

    def _api_puts(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        text = self.read_cstr(ptr)
        self.emit(text + b"\n")
        return len(text) + 1, 1

    def _api_fputs(self) -> Tuple[int, int]:
        ptr, _stream = self.args(2)
        text = self.read_cstr(ptr)
        self.emit(text)
        return len(text), 2

    def _api_putchar(self) -> Tuple[int, int]:
        (ch,) = self.args(1)
        self.emit(bytes([ch & 0xFF]))
        return ch & 0xFF, 1

    def _api_scanf(self) -> Tuple[int, int]:
        """scanf(fmt, ...)：把 stdin 里的输入填到指针参数里，返回成功赋值个数。"""
        (fmt,) = self.args(1)
        spec = self.read_cstr(fmt)
        rest = self.args(6)
        filled = 0
        arg_i = 1
        i = 0
        while i < len(spec):
            if spec[i:i + 1] != b"%":
                i += 1
                continue
            i += 1
            while i < len(spec) and spec[i:i + 1] in b"*0123456789hlL":
                width_star = spec[i:i + 1] == b"*"
                if width_star:
                    arg_i += 1
                i += 1
            if i >= len(spec):
                break
            conv = spec[i:i + 1]
            i += 1
            ptr = rest[arg_i] if arg_i < len(rest) else 0
            arg_i += 1
            if not ptr:
                break
            if conv == b"s":
                self.write_cstr(ptr, self._next_token())
                filled += 1
            elif conv == b"c":
                token = self.stdin[self.stdin_pos:self.stdin_pos + 1]
                self.stdin_pos += 1
                self.uc.mem_write(ptr, token or b"\x00")
                filled += 1
            elif conv in (b"d", b"i", b"u", b"x", b"X"):
                token = self._next_token()
                try:
                    value = int(token or b"0", 0 if conv in (b"i", b"x", b"X") else 10)
                except ValueError:
                    value = 0
                self.uc.mem_write(ptr, struct.pack("<i" if self.bits == 32 else "<q",
                                                   value))
                filled += 1
            elif conv in (b"f", b"g", b"e"):
                token = self._next_token()
                try:
                    value = float(token or b"0")
                except ValueError:
                    value = 0.0
                self.uc.mem_write(ptr, struct.pack("<d", value))
                filled += 1
            else:
                self._next_token()
        return filled, arg_i

    def _api_gets(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        line = self._next_line()
        self.write_cstr(ptr, line)
        return ptr, 1

    def _api_fgets(self) -> Tuple[int, int]:
        ptr, _size, _stream = self.args(3)
        line = self._next_line(keep_newline=True)
        self.write_cstr(ptr, line)
        return ptr, 3

    def _api_read(self) -> Tuple[int, int]:
        _fd, buf, count = self.args(3)
        data = self.stdin[self.stdin_pos:self.stdin_pos + count]
        self.stdin_pos += len(data)
        if data:
            self.uc.mem_write(buf, data)
        return len(data), 3

    # ---------------------------------------------------- 微软 CRT 的 stdio 胶水
    # 这一组是关键：很多 MinGW/MSVC 程序会先 `__iob_func()` 拿到 FILE* 数组、
    # 再对它加锁、setvbuf、fputs。**如果这几个 API 返回 0，程序就会拿着空指针
    # 去写 [FILE*+0x18]，模拟直接崩**（实测 R07 就死在 `or dword[bx+18],0x8000`）。
    def _iob(self) -> int:
        if getattr(self, "_iob_addr", 0):
            return self._iob_addr
        self._iob_addr = self._heap(3 * 0x60)          # stdin / stdout / stderr
        self.uc.mem_write(self._iob_addr, b"\x00" * (3 * 0x60))
        for i in range(3):
            # _flag 低位标记为已分配（0x0001）+ 设备类型，够糊弄 setvbuf/加锁逻辑
            self.uc.mem_write(self._iob_addr + i * 0x60 + 0x18,
                              struct.pack("<I", 0x40))
        return self._iob_addr

    def _api___iob_func(self) -> Tuple[int, int]:
        return self._iob(), 0

    def _api__iob(self) -> Tuple[int, int]:
        return self._iob(), 0

    def _api___acrt_iob_func(self) -> Tuple[int, int]:
        (index,) = self.args(1)
        return self._iob() + max(0, min(2, index)) * 0x60, 1

    def _api__lock(self) -> Tuple[int, int]:
        return 0, 1

    def _api__unlock(self) -> Tuple[int, int]:
        return 0, 1

    def _api_setvbuf(self) -> Tuple[int, int]:
        return 0, 4

    def _api_fflush(self) -> Tuple[int, int]:
        return 0, 1

    def _api_fclose(self) -> Tuple[int, int]:
        return 0, 1

    def _api_fwrite(self) -> Tuple[int, int]:
        buf, size, count, _stream = self.args(4)
        total = size * count
        data = b""
        try:
            data = bytes(self.uc.mem_read(buf, total))
        except Exception:
            pass
        self.emit(data)
        return count, 4

    def _api_fread(self) -> Tuple[int, int]:
        buf, size, count, _stream = self.args(4)
        total = size * count
        data = self.stdin[self.stdin_pos:self.stdin_pos + total]
        self.stdin_pos += len(data)
        if data:
            self.uc.mem_write(buf, data)
        return (len(data) // size) if size else 0, 4

    def _api___stdio_common_vfprintf(self) -> Tuple[int, int]:
        """UCRT 的 printf 内核：``(options, stream, format, locale, arglist)``。

        MSVC 编译的题目里 ``printf`` 会内联成对它的一次调用，所以必须实现；
        ``arglist`` 在 x64 上是"溢出参数区"的指针（前 4 个整型参数已用寄存器传走，
        变参从第 5 个开始压在这个区域里），所以按 8 字节步进取值即可。
        """
        _options, _stream, fmt, _locale, arglist = self.args(5)
        text, _used = self._format_from_va(self.read_cstr(fmt), arglist)
        self.emit(text)
        return len(text), 5

    def _format_from_va(self, fmt: bytes, va: int) -> Tuple[bytes, int]:
        out = bytearray()
        i = 0
        offset = 0
        while i < len(fmt):
            ch = fmt[i:i + 1]
            if ch != b"%":
                out += ch
                i += 1
                continue
            i += 1
            if i < len(fmt) and fmt[i:i + 1] == b"%":
                out += b"%"
                i += 1
                continue
            while i < len(fmt) and fmt[i:i + 1] in b"-+ #0123456789.*":
                i += 1
            while i < len(fmt) and fmt[i:i + 1] in b"hlLqjzt":
                i += 1
            spec = fmt[i:i + 1]
            i += 1
            if not spec:
                break
            value = 0
            if va:
                try:
                    value = struct.unpack("<Q", self.uc.mem_read(va + offset, 8))[0]
                except Exception:
                    value = 0
            offset += 8
            if spec == b"s":
                out += self.read_cstr(value)
            elif spec in (b"d", b"i"):
                signed = value - (1 << 64) if value >> 63 else value
                out += str(signed).encode()
            elif spec == b"u":
                out += str(value & 0xFFFFFFFF).encode()
            elif spec in (b"x", b"X"):
                text = f"{value & 0xFFFFFFFF:x}"
                out += (text.upper() if spec == b"X" else text).encode()
            elif spec == b"c":
                out += bytes([value & 0xFF])
            else:
                out += b"?" + spec
        return bytes(out), offset

    def _api__errno(self) -> Tuple[int, int]:
        """`_errno()`/`__errno()` 返回的是**指向 int 的指针**，不能返回 0。

        踩过的坑：返回 0 之后程序立刻 `mov r15d, [rax]` 解引用空指针，模拟直接崩。
        """
        if not getattr(self, "_errno_addr", 0):
            self._errno_addr = self._heap(16)
            self.uc.mem_write(self._errno_addr, b"\x00" * 16)
        return self._errno_addr, 0

    def _api___errno(self) -> Tuple[int, int]:
        return self._api__errno()

    def _api__p___errno(self) -> Tuple[int, int]:
        return self._api__errno()

    def _api___p___errno(self) -> Tuple[int, int]:
        return self._api__errno()

    def _api_GetCurrentProcess(self) -> Tuple[int, int]:
        return 0xFFFFFFFFFFFFFFFF if self.bits == 64 else 0xFFFFFFFF, 0

    def _api_GetCurrentThreadId(self) -> Tuple[int, int]:
        return 1, 0

    def _api_GetCurrentProcessId(self) -> Tuple[int, int]:
        return 0x1234, 0

    def _api_strcspn(self) -> Tuple[int, int]:
        """`strcspn(s, reject)`：返回 s 开头连续**不含** reject 里任一字符的长度。

        这个函数在逆向题里出现频率极高（``buf[strcspn(buf, "\\n")] = 0`` 是标配写法），
        而它一旦没实现、返回 0，程序就会把 ``buf[0]`` 置零 → 长度判成 0 → 直接走失败分支。
        （实测 R07 就卡在这里：明明输入长度对，却一直打印 "Nope."）
        """
        s, reject = self.args(2)
        data = self.read_cstr(s)
        bad = set(self.read_cstr(reject))
        for i, ch in enumerate(data):
            if ch in bad:
                return i, 2
        return len(data), 2

    def _api_strspn(self) -> Tuple[int, int]:
        s, accept = self.args(2)
        data = self.read_cstr(s)
        good = set(self.read_cstr(accept))
        for i, ch in enumerate(data):
            if ch not in good:
                return i, 2
        return len(data), 2

    def _api_strpbrk(self) -> Tuple[int, int]:
        s, accept = self.args(2)
        data = self.read_cstr(s)
        good = set(self.read_cstr(accept))
        for i, ch in enumerate(data):
            if ch in good:
                return s + i, 2
        return 0, 2

    def _api_strrchr(self) -> Tuple[int, int]:
        s, ch = self.args(2)
        data = self.read_cstr(s)
        idx = data.rfind(bytes([ch & 0xFF]))
        return (s + idx) if idx >= 0 else 0, 2

    def _api_strncat(self) -> Tuple[int, int]:
        dst, src, n = self.args(3)
        cur = self.read_cstr(dst)
        self.write_cstr(dst, cur + self.read_cstr(src, n)[:n])
        return dst, 3

    def _api_tolower(self) -> Tuple[int, int]:
        (ch,) = self.args(1)
        return (ch + 32) if 65 <= ch <= 90 else ch, 1

    def _api_toupper(self) -> Tuple[int, int]:
        (ch,) = self.args(1)
        return (ch - 32) if 97 <= ch <= 122 else ch, 1

    def _api_isdigit(self) -> Tuple[int, int]:
        (ch,) = self.args(1)
        return 1 if 48 <= ch <= 57 else 0, 1

    def _api_isalpha(self) -> Tuple[int, int]:
        (ch,) = self.args(1)
        return 1 if (65 <= ch <= 90 or 97 <= ch <= 122) else 0, 1

    def _api_HeapCreate(self) -> Tuple[int, int]:
        """返回一个**非 0 的假堆句柄**。

        踩过的坑：早期版本让 HeapCreate 返回 0，结果 CRT 拿着 0 句柄继续往下走，
        执行流跑飞到了栈上（RIP 变成 0x2f6a）并报 UC_ERR_MAP。
        对模拟器来说，句柄的实际值不重要，"非 0 且稳定"才重要。
        """
        return 0x00500000, 3

    def _api_GetProcessHeap(self) -> Tuple[int, int]:
        return 0x00500000, 0

    def _api_HeapAlloc(self) -> Tuple[int, int]:
        _heap, _flags, size = self.args(3)
        return self._heap(max(16, size)), 3

    def _api_HeapReAlloc(self) -> Tuple[int, int]:
        _heap, _flags, _ptr, size = self.args(4)
        return self._heap(max(16, size)), 4

    def _api_HeapFree(self) -> Tuple[int, int]:
        return 1, 3

    def _api_HeapDestroy(self) -> Tuple[int, int]:
        return 1, 1

    def _api_GetVersionExA(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        if ptr:
            self.uc.mem_write(ptr, struct.pack("<IIII", 0x9C, 6, 1, 7601))
        return 1, 1

    # ---------------------------------------------------- 启动链/同步/TLS 类
    # 这一组是"程序能不能活过启动阶段"的关键：CRT 与 MFC/Qt 的初始化会挨个调它们，
    # 任何一个返回 0 都可能让程序直接 exit(255)（实测 CM2012.exe 就死在
    # GetModuleFileNameA 返回 0 之后）。
    def _api_GetModuleFileNameA(self) -> Tuple[int, int]:
        _h, buf, size = self.args(3)
        path = b"C:\\crackme.exe\x00"
        if buf:
            self.uc.mem_write(buf, path[:max(1, size)])
        return len(path) - 1, 3

    def _api_GetModuleFileNameW(self) -> Tuple[int, int]:
        _h, buf, size = self.args(3)
        path = "C:\\crackme.exe\x00".encode("utf-16-le")
        if buf:
            self.uc.mem_write(buf, path[:max(1, size * 2)])
        return len(path) // 2 - 1, 3

    def _api_GetCommandLineW(self) -> Tuple[int, int]:
        line = " ".join(["prog.exe"] + [a for a in self.argv]) + "\x00"
        raw = line.encode("utf-16-le")
        addr = self._heap(len(raw))
        self.uc.mem_write(addr, raw)
        return addr, 0

    def _api_GetModuleHandleW(self) -> Tuple[int, int]:
        return getattr(self.image, "image_base", 0x400000), 1

    def _api_LoadLibraryExW(self) -> Tuple[int, int]:
        return getattr(self.image, "image_base", 0x400000), 3

    def _api_LoadLibraryExA(self) -> Tuple[int, int]:
        return getattr(self.image, "image_base", 0x400000), 3

    def _api_IsProcessorFeaturePresent(self) -> Tuple[int, int]:
        """一律回答"没有这个特性"（0）。

        为什么不能返回 1：这个 API 是**反调试/反模拟的常用开关**。实测看雪 CTF 2019q2
        第一题《神秘来信》就是这样——它问 `IsProcessorFeaturePresent(0x17)`，
        **一旦返回非零就执行 `int 0x29`（Windows 的 `__fastfail`，直接让进程异常终止）**，
        调试器/模拟器不好接。返回 0 就走普通路径，题目逻辑得以继续。
        这也与"模拟环境尽量朴素"的原则一致：假装自己是一台没有这些新特性的老机器。
        """
        (feature,) = self.args(1)
        self.note(f"IsProcessorFeaturePresent(0x{feature:x}) → 0"
                  f"（假装没有该特性；某些题会拿它当反调试开关）")
        return 0, 1

    def _api_GetSystemTimeAsFileTime(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        if ptr:
            self.uc.mem_write(ptr, struct.pack("<Q", 0x01D0000000000000))
        return 0, 1

    def _api_InitCommonControls(self) -> Tuple[int, int]:
        return 0, 0

    def _api_InitCommonControlsEx(self) -> Tuple[int, int]:
        return 1, 1

    def _api_EventRegister(self) -> Tuple[int, int]:
        """ETW 的 `EventRegister(ProviderId, EnableCallback, Context, RegHandle*)`。

        模拟环境里没有 ETW，但**必须给一个非零句柄并返回 ERROR_SUCCESS(0)**：
        程序会把 `*RegHandle` 存起来、后面当参数传给别的 API；
        返回 0 的话它拿着 NULL 继续走，很快就会崩在别处（实测看雪第一题 689 条时卡这里）。
        """
        _provider, _callback, _context, handle = self.args(4)
        if handle:
            try:
                self.uc.mem_write(handle, struct.pack("<I", 0x4554))
            except Exception:
                pass
        return 0, 4

    def _api_EventUnregister(self) -> Tuple[int, int]:
        return 0, 1

    def _api_EventSetInformation(self) -> Tuple[int, int]:
        return 0, 4

    def _api_EventWriteTransfer(self) -> Tuple[int, int]:
        return 0, 8

    def _api_EventActivityIdControl(self) -> Tuple[int, int]:
        return 0, 2

    def _api_EventEnabled(self) -> Tuple[int, int]:
        return 0, 2

    def _api_EventWrite(self) -> Tuple[int, int]:
        return 0, 5

    def _api_FlsAlloc(self) -> Tuple[int, int]:
        """FLS（fiber-local storage）：MSVC 的线程安全静态初始化会用它。

        模拟环境只有一个"线程"，所以直接给一个自增索引 + 一张表即可；
        **绝不能返回 0**（0 是合法索引，但也是"失败"的表示；更要紧的是不实现会返回 0，
        程序拿它当句柄继续用，后面读到的就是垃圾）。
        """
        table = getattr(self, "_fls_table", None)
        if table is None:
            table = self._fls_table = {}
        index = len(table) + 1
        table[index] = 0
        return index, 1

    def _api_FlsGetValue(self) -> Tuple[int, int]:
        (index,) = self.args(1)
        return getattr(self, "_fls_table", {}).get(index, 0), 1

    def _api_FlsSetValue(self) -> Tuple[int, int]:
        index, value = self.args(2)
        if not hasattr(self, "_fls_table"):
            self._fls_table = {}
        self._fls_table[index] = value
        return 1, 2

    def _api_FlsFree(self) -> Tuple[int, int]:
        (index,) = self.args(1)
        getattr(self, "_fls_table", {}).pop(index, None)
        return 1, 1

    def _api_InitializeCriticalSectionEx(self) -> Tuple[int, int]:
        """``BOOL InitializeCriticalSectionEx(cs, dwSpinCount, Flags)`` —— 返回 TRUE。

        为什么必须实现它、而不能"未实现就返回 0"：MSVC 的 C++ 运行时会用
        ``GetProcAddress`` **动态解析**这个 API，拿到 0 之后程序会把它当函数指针存起来，
        稍后 ``call`` 那个 NULL——表现成"执行流进入低地址 0x0"，误导性极强
        （实测看雪第一题：1343 条指令后卡在这里）。临界区在模拟环境里不需要真的同步，
        把结构体清零、返回成功即可。
        """
        ptr, _spin, _flags = self.args(3)
        if ptr:
            self.uc.mem_write(ptr, b"\x00" * 40)
        return 1, 3

    def _api_InitializeCriticalSectionAndSpinCount(self) -> Tuple[int, int]:
        ptr, _spin = self.args(2)
        if ptr:
            self.uc.mem_write(ptr, b"\x00" * 40)
        return 1, 2

    def _api_TryEnterCriticalSection(self) -> Tuple[int, int]:
        return 1, 1                    # 模拟环境里永远"立刻拿到锁"

    def _api_InitializeCriticalSection(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        if ptr:
            self.uc.mem_write(ptr, b"\x00" * 24)
        return 0, 1

    def _api_DeleteCriticalSection(self) -> Tuple[int, int]:
        return 0, 1

    def _api_EnterCriticalSection(self) -> Tuple[int, int]:
        return 0, 1

    def _api_LeaveCriticalSection(self) -> Tuple[int, int]:
        return 0, 1

    def _api_TlsAlloc(self) -> Tuple[int, int]:
        self._tls_index = getattr(self, "_tls_index", 0) + 1
        return self._tls_index, 0

    def _api_TlsGetValue(self) -> Tuple[int, int]:
        return getattr(self, "_tls_value", 0), 1

    def _api_TlsSetValue(self) -> Tuple[int, int]:
        _idx, value = self.args(2)
        self._tls_value = value
        return 1, 2

    def _api_TlsFree(self) -> Tuple[int, int]:
        return 1, 1

    def _api_GetUserDefaultLCID(self) -> Tuple[int, int]:
        return 0x409, 0

    def _api_GetThreadLocale(self) -> Tuple[int, int]:
        return 0x409, 0

    def _api_GetLocaleInfoA(self) -> Tuple[int, int]:
        _lcid, _type, buf, size = self.args(4)
        if buf and size:
            self.uc.mem_write(buf, b"en-US\x00"[:size])
        return 6, 4

    def _api_GetStringTypeW(self) -> Tuple[int, int]:
        return 1, 4

    def _api_GetStringTypeA(self) -> Tuple[int, int]:
        return 1, 5

    def _api_GetStartupInfoW(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        if ptr:
            self.uc.mem_write(ptr, b"\x00" * 104)
            self.uc.mem_write(ptr, struct.pack("<I", 104))
        return 0, 1

    def _api_HeapSize(self) -> Tuple[int, int]:
        return 0x100, 3

    def _api_GetCurrentThread(self) -> Tuple[int, int]:
        return 0xFFFFFFFE if self.bits == 32 else 0xFFFFFFFFFFFFFFFE, 0

    def _api_SetErrorMode(self) -> Tuple[int, int]:
        return 0, 1

    def _api_GetSystemTime(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        if ptr:
            self.uc.mem_write(ptr, struct.pack("<8H", 2024, 1, 1, 1, 0, 0, 0, 0))
        return 0, 1

    def _api_GetLocalTime(self) -> Tuple[int, int]:
        return self._api_GetSystemTime()

    def _api_rand(self) -> Tuple[int, int]:
        self._rand_state = (getattr(self, "_rand_state", 1) * 214013 + 2531011) & 0xFFFFFFFF
        return (self._rand_state >> 16) & 0x7FFF, 0

    def _api_srand(self) -> Tuple[int, int]:
        (seed,) = self.args(1)
        self._rand_state = seed & 0xFFFFFFFF
        return 0, 1

    def _api_time(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        if ptr:
            self.uc.mem_write(ptr, struct.pack("<i" if self.bits == 32 else "<q", 0x60000000))
        return 0x60000000, 1

    # ---------------------------------------------------- Win32
    def _api_GetStdHandle(self) -> Tuple[int, int]:
        return 0xF0, 1

    def _api_WriteFile(self) -> Tuple[int, int]:
        _h, buf, count, written, _ov = self.args(5)
        data = b""
        try:
            data = bytes(self.uc.mem_read(buf, count))
        except Exception:
            pass
        self.emit(data)
        if written:
            self.uc.mem_write(written, struct.pack("<I", len(data)))
        return 1, 5

    def _api_WriteConsoleA(self) -> Tuple[int, int]:
        _h, buf, count, written, _r = self.args(5)
        data = b""
        try:
            data = bytes(self.uc.mem_read(buf, count))
        except Exception:
            pass
        self.emit(data)
        if written:
            self.uc.mem_write(written, struct.pack("<I", len(data)))
        return 1, 5

    def _api_WriteConsoleW(self) -> Tuple[int, int]:
        _h, buf, count, written, _r = self.args(5)
        data = b""
        try:
            data = bytes(self.uc.mem_read(buf, count * 2))
        except Exception:
            pass
        text = data.decode("utf-16-le", "replace")
        self.emit(text.encode("utf-8"))
        if written:
            self.uc.mem_write(written, struct.pack("<I", count))
        return 1, 5

    def _api_ReadFile(self) -> Tuple[int, int]:
        _h, buf, count, read_ptr, _ov = self.args(5)
        data = self.stdin[self.stdin_pos:self.stdin_pos + count]
        self.stdin_pos += len(data)
        if data:
            self.uc.mem_write(buf, data)
        if read_ptr:
            self.uc.mem_write(read_ptr, struct.pack("<I", len(data)))
        return 1, 5

    def _api_ReadConsoleA(self) -> Tuple[int, int]:
        return self._api_ReadFile()

    def _api_GetCommandLineA(self) -> Tuple[int, int]:
        line = b" ".join([b"prog.exe"] + [a.encode() for a in self.argv]) + b"\x00"
        addr = self._heap(len(line))
        self.uc.mem_write(addr, line)
        return addr, 0

    def _api_GetModuleHandleA(self) -> Tuple[int, int]:
        return getattr(self.image, "image_base", 0x400000), 1

    def next_stub(self, name: str) -> int:
        """再要一个桩地址并登记 API 名（给 `GetProcAddress` 用）。"""
        if not getattr(self, "_extra_stub", 0):
            self._extra_stub = self._stub_base + 0x1000
            try:
                self.uc.mem_map(self._stub_base + 0x1000, 0x1000)
            except Exception:
                pass
        addr = self._extra_stub
        self._extra_stub += 16
        self._stub_of[addr] = name
        return addr

    def _api_GetProcAddress(self) -> Tuple[int, int]:
        """**把动态解析的 API 也接到桩系统上**。

        踩过的坑：早期版本直接返回 0，程序随后 `call eax` 就跳到空指针，
        执行流飘进 TEB/栈里，报出 "UC_ERR_MAP 在 0x2f2f" 这种完全看不懂的错误。
        正确做法是：拿到 API 名字符串后，**给它分配一个新的桩地址并登记名字**，
        于是 `call [GetProcAddress(...)]` 落到的就是我们能处理的桩。
        这让"运行时解析 API"的样本（很常见）也能继续跑下去。
        """
        _hmodule, name_ptr = self.args(2)
        if not name_ptr:
            return 0, 2
        if name_ptr >> 16 == 0:                       # 序号导入
            name = f"#{name_ptr & 0xFFFF}"
        else:
            name = self.read_cstr(name_ptr).decode("latin-1", "replace")
        if not name:
            return 0, 2
        return self.next_stub(name), 2

    def _api_LoadLibraryA(self) -> Tuple[int, int]:
        return getattr(self.image, "image_base", 0x400000), 1

    def _api_GetStartupInfoA(self) -> Tuple[int, int]:
        """STARTUPINFOA 是个 68 字节结构，全零就是"没有特殊设置"，够用。"""
        (ptr,) = self.args(1)
        if ptr:
            self.uc.mem_write(ptr, b"\x00" * 68)
            self.uc.mem_write(ptr, struct.pack("<I", 68))       # cb = sizeof
        return 0, 1

    def _api_GetFileType(self) -> Tuple[int, int]:
        return 2, 1                                            # FILE_TYPE_CHAR

    def _api_SetHandleCount(self) -> Tuple[int, int]:
        (count,) = self.args(1)
        return count, 1

    def _api_GetEnvironmentStrings(self) -> Tuple[int, int]:
        addr = self._heap(16)
        self.uc.mem_write(addr, b"\x00" * 16)                  # 空环境块（两个 NUL 结束）
        return addr, 0

    def _api_GetEnvironmentStringsW(self) -> Tuple[int, int]:
        return self._api_GetEnvironmentStrings()

    def _api_FreeEnvironmentStringsA(self) -> Tuple[int, int]:
        return 1, 1

    def _api_FreeEnvironmentStringsW(self) -> Tuple[int, int]:
        return 1, 1

    def _api_VirtualAlloc(self) -> Tuple[int, int]:
        """**照请求地址分配**（壳基本都靠它把原始代码搬到固定位置）。

        踩过的坑：早先版本忽略 `lpAddress`、一律从自留地里切一块，结果自解压壳
        "搬完代码却跳不到该去的地方"，14 条指令就崩。壳的搬运目标地址是写死在代码里的，
        必须尊重它：能映射就映射，撞车了才退回自留地。
        """
        addr, size, _alloc_type, _protect = self.args(4)
        size = max(0x1000, min(int(size or 0x1000), 0x8000000))
        if addr:
            base = int(addr) & ~0xFFF
            try:
                self.uc.mem_map(base, (size + 0xFFF) & ~0xFFF)
                return base, 4
            except Exception:
                pass                      # 已映射/冲突 → 退回去用自留地
        return self._heap(size), 4

    def _api_VirtualProtect(self) -> Tuple[int, int]:
        _addr, _size, _new, old = self.args(4)
        if old:
            self.uc.mem_write(old, struct.pack("<I", 0x40))
        return 1, 4

    def _api_VirtualFree(self) -> Tuple[int, int]:
        return 1, 3

    # 反调试一律返回"没有调试器"；时间一律固定，顺手废掉时间差反调试
    def _api_IsDebuggerPresent(self) -> Tuple[int, int]:
        self.note("IsDebuggerPresent → 0（已绕过反调试）")
        return 0, 0

    def _api_CheckRemoteDebuggerPresent(self) -> Tuple[int, int]:
        _h, ptr = self.args(2)
        if ptr:
            self.uc.mem_write(ptr, struct.pack("<I", 0))
        self.note("CheckRemoteDebuggerPresent → FALSE（已绕过反调试）")
        return 1, 2

    def _api_QueryPerformanceCounter(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        if ptr:
            self.uc.mem_write(ptr, struct.pack("<q", self.time_source))
        return 1, 1

    def _api_QueryPerformanceFrequency(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        if ptr:
            self.uc.mem_write(ptr, struct.pack("<q", 1000000))     # 1 MHz
        return 1, 1

    def _api_GetTickCount(self) -> Tuple[int, int]:
        return self.time_source & 0xFFFFFFFF, 0

    def _api_Sleep(self) -> Tuple[int, int]:
        return 0, 1

    def _api_GetVersion(self) -> Tuple[int, int]:
        return 0x0A000000, 0

    def _api_MessageBoxA(self) -> Tuple[int, int]:
        _h, text, caption, _type = self.args(4)
        body = self.read_cstr(text)
        title = self.read_cstr(caption)
        self.note(f"MessageBoxA({title.decode('latin-1', 'replace')!r}, "
                  f"{body.decode('latin-1', 'replace')!r})")
        self.emit(b"[MessageBox] " + title + b": " + body + b"\n")
        return 1, 4

    def _api_GetEnvironmentVariableA(self) -> Tuple[int, int]:
        return 0, 3

    def _api_CreateFileA(self) -> Tuple[int, int]:
        """返回一个**看似有效的句柄**，而不是失败。

        为什么：加壳程序启动时常用"打开/删除自己"来判断是否被调试或是否被转储，
        一旦返回失败就会走进"检测到异常环境"的分支（实测自写壳在这里停下）。
        给它一个假句柄（读操作按 EOF 处理），程序就会按正常路径继续。
        """
        return 0x1A0, 7

    def _api_CreateFileW(self) -> Tuple[int, int]:
        return self._api_CreateFileA()

    def _api_DeleteFileA(self) -> Tuple[int, int]:
        return 1, 1                        # 假装删成功（不改真实文件）

    def _api_CreateMutexA(self) -> Tuple[int, int]:
        return 0x1B0, 3

    def _api_CreateMutexW(self) -> Tuple[int, int]:
        return self._api_CreateMutexA()

    def _api_OpenMutexA(self) -> Tuple[int, int]:
        return 0x1B0, 3

    def _api_ReleaseMutex(self) -> Tuple[int, int]:
        return 1, 1

    def _api_CloseHandle(self) -> Tuple[int, int]:
        return 1, 1

    def _api_GetFileSize(self) -> Tuple[int, int]:
        """假装文件是 0 字节：让"读自己"的代码拿到 EOF 而不是崩。"""
        _h, high = self.args(2)
        if high:
            self.uc.mem_write(high, struct.pack("<I", 0))
        return 0, 2

    def _api_SetFilePointer(self) -> Tuple[int, int]:
        return 0, 4

    def _api_GetFileAttributesA(self) -> Tuple[int, int]:
        return 0x80, 1                     # FILE_ATTRIBUTE_NORMAL

    def _api_WriteProcessMemory(self) -> Tuple[int, int]:
        return 0, 5

    def _api_GetThreadContext(self) -> Tuple[int, int]:
        return 0, 2

    def _api_OutputDebugStringA(self) -> Tuple[int, int]:
        (ptr,) = self.args(1)
        text = self.read_cstr(ptr)
        if text:
            self.note(f"OutputDebugString: {text[:60]!r}")
        return 0, 1

    def _api_TerminateProcess(self) -> Tuple[int, int]:
        _h, code = self.args(2)
        raise _ExitRequested(code & 0xFF)

    # ---------------------------------------------------- ELF 侧常用
    def _api_puts_elf(self) -> Tuple[int, int]:
        return self._api_puts()

    def _api___libc_start_main(self) -> Tuple[int, int]:
        """glibc 的启动函数：直接调用 main(argc, argv) 再退出（ELF 动态链接时才用）。"""
        main, argc, argv = self.args(3)
        self.note("__libc_start_main：直接调用 main")
        self._pending_main = (main, argc, argv)
        raise _ExitRequested(0)
