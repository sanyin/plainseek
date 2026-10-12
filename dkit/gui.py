"""GUI CrackMe 的"自动判定"辅助：让程序自己判对错，宿主只负责喂输入。

## 为什么需要这个模块

上一轮（吾爱 2012CM ying5567890）是**手工**做成的：

1. 找到"读输入"的调用点（`GetWindowTextA`）→ 定位它所在的函数；
2. 从**函数入口**调用（不能从中间进去：外面套着 `pushal … popal`，`popal` 会弹出垃圾 EBP）；
3. 用 `pre_write` 摆好全局缓冲、用 `api_setup` 把 `GetWindowTextA` 换成"返回我们想试的输入"；
4. 喂两个不同输入，**看程序最后把哪条提示语交给了文本类 API**
   （成功分支 vs 失败分支），由此得到"程序自己给出的判定"。

这套方法跟具体题目无关，可以自动化。本模块就是它的封装。

## 关键设计

* **判定靠"提示语"**：几乎每个 CrackMe 都有成功/失败文案（`congratulation`、
  `success`、`correct` / `wrong`、`try again`、`error`，中文 `成功`/`失败`/`恭喜`）。
  把"任何把字符串交给 UI/输出 API 的调用"都插上探针，就能读出它在说什么。
* **入口要猜**：GUI 程序的校验可能在窗口过程里（需要消息参数），也可能在按钮处理函数里。
  所以 `candidate_entries()` 会给出若干个候选入口 + 若干组参数，`discover()` 逐个试。
* **"可用判定"的定义**：同一个入口下，**两个不同输入给出不同结论**（一个成功一个失败）
  才算真的找到了校验——只报"成功"或只报"失败"的入口多半是假信号。
"""

from __future__ import annotations

import struct
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import emu, pe

#: 成功/失败文案关键词（小写比较）。中文字符串按 GBK 编码参与匹配。
SUCCESS_WORDS = (
    b"congrat", b"success", b"correct", b"right", b"passed", b"welldone",
    b"well done", b"great", b"good job", b"accepted", b"valid",
    "成功".encode("gbk"), "正确".encode("gbk"), "恭喜".encode("gbk"),
    "通过".encode("gbk"),
)
FAILURE_WORDS = (
    b"wrong", b"fail", b"error", b"try again", b"incorrect", b"invalid",
    b"nope", b"denied", b"sorry",
    "失败".encode("gbk"), "错误".encode("gbk"), "不正确".encode("gbk"),
    "重试".encode("gbk"),
)

#: 会把字符串拿出去的 API（都要插探针）。名字用"去掉下划线后小写"比较，避免
#: 32/64 位、ANSI/宽字符两套名字漏掉。
TEXT_API_HINTS = (
    "messagebox", "setwindowtext", "setdlgitemtext", "sendmessage",
    "senddlgitemmessage", "printf", "sprintf", "wsprintf", "puts", "putchar",
    "writeconsole", "writefile", "fputs", "fwrite", "outputdebugstring",
    "settimer", "showwindow", "playsound", "mciSendString",
)

#: 读输入的 API
INPUT_API_HINTS = ("getwindowtext", "getdlgitemtext", "getwindowtextlength",
                   "getdlgitemtextlength")


def _norm(name: str) -> str:
    return (name or "").lower().replace("_", "").replace("@", "")


def classify_text(text: bytes) -> Optional[str]:
    """把一段程序输出的文本判成 ``"success"`` / ``"failure"`` / ``None``。"""
    if not text:
        return None
    low = text.lower()
    # 失败词优先：很多程序里"Error: success"这种混搭极少见，但 "not correct" 很常见
    for word in FAILURE_WORDS:
        if word.lower() in low:
            return "failure"
    for word in SUCCESS_WORDS:
        if word.lower() in low:
            return "success"
    return None


def candidate_entries(img) -> List[Tuple[int, str]]:
    """猜"校验代码可能所在的函数入口"。

    线索（按可信度排序）：
    1. 引用了成功/失败文案的函数（`string_xrefs` → 回溯函数起点）；
    2. 调用 `GetWindowText*` / `GetDlgItemText*` 的函数（校验通常紧跟着读输入）；
    3. 引用了 `DialogBoxParam*` 的函数（对话框题的窗口过程）。
    """
    starts: Dict[int, str] = {}

    def add(addr: int, why: str) -> None:
        fn = img.function_of(addr)
        if not fn:
            return
        start = fn[0]
        if start and start not in starts:
            starts[start] = why

    for word in SUCCESS_WORDS + FAILURE_WORDS:
        for at in pe.string_xrefs(img, word)[:6]:
            add(at, f"引用了 {word[:12]!r}")

    # 关键词扫描**自己做**，不用 `crackme.interesting_strings`：
    # 后者为了降噪会跳过可执行节，而有些程序（尤其自己拼出来的 PE、或者把字符串
    # 混在代码段里的题）文案就在可执行节里。这里对整个镜像做**大小写不敏感**扫描，
    # 再用"命中的原始字节"去找引用点（`pe.string_xrefs` 是大小写敏感的）。
    import re as _re
    seen_words = set()
    for word in SUCCESS_WORDS + FAILURE_WORDS:
        pattern = _re.compile(_re.escape(word), _re.IGNORECASE)
        hits = 0
        for sec in img.segments:
            data = sec.data or b""
            if not data:
                continue
            for match in pattern.finditer(data):
                exact = match.group(0)
                if exact in seen_words:
                    continue
                seen_words.add(exact)
                for at in pe.string_xrefs(img, exact)[:4]:
                    add(at, f"引用了 {exact[:14]!r}")
                hits += 1
                if hits >= 3:
                    break
            if hits >= 3:
                break

    for imp in getattr(img, "imports", []) or []:
        name = _norm(imp.name)
        if any(h.lower() in name for h in INPUT_API_HINTS):
            from . import crackme
            for at in crackme.find_callers_of_import(img, imp.name,
                                                     include_thunk=False):
                add(at, f"调用了 {imp.name}")
        if "dialogboxparam" in name:
            from . import crackme
            for at in crackme.find_callers_of_import(img, imp.name,
                                                     include_thunk=False):
                add(at, f"引用了 {imp.name}")
    return sorted(starts.items())


def _read_both(api, ptr: int) -> List[bytes]:
    """从一个指针同时尝试读**窄字符**和**宽字符（UTF-16LE）**字符串。

    为什么必须都试：Windows GUI 的文案常常是宽字符（尤其资源里加载出来的），
    只按 C 字符串读会得到一连串"单字母 + NUL"，长度不足被丢掉，
    于是"程序明明说了 congratulation，探针却什么都没抓到"
    （实测 ying5567890 就栽在这里：文件里搜不到 ASCII 的 congratulation）。
    """
    out: List[bytes] = []
    try:
        raw = bytes(api.uc.mem_read(ptr, 128))
    except Exception:
        return out
    narrow = raw.split(b"\x00")[0]
    if len(narrow) >= 3:
        out.append(narrow)
    wide = bytearray()
    for i in range(0, len(raw) - 1, 2):
        lo, hi = raw[i], raw[i + 1]
        if hi == 0 and 32 <= lo < 127:
            wide.append(lo)
        else:
            break
    if len(wide) >= 3:
        out.append(bytes(wide))
    return out


def string_verdict_map(img) -> Dict[int, str]:
    """把程序里所有"成功/失败文案"的**地址**收集起来：``{地址: 'success'/'failure'}``。

    为什么要这条信号：很多 GUI 程序的成功文案是**运行时从资源加载**的（全局指针初值为 0），
    所以"读它传给 UI 的文本"什么都读不到（实测 ying5567890 就是：
    文件里根本没有 ASCII/UTF-16 的 `congratulation`）。但只要它把某个
    成功/失败文案的**地址**当参数传出去，我们就能据此判定——这比读文本更通用。
    """
    from . import crackme
    out: Dict[int, str] = {}
    try:
        items = crackme.interesting_strings(img, limit=500)
    except Exception:
        return out
    for addr, text, _enc in items:
        verdict = classify_text(text.encode("latin-1", "ignore"))
        if verdict:
            out[addr] = verdict
    return out


def _install_spies(api, collected: List[bytes], input_bytes: Optional[bytes],
                   input_length: bool = True,
                   verdict_map: Optional[Dict[int, str]] = None,
                   verdicts: Optional[List[str]] = None) -> None:
    """给文本类 API 插探针；把读输入的 API 换成"返回我们想试的输入"。"""
    verdict_map = verdict_map or {}
    verdicts = verdicts if verdicts is not None else []

    def record(text: bytes) -> None:
        if text:
            collected.append(text)

    for name in dir(api):
        if not name.startswith("_api_"):
            continue
        api_name = _norm(name[5:])
        if any(h.lower() in api_name for h in TEXT_API_HINTS):
            def make_spy(orig, nargs_hint=None):
                def spy():
                    args = api.args(nargs_hint or 4)
                    for value in args:
                        # 信号一：参数本身就是"成功/失败文案的地址"
                        if value in verdict_map:
                            verdicts.append(verdict_map[value])
                        # 信号二：参数是指向文本的指针，读出来判（窄+宽都试）
                        for text in _read_both(api, value):
                            record(text)
                            got = classify_text(text)
                            if got:
                                verdicts.append(got)
                    try:
                        return orig()
                    except Exception:
                        return 0, nargs_hint or 4
                return spy
            setattr(api, name, make_spy(getattr(api, name)))

    if input_bytes is not None:
        data = input_bytes

        def fake_get_text():
            # GetWindowTextA(hwnd, buf, max) / GetDlgItemTextA(hwnd, id, buf, max)
            args = api.args(4)
            buf = args[1] if len(args) > 1 else 0
            try:
                api.uc.mem_write(buf, data + b"\x00")
            except Exception:
                pass
            return (len(data) if input_length else 0), len(args) or 3

        for attr in ("_api_GetWindowTextA", "_api_GetWindowTextW",
                     "_api_GetDlgItemTextA"):
            if hasattr(api, attr):
                setattr(api, attr, fake_get_text)

    # 命中测试要能通过（否则走不到校验）：矩形 0,0,200,200 / 光标在内部
    if hasattr(api, "_api_GetWindowRect"):
        api._api_GetWindowRect = lambda: (
            api.uc.mem_write(api.args(2)[1], struct.pack("<iiii", 0, 0, 200, 200)),
            1, 2)[1:]
    if hasattr(api, "_api_GetCursorPos"):
        api._api_GetCursorPos = lambda: (
            api.uc.mem_write(api.args(1)[0], struct.pack("<ii", 100, 100)), 1, 1)[1:]


def judge(img, entry: int, args: Sequence[int], input_bytes: bytes,
          max_ins: int = 200000) -> Dict[str, object]:
    """在某个入口下喂一个输入，返回程序给出的判定。

    返回 ``{"verdict": "success"/"failure"/None, "texts": [...], "stop": ..., }``
    """
    collected: List[bytes] = []
    verdicts: List[str] = []
    vmap = string_verdict_map(img)

    def setup(api):
        _install_spies(api, collected, input_bytes, verdict_map=vmap,
                       verdicts=verdicts)

    res = emu.run_function(img, entry, args=list(args), max_ins=max_ins,
                           api_setup=setup, snapshot=False,
                           stdin=input_bytes + b"\n")
    verdicts += [v for v in (classify_text(t) for t in collected) if v]
    verdict = None
    # 只要出现失败判定就算失败（校验类程序通常"先过一堆检查，任一条不过就报错"）
    if "failure" in verdicts:
        verdict = "failure"
    elif "success" in verdicts:
        verdict = "success"
    return {"verdict": verdict, "texts": collected[:8], "stop": res.get("stop"),
            "ins": res.get("ins"), "coverage": res.get("coverage") or set()}


def discover(img, inputs: Optional[Sequence[bytes]] = None,
             arg_sets: Optional[Sequence[Sequence[int]]] = None,
             max_ins: int = 200000, limit: int = 24
             ) -> List[Dict[str, object]]:
    """自动找"可用的判定"：某入口下**两个不同输入给出不同结论**才算数。

    这条标准很重要——只报成功、或只报失败的入口往往是假信号（比如程序启动就把
    失败文案写进状态栏）。两个输入都能给出**不同**结论，才说明我们真的碰到了校验逻辑。
    """
    if inputs is None:
        inputs = [b"A" * 16, b"52pojie", b"123456", b"a" * 8 + b"1",
                  "test1234".encode(), b"0" * 12]
    if arg_sets is None:
        arg_sets = [(0x10001, 0x201, 0, 0),      # WM_LBUTTONDOWN
                    (0x10001, 0x111, 0x3ec, 0),  # WM_COMMAND / 按钮
                    (0x10001, 0x111, 1, 0),
                    (0x10001, 0x110, 0, 0),      # WM_INITDIALOG
                    (0,),                        # 无参函数
                    (0x10001,)]
    found: List[Dict[str, object]] = []
    for entry, why in candidate_entries(img)[:limit]:
        for args in arg_sets:
            verdicts = []
            for data in inputs[:3]:
                try:
                    out = judge(img, entry, args, data, max_ins=max_ins)
                except Exception:
                    verdicts = []
                    break
                verdicts.append(out["verdict"])
            distinct = {v for v in verdicts if v}
            if len(distinct) >= 2:
                found.append({"entry": entry, "why": why, "args": list(args),
                              "verdicts": verdicts})
                break
    return found


def report(img, limit: int = 24) -> str:
    lines = ["【GUI 题自动判定辅助】"]
    entries = candidate_entries(img)
    if not entries:
        lines.append("  没找到可能的校验入口（可能不是 GUI 题，或字符串被加密了）")
        return "\n".join(lines)
    lines.append(f"  可能的校验入口 {len(entries)} 个（前 {min(limit, len(entries))} 个）：")
    for start, why in entries[:limit]:
        lines.append(f"    0x{start:x}  ← {why}")
    lines.append("  用 `gui --discover` 可以逐个试，看哪个入口能让程序自己判对错")
    return "\n".join(lines)
