"""triage —— 逆向题的"指路"层。

## 为什么需要它

这个工具原来会干活（扫描、脱壳、模拟执行、静态定位各有命令），但**不会指路**：
拿到一个陌生样本，人得自己决定"先 sig 还是先 crackme、是不是要先脱壳、这题到底能不能碰"。
真实使用中我在 2026 春节题包上把同一套判断手工做了五遍，五次顺序还不一样。

`triage` 就是把那套判断固化成一条命令：**侦察一遍，然后给出排好序的下一步该敲什么**。

## 它给什么

1. **身份**：PE/ELF、位数、子系统（控制台/GUI）、入口、节数；
2. **外壳**：UPX（能自己脱）还是别的（只能告诉你该上 x64dbg/Scylla）；
3. **语言/运行时**：MSVC C++、Go、Rust、.NET、Delphi、AutoIt、Electron、PyInstaller、易语言……
   —— 这决定"这题在不在工具射程内"，.NET 会直接劝你去 dnSpy；
4. **加密常量**：AES S 盒 / MD5 IV / TEA delta 之类，附偏移；
5. **成败文案**：程序自己打印的 SUCCESS/WRONG，这是"让它自己判对错"的抓手；
6. **输入通道**：stdin / argv / GUI 编辑框 / 文件；
7. **下一步**：按优先级排的命令清单，每条都带"为什么"。

## 它不给什么

**不猜答案**。triage 只产出"线索 + 路线"，一个候选明文都不会凭空造出来——
那是 `auto` / `emu --run` / `gui --discover` 的活。这样划分是为了让"工具说的每句话都有出处"。
"""

from __future__ import annotations

import os
import struct
from typing import Dict, List, Optional, Sequence, Tuple

from . import crackme, emu, gui, pe, sigscan, unpack

# ---------------------------------------------------------------------------
# 语言 / 运行时指纹：都是"便宜且不容易误判"的证据，宁可少报
# ---------------------------------------------------------------------------


def _section_names(img) -> List[str]:
    return [s.name.lower() for s in getattr(img, "sections", [])]


def _import_names(img) -> List[str]:
    return [i.name.lower() for i in getattr(img, "imports", [])]


def _import_dlls(img) -> List[str]:
    return [i.dll.lower() for i in getattr(img, "imports", [])]


def detect_runtime(img, strings: Sequence[Tuple[int, str, str]]) -> List[str]:
    """判断是用什么写的。返回人类可读的结论列表（可能多条并存）。"""
    found: List[str] = []
    text = "\n".join(s[1] for s in strings).lower()
    secs = _section_names(img)
    imports = _import_names(img)
    dlls = _import_dlls(img)

    if getattr(img, "is_dotnet", False):
        ver = getattr(img, "dotnet_version", None) or "?"
        found.append(f".NET / IL（CLR 头 v{ver}）→ **不在本工具射程**，该用 dnSpy / ILSpy")
    if any(s.startswith(".gopclntab") or s == ".go.buildinfo" for s in secs) \
            or "go build id" in text or "runtime.gopanic" in text:
        found.append("Go（.gopclntab/.go.buildinfo）→ 结构还原可做，逻辑还原建议 GoReSym / IDA")
    if "rustc" in text or "panicked at" in text or "core::panicking" in text:
        found.append("Rust（panic 文案）→ 逻辑还原建议 IDA + rust 符号恢复")
    if "pyinstaller" in text or "pyi-windowed" in text or "python3.dll" in " ".join(dlls):
        found.append("PyInstaller 打包的 Python → 先 `plainseek pyc` 找 .pyc，再 `pyc --solve`")
    if "autoit3" in text or "au3!" in text or "autoit" in " ".join(dlls):
        found.append("AutoIt → 建议 Exe2Aut / myAut2Exe 还原脚本")
    if "app.asar" in text or "electron" in text or "node.dll" in " ".join(dlls):
        found.append("Electron/Node → 建议先找 app.asar，再看 JS（本工具能扫 JS 字符串）")
    if "krnln.fnr" in text or "易语言" in text or "eapi" in text:
        found.append("易语言 → 5.x 静态分析建议 E-Code Explorer；本工具只能跑模拟执行路线")
    if "tform" in text or "borland" in text or "system@sysutils" in text:
        found.append("Delphi/C++Builder → 建议 IDA + IDR")
    if "qt5core" in " ".join(dlls) or "qt6core" in " ".join(dlls) or "qt5core" in text:
        found.append("Qt → 信号槽/字符串建议 IDA，模拟执行只适合纯算法函数")
    if "_cxthrowllexception" in " ".join(imports) or "ios_base" in text or "basic_string" in text:
        found.append("MSVC C++ 运行库（iostream/std::string）→ 需要 CRT 初始化，本工具已支持")
    if "__gxx_personality_v0" in " ".join(imports) or ".eh_frame" in secs:
        found.append("GCC/MinGW C++（.eh_frame）")
    if "mfc" in text and ("afxwininit" in " ".join(imports) or "mfc" in " ".join(dlls)):
        found.append("MFC → 界面逻辑建议 IDA，校验函数可用本工具直调")
    if not found:
        found.append("未识别出特定运行时（大概率是原生 C/C++，或加壳后看不见导入表）")
    return found


# ---------------------------------------------------------------------------
# 输入通道：决定"答案从哪个口喂进去"
# ---------------------------------------------------------------------------


def detect_input_channels(img, strings: Sequence[Tuple[int, str, str]]) -> List[str]:
    """判断程序从哪里读答案。GUI 与 stdin 的差别决定用 `gui` 还是 `emu --run`。"""
    channels: List[str] = []
    imports = _import_names(img)
    text = "\n".join(s[1] for s in strings).lower()
    if getattr(img, "subsystem", 3) == 2:
        channels.append("GUI（PE 子系统 = 2）→ 校验在按钮回调里，用 `gui --discover` 或静态定位")
    if any(n.startswith("getwindowtext") or n == "getdlgitemtexta" for n in imports):
        channels.append("GUI 编辑框（GetWindowText*）→ `gui --discover`")
    if any(n in imports for n in ("scanf", "_scanf", "fgets", "getc", "fgetc",
                                  "fread", "_read", "readfile", "getchar")):
        channels.append("stdin（scanf/fgets/getc/ReadFile）→ `emu --run --stdin \"候选\"`")
    if any(n in imports for n in ("getcommandlinea", "commandlinetoargv")) or \
            "usage" in text or "usage:" in text:
        channels.append("argv（GetCommandLine/Usage 文案）→ `emu --run` 时带 `--argv`")
    if any(n in imports for n in ("createfilea", "createfilew", "openfile")):
        channels.append("文件（CreateFile*）→ 程序可能读一个输入文件，注意它打开哪个路径")
    if not channels:
        channels.append("没看出明显输入口（可能校验内置常量、或由外部条件触发）")
    return channels


# ---------------------------------------------------------------------------
# 路线：把线索翻译成"下一步敲什么"
# ---------------------------------------------------------------------------


def _q(path: str) -> str:
    """命令里引用路径：带空格/花括号就加引号，否则复制出来会跑不通。"""
    if path in ("-", "/dev/stdin"):
        return path
    return f'"{path}"' if any(c in path for c in " {}(),&^") else path


def _next_steps(path: str, info: Dict[str, object]) -> List[Tuple[str, str]]:
    steps: List[Tuple[int, str, str]] = []          # (优先级, 命令, 为什么)
    packed = info["packed"]
    runtime = " ".join(info["runtime"])
    channels = " ".join(info["input_channels"])
    verdicts = info["verdict_strings"]
    crypto = info["crypto"]
    p = _q(path)

    if packed.get("kind") == "upx":
        steps.append((1, f"python plainseek.py unpack {p}",
                      "是 UPX：先在模拟器里脱壳（dump 出平铺镜像），脱完再对产物跑 triage"))
    elif packed.get("kind") == "other":
        steps.append((9, "# 非 UPX 壳：用 x64dbg + Scylla 手工脱，本工具对此只报证据不硬脱",
                      f"检测到 {packed.get('name')}（置信度 {packed.get('confidence')}）"))

    if ".NET" in runtime:
        steps.append((9, "# 建议 dnSpy / ILSpy：本工具不解析 IL", "这是 .NET 程序，模拟执行路线不适用"))
        return [(pri, cmd, why) for pri, cmd, why in steps]

    if "GUI" in channels:
        steps.append((2, f"python plainseek.py gui {p} --discover",
                      "GUI 题：逐个试候选校验入口，找“两个输入给出不同结论”的那个"))
    if "stdin" in channels or "argv" in channels:
        why = ("有 stdin/argv 通道：直接喂候选，看程序自己的成败文案")
        if "MSVC C++" in runtime or "GCC/MinGW" in runtime:
            why = "C++ 控制台 + stdin：CRT 初始化已支持，程序会自己判对错"
        steps.append((2, f"python plainseek.py emu {p} --run --stdin \"候选\" --max-ins 2000000", why))
    if verdicts.get("success"):
        steps.append((3, f"python plainseek.py crackme {p}",
                      f"找到 {len(verdicts['success'])} 条成功文案，静态定位它们被谁引用"))
        steps.append((3, f"python plainseek.py emu {p} --anchor \"{info['anchor_hint']}\"",
                      "从“成功文案”回溯到校验函数入口（再配合 --break 在比较点取现场）"))
    if crypto:
        names = "、".join(sorted({c["name"] for c in crypto})[:3])
        steps.append((4, f"python plainseek.py sig {p}",
                      f"命中加密常量（{names}）：先确认算法，再找密钥/密文位置"))
    if info.get("magic_hits"):
        steps.append((4, f"python plainseek.py fragments {p}",
                      f"样本里出现 {', '.join(info['magic_hits'])}，可能是密文/flag 片段"))
    steps.append((6, f"python plainseek.py crackme {p}", "静态兜底：输入点、比较点、可疑字符串"))
    steps.append((7, "python plainseek.py selftest", "先确认环境没坏（52 项），避免把工具问题当成题目问题"))

    steps.sort(key=lambda s: s[0])
    seen = set()
    out: List[Tuple[str, str]] = []
    for _pri, cmd, why in steps:
        if cmd in seen:
            continue
        seen.add(cmd)
        out.append((cmd, why))
    return out


# ---------------------------------------------------------------------------


def _tier(info: Dict[str, object]) -> Tuple[str, str]:
    """A 档 = 大概率能全自动出答案；B 档 = 必须人工判断。判定要保守。

    ⚠ 只有**低置信度**的"可能加壳"不该把题目降成 B 档：
    小体积 PE 常见 RWX 节，`detect_packer` 会以"低"置信度报"可能加壳"，
    但它并不是真壳（实测自检里那个合成 PE 就被误判过）。
    """
    runtime = " ".join(info["runtime"])
    packed = info["packed"]
    verdicts = info["verdict_strings"]
    if ".NET" in runtime:
        return "B", ".NET 不在射程，需要 dnSpy/ILSpy"
    if packed.get("kind") == "other" and packed.get("confidence") != "低":
        return "B", f"非 UPX 的壳（{packed.get('name')}），需要手工脱壳后再看"
    if packed.get("kind") == "upx":
        return "B", "先脱壳，脱完再判断（很多 UPX 样本脱壳后就是 A 档）"
    if verdicts.get("success") and verdicts.get("failure"):
        return "A", "有成败文案 + 无壳 → 可以让程序自己判对错"
    return "B", "没有明确的成败文案，判定条件要自己找"


def _cstring_at(img, addr: int, limit: int = 64) -> str:
    """从虚拟地址读一个 C 字符串（不依赖 unicorn，纯静态）。"""
    for sec in getattr(img, "sections", []):
        start = sec.vaddr
        if start <= addr < start + len(getattr(sec, "data", b"")):
            raw = sec.data[addr - start: addr - start + limit]
            raw = raw.split(b"\x00", 1)[0]
            try:
                return raw.decode("latin-1")
            except Exception:
                return ""
    return ""


def triage_blob(blob: bytes, name: str = "stdin") -> Dict[str, object]:
    """对一个样本做侦察，返回结构化结果（不打印）。"""
    info: Dict[str, object] = {
        "file": name, "size": len(blob), "kind": "未知", "bits": None,
        "subsystem": None, "entry": None, "packed": {"kind": None},
        "runtime": [], "crypto": [], "verdict_strings": {},
        "input_channels": [], "magic_hits": [], "notes": [],
    }
    try:
        img = emu.load_image(blob)
    except Exception as exc:
        info["kind"] = "非 PE/ELF"
        info["notes"].append(f"解析失败：{exc}")
        info["runtime"] = ["无法识别：不是本工具能解析的二进制（可能是脚本/文档/加密数据）"]
        info["input_channels"] = ["—"]
        info["tier"] = "B"
        info["tier_reason"] = "不是二进制，走 `scan` / `auto` 更合适"
        info["anchor_hint"] = "Correct"
        info["next_steps"] = [("python plainseek.py scan " + _q(name),
                               "先用文件级侦察看它是什么、像不像密文或编码数据")]
        return info

    info["kind"] = img.describe().splitlines()[0]
    info["bits"] = getattr(img, "bits", None)
    info["subsystem"] = getattr(img, "subsystem", None)
    info["entry"] = getattr(img, "entry", None)

    # 壳
    upx, reasons = unpack.looks_like_upx(img)
    if upx:
        info["packed"] = {"kind": "upx", "name": "UPX", "reasons": reasons}
    else:
        verdict = sigscan.detect_packer(img)
        if verdict is not None:
            info["packed"] = {"kind": "other", "name": verdict.name,
                              "confidence": verdict.confidence,
                              "reasons": verdict.evidence}

    # 字符串 / 文案 / 常量
    strings = crackme.interesting_strings(img, limit=200)
    info["runtime"] = detect_runtime(img, strings)
    info["input_channels"] = detect_input_channels(img, strings)
    try:
        vmap = gui.string_verdict_map(img)
    except Exception:
        vmap = {}
    info["verdict_strings"] = {
        "success": sorted(a for a, v in vmap.items() if v == "success"),
        "failure": sorted(a for a, v in vmap.items() if v == "failure"),
    }
    # 成功文案里挑一条最像"人工可读"的，给 --anchor 用
    # 成功文案里挑一条"像人写给玩家看的"，给 --anchor 用。
    # ⚠ 不能随便挑第一条：`string_verdict_map` 是按关键词分类的，
    #    "[!] Nice try, but not quite right..." 这种**失败**文案里含 "right" 也会被归成 success。
    #    所以这里加一层"更像成功语"的优先序，最后还是挑不到就用 Correct。
    want = ("success", "correct", "congrat", "win", "pass", "right answer", "yes")
    candidates: List[str] = []
    for addr in info["verdict_strings"]["success"]:
        text = _cstring_at(img, addr).strip()
        if text and 3 <= len(text) <= 40 and any(c.isalpha() for c in text):
            candidates.append(text)
    hint = ""
    for word in want:
        for text in candidates:
            low = text.lower()
            # 排除带否定词的（Nice try / not quite / wrong 之类）
            if word in low and not any(bad in low for bad in
                                       ("not ", "n't", "wrong", "fail", "try", "sorry")):
                hint = text
                break
        if hint:
            break
    info["anchor_hint"] = hint or "Correct"
    info["crypto"] = [{"name": h.name, "offset": hex(h.at),
                       "similarity": h.similarity, "exact": h.exact}
                      for h in sigscan.scan_crypto(img)]
    # 魔数：用"人话名字"而不是 b'\x03\x04' 这种，报告才看得懂
    magic_names = {
        b"flag{": "flag 前缀",
        b"CM26": "自定义魔数 CM26",
        b"PK\x03\x04": "ZIP 结构",
        b"-----BEGIN": "PEM",
        b"\x89PNG": "PNG",
    }
    for magic, label in magic_names.items():
        at = blob.find(magic)
        if at >= 0:
            info["magic_hits"].append(f"{label} @0x{at:x}")

    # LÖVE（love2d）游戏：exe 尾部追加 .love（就是 zip），里面是 main.lua。
    # 吾爱 2026 春节之六 就是这种，flag.dat 在 zip 里，压根不用跑游戏。
    if b"PK\x03\x04" in blob and (b"main.lua" in blob or b"conf.lua" in blob):
        info["notes"].append("像是 LÖVE/love2d 游戏：zip 直接附加在 exe 尾部，"
                             "flag 常在 zip 里的 main.lua 逻辑或 assets 数据里")
    info["tier"], info["tier_reason"] = _tier(info)
    info["next_steps"] = _next_steps(name, info)
    return info


def format_report(info: Dict[str, object]) -> str:
    """把结构化结果排成人看的样子：先结论，再证据，最后下一步。"""
    out: List[str] = []
    w = out.append
    w("=" * 74)
    w(f" triage：{info['file']}（{info['size']} 字节）")
    w("=" * 74)
    w(f"  身份    {info['kind']}")
    if info["entry"]:
        w(f"          入口 0x{info['entry']:x}，子系统 {info['subsystem']}"
          f"（{ {2: 'GUI', 3: '控制台'}.get(info['subsystem'], '其它') }）")
    packed = info["packed"]
    if packed.get("kind") == "upx":
        w(f"  外壳    UPX（能自己脱）：{'；'.join(packed.get('reasons', []))}")
    elif packed.get("kind") == "other":
        w(f"  外壳    {packed.get('name')}（置信度 {packed.get('confidence')}）"
          f"：{'；'.join(packed.get('reasons', [])[:3])}")
    else:
        w("  外壳    没发现明显加壳特征")
    w("  运行时")
    for line in info["runtime"]:
        w(f"          · {line}")
    w("  输入口")
    for line in info["input_channels"]:
        w(f"          · {line}")
    verdicts = info["verdict_strings"]
    w(f"  成败文案  成功 {len(verdicts.get('success', []))} 条 / "
      f"失败 {len(verdicts.get('failure', []))} 条")
    for addr in (verdicts.get("success") or [])[:3]:
        w(f"          成功文案 @0x{addr:x}")
    if info["crypto"]:
        w("  加密常量  （命中说明算法可能被改过，看 diffs 更准）")
        for hit in info["crypto"][:5]:
            mark = "完全一致" if hit["exact"] else f"相似 {hit['similarity']:.0%}"
            w(f"          · {hit['name']} @{hit['offset']}（{mark}）")
    if info["magic_hits"]:
        w(f"  可疑魔数  {', '.join(info['magic_hits'])}")
    for note in info["notes"]:
        w(f"  备注      {note}")
    w("")
    tier, reason = info["tier"], info.get("tier_reason", "")
    w(f"  ── 结论：{tier} 档（{'大概率能全自动' if tier == 'A' else '需要人工判断'}）")
    w(f"           {reason}")
    w("")
    w("  ── 下一步（按优先级，可以直接复制执行）")
    for i, (cmd, why) in enumerate(info["next_steps"], 1):
        w(f"   {i}. {cmd}")
        w(f"      ↳ {why}")
    w("")
    w("  说明：triage 只给线索和路线，不会凭空造候选明文；")
    w("        真正出答案的是 auto / emu --run / gui --discover。")
    return "\n".join(out)


def triage_path(path: str) -> Dict[str, object]:
    blob = _read(path)
    return triage_blob(blob, os.path.basename(path) if path not in ("-", "/dev/stdin") else "stdin")


def _read(path: str) -> bytes:
    if path in ("-", "/dev/stdin"):
        import sys
        return sys.stdin.buffer.read()
    with open(path, "rb") as fh:
        return fh.read()
