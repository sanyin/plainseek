"""命令行界面：scan / solve / chain / pair / table / oracle / selftest。"""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import List, Optional

from . import (alphabets, baseN, board, carve, crack, identify, langscore, oracles,
               pipeline, recover, search, transforms, verify, xoranalysis)
from .transforms import Ctx, Step


def _console_is_utf8() -> bool:
    """当前控制台是不是 UTF-8 代码页（chcp 65001）。"""
    try:
        import ctypes
        return ctypes.windll.kernel32.GetConsoleOutputCP() == 65001
    except Exception:
        return False


def _setup_stdout() -> None:
    """让中文在两种场景下都能正常显示：

    * 一条龙.bat 里先执行了 ``chcp 65001`` → 控制台是 UTF-8，就按 UTF-8 输出；
    * 用户直接在普通 cmd/PowerShell 里跑（默认 GBK/936）→ 尊重控制台编码，
      否则强行 UTF-8 会在 GBK 控制台里显示成乱码。
    """
    try:
        import locale
        fallback = sys.stdout.encoding or locale.getpreferredencoding(False) or "utf-8"
        forced = os.environ.get("PYTHONIOENCODING")
        target = "utf-8" if (forced or _console_is_utf8()) else fallback
        sys.stdout.reconfigure(encoding=target, errors="replace")
        sys.stderr.reconfigure(encoding=target, errors="replace")
    except Exception:
        pass


def _b(text: str) -> bytes:
    if isinstance(text, (bytes, bytearray)):        # 菜单里可能直接给 bytes
        return bytes(text)
    return text.encode("utf-8")


def _key_bytes(text) -> bytes:
    """密钥参数：支持 ``hex:`` 前缀（十六进制密钥，DES 类题目常用）。"""
    if isinstance(text, (bytes, bytearray)):
        return bytes(text)
    text = str(text).strip()
    if text.lower().startswith("hex:"):
        try:
            return bytes.fromhex(text[4:].strip())
        except ValueError as exc:
            print(f"  [warn] 十六进制密钥解析失败（{exc}），按普通字符串处理")
    return text.encode("utf-8")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="autocrypt",
        description="一条龙解密工具：自动识别密码表、自动叠加多层、自动判断解对了没有",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""常用例子：
  python autocrypt.py auto  ./题目目录            # 最省事：拖文件/文件夹/zip 进来
  python autocrypt.py scan  ./attachment
  python autocrypt.py solve ./attachment -o ./recovered
  python autocrypt.py solve ./attachment --keys-from ./attachment/distorted --deep
  python autocrypt.py chain "rev,hex,xor:0x5a" secret.bin
  python autocrypt.py pair plain.txt plain.txt.enc
  python autocrypt.py fragments ./attachment          # flag 被拆成几段时
  python autocrypt.py verify app.exe --plain 'CTF{'   # 用程序内密文确认密钥
  python autocrypt.py pyc target.pyc --dis            # 跨版本读 .pyc
  python autocrypt.py formula secret.bin --crib 'flag{'
  python autocrypt.py stego art.bmp --dump bits.bin   # 隐写：BMP 位平面 / WAV 频谱
  python autocrypt.py emu app --call 0x401930         # 模拟执行取证（跑一遍看它写了什么）
  python autocrypt.py selftest
""")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="侦察：文件类型、熵、编码猜测、配对了没")
    s.add_argument("paths", nargs="+")
    s.add_argument("--recursive", action="store_true")

    s = sub.add_parser("solve", help="一条龙：自动解密整个目录")
    s.add_argument("paths", nargs="+")
    s.add_argument("-o", "--out", help="输出目录")
    s.add_argument("--depth", type=int, default=4, help="最多叠加几层（默认 4）")
    s.add_argument("--beam", type=int, default=12, help="每层保留多少候选（默认 12）")
    s.add_argument("--timeout", type=float, default=90.0, help="每个文件的搜索时间上限（秒）")
    s.add_argument("--work", type=int, default=20000, help="变换执行次数上限")
    s.add_argument("--deep", action="store_true", help="深度暴力（更慢更全）")
    s.add_argument("--key", action="append", default=[], help="手动给密钥，可重复")
    s.add_argument("--keys-file", action="append", default=[], help="密钥字典文件")
    s.add_argument("--keys-from", action="append", default=[], help="从这个文件里抓密钥字符串")
    s.add_argument("--key-script", help="自定义密钥派生脚本（定义 keys(ctx) 生成器）")
    s.add_argument("--fmt", default="", help="强制目标格式：jpeg/png/txt/zip…")
    s.add_argument("--reference", help="参考文件（如标准 JPEG，用于比对 Huffman 表）")
    s.add_argument("--table", help="直接给出字符表（64 个字符）")
    s.add_argument("--crib", help="已知明文串或正则：设了就只认命中它的结果")
    s.add_argument("--crib-regex", action="store_true", help="把 --crib 当正则处理")
    s.add_argument("--verify-binary", help="密钥确认用的程序（里面存着密文/明文常量）")
    s.add_argument("--verify-plain", help="方式 A 的已知明文前缀（@文件 也可）")
    s.add_argument("--verify-cipher", default="des,des3,aes,rc4,rc4v,xor",
                   help="密钥确认要试的密码规格")
    s.add_argument("--verify-key-transform", default="raw,bitrev",
                   help="密钥确认要试的密钥位变换")
    s.add_argument("--ciphertext-offset", type=lambda v: int(v, 0), default=-1,
                   help="方式 B：密文在程序里的文件偏移")
    s.add_argument("--ciphertext-length", type=int, default=0, help="方式 B：密文长度")
    s.add_argument("--keyspace", default="none",
                   choices=["none", "digits", "hex", "lower", "alnum", "range", "words"],
                   help="密钥确认要枚举的输入空间")
    s.add_argument("--length", type=int, default=6, help="输入空间长度")
    s.add_argument("--derive", default="raw", help="派生规则（raw/md5/md5_hex/…）")
    s.add_argument("--verify-limit", type=int, default=2000000, help="密钥确认最多试多少候选")
    s.add_argument("--no-fragments", action="store_true",
                   help="关闭「flag 片段拼接」兜底（默认开启）")
    s.add_argument("--no-flag-prefix", action="store_true", help="不要假设 flag{ 前缀")
    s.add_argument("--recursive", action="store_true")
    s.add_argument("--json", action="store_true", help="以 JSON 输出摘要")

    s = sub.add_parser("chain", help="按给定配方解（可用来验证/复用）")
    s.add_argument("recipe", nargs="?", help="配方，如 rev,hex,xor:0x5a")
    s.add_argument("file", nargs="?")
    s.add_argument("-o", "--out", help="输出文件")
    s.add_argument("--key", action="append", default=[])
    s.add_argument("--list", action="store_true", help="只列出可用的变换名")

    s = sub.add_parser("pair", help="分析一对明文/密文，给出密钥流/字符表结论")
    s.add_argument("plain")
    s.add_argument("cipher")

    s = sub.add_parser("table", help="还原被打乱的字符表")
    s.add_argument("cipher", nargs="+", help="自定义字符表编码的数据（可多个，一起约束）")
    s.add_argument("--pair-plain", help="与之配对的明文文件")
    s.add_argument("--pair-cipher", help="与该明文配对的密文文件")
    s.add_argument("--fmt", default="", help="目标格式")
    s.add_argument("--reference", help="参考文件")

    s = sub.add_parser("oracle", help="给文件打分（看解出来像不像真东西）")
    s.add_argument("file")

    s = sub.add_parser("transforms", help="列出所有可用变换")

    # ---- 借鉴同类工具补的功能 ----
    s = sub.add_parser("identify", help="识别这是什么（哈希/令牌/凭证/编码…）")
    s.add_argument("target", help="文本或文件路径")
    s.add_argument("--include", action="append", default=[], help="只看这些标签")
    s.add_argument("--exclude", action="append", default=[], help="排除这些标签")
    s.add_argument("--tags", action="store_true", help="列出所有可用标签")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("xor", help="多字节 XOR 自动分析（猜长度 + 猜密钥）")
    s.add_argument("file")
    s.add_argument("-m", "--max-length", type=int, default=32, help="最大密钥长度")
    s.add_argument("-c", "--most-common", action="append", default=[],
                   help="最高频明文字节，如 0x20 / 0x00，可重复")
    s.add_argument("--hex", action="store_true", help="输入是十六进制文本")
    s.add_argument("-o", "--out", help="把最优结果写到这个文件")

    s = sub.add_parser("basedecode", help="递归多层 Base 解码（magic 模式）")
    s.add_argument("target", help="文本或文件路径")
    s.add_argument("-d", "--depth", type=int, default=8)
    s.add_argument("--allow", help="只允许这些编码，逗号分隔")
    s.add_argument("--out", help="把最优结果写到这个文件")

    s = sub.add_parser("carve", help="扫描/雕刻内嵌文件（识别魔数、结构校验、压缩区抑制）")
    s.add_argument("file")
    s.add_argument("--extract", action="store_true", help="把识别到的内嵌文件导出")
    s.add_argument("-o", "--out", help="导出目录")
    s.add_argument("--depth", type=int, default=0, help="递归雕刻层数")
    s.add_argument("--json", help="把报告写成 JSON")
    s.add_argument("--min-magic", type=int, default=4, help="最短 magic 长度")
    s.add_argument("--list-sigs", action="store_true", help="列出所有签名")

    s = sub.add_parser("crack", help="古典密码自动破解（凯撒/仿射/维吉尼亚/单表替换/栅栏）")
    s.add_argument("file")
    s.add_argument("--type", default="auto",
                   choices=["auto", "caesar", "affine", "vigenere", "sub", "railfence",
                            "columnar", "xor"])
    s.add_argument("--deep", action="store_true")
    s.add_argument("-o", "--out")

    s = sub.add_parser("verify", help="密钥确认：拿程序里存着的密文当标准答案反查候选密钥")
    s.add_argument("binary", help="目标程序（里面存着密文/明文常量）")
    s.add_argument("--plain", help="已知明文前缀（方式 A：加密后在程序里找密文）；@文件 也可")
    s.add_argument("--try-lenprefix", action="store_true",
                   help="再把「4/2 字节长度前缀 + 明文」当模板一起试")
    s.add_argument("--cipher", default=",".join(verify.DEFAULT_CIPHERS),
                   help="密码规格，逗号分隔，如 des:mode=ecb 或 rc4v:mask=1,p1=0x72,p2=0x37")
    s.add_argument("--key", action="append", default=[], help="直接给候选密钥")
    s.add_argument("--keys-file", action="append", default=[], help="密钥字典（每行一个）")
    s.add_argument("--keyspace", default="digits",
                   choices=["none", "digits", "hex", "lower", "alnum", "range", "words"],
                   help="枚举的输入空间（默认 digits）")
    s.add_argument("--length", type=int, default=6, help="输入长度（默认 6）")
    s.add_argument("--range", dest="range_expr", help="range 模式：起始:结束，如 0:1000000")
    s.add_argument("--words-file", help="words 模式使用的字典")
    s.add_argument("--derive", default="raw",
                   help="派生规则：raw/md5/sha1/sha256/md5_hex/…，可加号组合，如 md5_hex+pad8")
    s.add_argument("--key-script", help="把程序里的派生逻辑写成 keys() 生成器（可 yield (输入, 密钥)）")
    s.add_argument("--key-transform", default="raw,bitrev",
                   help="密钥位变换，逗号分隔（DES 变体题常要 bitrev）")
    s.add_argument("--ciphertext-hex", help="方式 B：直接给出密文（十六进制）")
    s.add_argument("--ciphertext-offset", type=lambda v: int(v, 0), default=-1,
                   help="方式 B：密文在程序里的文件偏移")
    s.add_argument("--ciphertext-length", type=int, default=0, help="方式 B：密文长度")
    s.add_argument("--emulate-script", help="方式 C：自备模拟执行脚本（定义 verify(key, blob, label)）")
    s.add_argument("--threshold", type=float, default=0.85,
                   help="结构判据阈值（默认 0.85；弱判据 0.8 不算确认，避免百万级枚举误报）")
    s.add_argument("--limit", type=int, default=2000000, help="最多尝试多少个候选")
    s.add_argument("--timeout", type=float, default=300.0, help="确认过程时间上限（秒）")

    s = sub.add_parser("fragments", help="flag 片段收集与拼接（flag 被拆成几段分别存储时用）")
    s.add_argument("file")
    s.add_argument("--crib", help="已知前缀，如 XJUSEC{")
    s.add_argument("--min-len", type=int, default=3, help="片段最短长度")
    s.add_argument("--max-parts", type=int, default=6, help="最多拼几段")
    s.add_argument("--budget", type=int, default=400000, help="搜索节点上限")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("pyc", help="读 Python 字节码（.pyc）：版本/常量/反汇编，可尝试直接还原 flag")
    s.add_argument("file")
    s.add_argument("--dis", action="store_true", help="反汇编所有 code object")
    s.add_argument("--solve", action="store_true", help="尝试用常量+公式搜索直接还原 flag")
    s.add_argument("--crib", help="已知 flag 前缀（默认从字符串常量里自动猜）")
    s.add_argument("--timeout", type=float, default=30.0, help="公式搜索时间上限")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("sig", help="签名扫描：加密常量指纹（含被改过的常量）+ 打包器识别 + 熵")
    s.add_argument("file")
    s.add_argument("--crib", action="store_true",
                   help="额外尝试**多字节**异或字符串解密（启发式，假阳性较多，"
                        "默认只做可靠的单字节路径）")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("gui", help="GUI/CrackMe 自动判定：找候选校验入口并让程序自己判对错")
    s.add_argument("file")
    s.add_argument("--discover", action="store_true",
                   help="逐个试候选入口，找出「两个不同输入给出不同结论」的可用判定")
    s.add_argument("--max-ins", type=int, default=200000)
    s.set_defaults(func=cmd_gui)

    s = sub.add_parser("unpack", help="UPX 自动脱壳：内存里跑壳的 stub，dump 出可分析的镜像")
    s.add_argument("file", help="要脱壳的文件；写 - 表示从 stdin 读（杀软锁文件时用管道）")
    s.add_argument("--out", help="输出路径（默认 <原名>.unpacked.bin）")
    s.add_argument("--max-ins", type=int, default=4000000)
    s.set_defaults(func=cmd_unpack)

    s = sub.add_parser("triage", help="逆向题指路：侦察 + 排序好的下一步命令（只给线索，不造答案）")
    s.add_argument("file", help="样本文件；写 - 表示从 stdin 读")
    s.add_argument("--json", action="store_true", help="结构化输出")
    s.set_defaults(func=cmd_triage)

    s = sub.add_parser("crackme", help="CrackMe 辅助：静态定位比较点/输入点 + 可选模拟执行")
    s.add_argument("file")
    s.add_argument("--run", action="store_true", help="顺便把程序模拟执行跑一遍")
    s.add_argument("--stdin", help="喂给程序的输入")
    s.add_argument("--max-ins", type=int, default=2000000)

    s = sub.add_parser("emu", help="模拟执行取证：跑函数、看它改写了什么内存（unicorn）")
    s.add_argument("file")
    s.add_argument("--anchor", action="append",
                   help="锚点字符串（可重复），给出引用它的代码地址，用来定位 main/verify")
    s.add_argument("--call", help="模拟执行这个地址处的函数，如 --call 0x401930")
    s.add_argument("--args", action="append",
                   help="函数参数（按 rdi,rsi,rdx,rcx,r8,r9 顺序，可重复）")
    s.add_argument("--imm", action="append",
                   help="列出该地址附近的立即数常量，如 --imm 0x401a60:24")
    s.add_argument("--dump", action="append",
                   help="跑完后读内存，格式 0x地址:长度（可重复）")
    s.add_argument("--dump-to", help="把「被改写的内存」逐块导出到这个目录")
    s.add_argument("--max-ins", type=int, default=200000, help="指令数上限")
    s.add_argument("--trace", action="store_true", help="打印执行轨迹前若干条")
    s.add_argument("--run", action="store_true",
                   help="把程序自己跑起来（自动定位校验函数；PE 会接管导入表、绕过反调试）")
    s.add_argument("--stdin", help="喂给程序的输入（判断候选 flag 对不对的最硬证据）")
    s.add_argument("--stdin-file", help="从文件读取要喂给程序的输入")
    s.add_argument("--list-candidates", action="store_true",
                   help="只列出猜出来的校验函数候选（靠符号表 / 字符串引用 + .pdata 回溯）")
    s.add_argument("--break", dest="break_at", action="append", metavar="ADDR",
                   help="断点地址（可重复）：跑到这里停下并打印寄存器现场，"
                        "常用来抓\"比较的那一刻两个操作数是什么\"")
    s.add_argument("--trace-cfg", action="store_true",
                   help="按**真实执行轨迹**反汇编并打印（对付\"跳进指令中间\"的花指令："
                        "线性反汇编解不到的地方，它能给出真实指令流）")

    s = sub.add_parser("stego", help="隐写分析：BMP 位平面提取 + WAV 频谱/音频解码")
    s.add_argument("file")
    s.add_argument("--kind", choices=["auto", "bmp", "wav"], default="auto")
    s.add_argument("--top", type=int, default=8, help="位平面候选显示几条")
    s.add_argument("--dump", help="导出原始位流（BMP）或采样（WAV）到该文件")
    s.add_argument("--channel", choices=["b", "g", "r", "all"], help="--dump 时用哪个通道")
    s.add_argument("--bit", type=int, default=0, help="--dump 时取第几位（默认 0，最低位）")
    s.add_argument("--lsb-first", action="store_true", help="--dump 时按 LSB-first 位序")
    s.add_argument("--order", choices=["row", "col", "plane"], default="row",
                   help="--dump 时的像素顺序（plane = 8 个位平面拼接）")
    s.add_argument("--stride", type=int, default=1, help="--dump 时每隔几个像素取一位")
    s.add_argument("--snake", action="store_true",
                   help="--dump 时按蛇形扫描（偶数行正向、奇数行反向）")
    s.add_argument("--skip-pixels", type=int, default=0,
                   help="--dump 时开头跳过多少个像素（自制打包工具常留表头，R13 是 64）")
    s.add_argument("--spectrogram", help="WAV：把频谱图导出成 PNG（密钥被「画」成声音时用）")
    s.add_argument("--ascii-art", action="store_true",
                   help="WAV：把频谱还原成终端 ASCII 点阵（不用看图也能读字）")

    s = sub.add_parser("formula", help="逐字节线性公式反推（目标字节 + 已知前缀 → 全文）")
    s.add_argument("target", help="目标字节：十六进制串、@文件、或文件路径")
    s.add_argument("--crib", required=True, help="已知明文前缀，如 XJUSEC{")
    s.add_argument("--offset", type=int, default=0, help="crib 在明文中的起始下标")
    s.add_argument("--top", type=int, default=5)
    s.add_argument("--timeout", type=float, default=8.0)
    s.add_argument("-o", "--out", help="把最优结果写到这个文件")

    s = sub.add_parser("bulk", help="批量处理：文件里每行一串，逐行识别与解码")
    s.add_argument("file")
    s.add_argument("--out", help="把每行解出的结果写到这个文件")

    # ---- 拖进来就能跑 ----
    s = sub.add_parser("auto", help="自动模式：文件/文件夹/zip 通吃（先侦察再一条龙）")
    s.add_argument("target", help="文件、文件夹或 zip")
    s.add_argument("-o", "--out", help="输出目录")
    s.add_argument("--depth", type=int, default=4)
    s.add_argument("--beam", type=int, default=12)
    s.add_argument("--timeout", type=float, default=60.0)
    s.add_argument("--work", type=int, default=20000)
    s.add_argument("--deep", action="store_true")
    s.add_argument("--key", action="append", default=[])
    s.add_argument("--keys-file", action="append", default=[])
    s.add_argument("--keys-from", action="append", default=[])
    s.add_argument("--key-script")
    s.add_argument("--fmt", default="")
    s.add_argument("--reference")
    s.add_argument("--table")
    s.add_argument("--crib")
    s.add_argument("--crib-regex", action="store_true")
    s.add_argument("--no-flag-prefix", action="store_true")
    s.add_argument("--verify-binary")
    s.add_argument("--verify-plain")
    s.add_argument("--verify-cipher", default="des,des3,aes,rc4,rc4v,xor")
    s.add_argument("--verify-key-transform", default="raw,bitrev")
    s.add_argument("--ciphertext-offset", type=lambda v: int(v, 0), default=-1)
    s.add_argument("--ciphertext-length", type=int, default=0)
    s.add_argument("--keyspace", default="none",
                   choices=["none", "digits", "hex", "lower", "alnum", "range", "words"])
    s.add_argument("--length", type=int, default=6)
    s.add_argument("--derive", default="raw")
    s.add_argument("--verify-limit", type=int, default=2000000)
    s.add_argument("--no-fragments", action="store_true")
    s.add_argument("--recursive", action="store_true")
    s.add_argument("--menu", action="store_true",
                   help="解不出来时留在窗口里交互重试（一条龙.bat 默认开启）")
    s.add_argument("--no-menu", action="store_true", help="关闭交互菜单")

    sub.add_parser("selftest", help="自检：用合成的多层加密验证整条流水线")
    return p


# --------------------------------------------------------------------------
# 子命令实现
# --------------------------------------------------------------------------

def cmd_scan(args) -> int:
    files = pipeline.list_files(args.paths, args.recursive)
    if not files:
        print("没有文件")
        return 1
    pairs = {c: p for p, c in recover.find_pairs(files)}
    for path in files:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print(f"{path}: 读取失败 {exc}")
            continue
        info = oracles.describe(data)
        fmt = pipeline.guess_format(path, data)
        tag = " [密文候选]" if pipeline.is_encrypted_candidate(path) else ""
        print(f"\n=== {path}{tag}")
        print(f"    大小 {info['len']}  熵 {info['entropy']}  可打印率 {info['printable']}  "
              f"不同字节 {info['distinct_bytes']}")
        print(f"    长度 mod4={info['mod4']} mod8={info['mod8']} mod16={info['mod16']}"
              f"  头部 {info['head_hex']}")
        if fmt:
            print(f"    疑似格式：{fmt}")
        guesses = alphabets.detect_alphabets(data)
        if guesses:
            print(f"    字符表猜测：{guesses[0]}")
        for v in info["verdicts"]:
            print(f"    判定：{v}")
        if path in pairs:
            print(f"    配对明文：{pairs[path]}")
    return 0


def cmd_solve(args) -> int:
    opts = pipeline.Options(
        out_dir=args.out, depth=args.depth, beam=args.beam, timeout=args.timeout,
        work_limit=args.work, deep=args.deep,
        keys=[_key_bytes(k) for k in args.key], key_files=args.keys_file, keys_from=args.keys_from,
        key_script=args.key_script, fmt=args.fmt, reference=args.reference,
        assume_flag_prefix=not args.no_flag_prefix,
        table=_b(args.table) if args.table else None,
        crib=args.crib, crib_is_regex=args.crib_regex,
        verify_binary=args.verify_binary, verify_plain=args.verify_plain,
        verify_ciphers=args.verify_cipher, verify_key_transforms=args.verify_key_transform,
        ciphertext_offset=args.ciphertext_offset, ciphertext_length=args.ciphertext_length,
        keyspace_kind=args.keyspace, keyspace_length=args.length, derive=args.derive,
        verify_limit=args.verify_limit, fragments=not args.no_fragments,
        recursive=args.recursive, log=print)
    rep = pipeline.run(args.paths, opts)
    print("\n================ 结果汇总 ================")
    if not rep.outcomes:
        print("没有解出结果。可尝试：--deep、--keys-from 指定二进制、--key 手动给密钥、"
              "--fmt 指定格式、加大 --timeout")
        return 1
    for o in rep.outcomes:
        print(o.summary())
    flag_hits = []
    for o in rep.outcomes:
        for v in oracles.evaluate(o.plaintext, only=["flag"]):
            flag_hits.append((o.path, v.detail, o))
    if flag_hits:
        print("\n找到的 flag（附证据等级：只有 oracle 及以上才算「确认」）：")
        for path, text, o in flag_hits:
            kind, why = pipeline.outcome_evidence(o)
            strong = board.evidence_level(kind) >= board.STRONG_EVIDENCE
            mark = "✔确认" if strong else "⚠待验证"
            print(f"  [{mark} {kind}] {text}   （来自 {os.path.basename(path)}；{why}）")
        if not any(board.evidence_level(pipeline.outcome_evidence(o)[0])
                   >= board.STRONG_EVIDENCE for _p, _t, o in flag_hits):
            print("  ⚠ 上面这些**都没有强证据**：逆向题常在附件里埋诱饵 flag"
                  "（投稿包 3/12 就埋了）。提交前请用 `verify`（程序内密文反查）"
                  "或 `emu --run --stdin 候选`（让程序自己判对错）确认一次。")
    if args.json:
        import json
        print(json.dumps({
            "elapsed": rep.elapsed,
            "outcomes": [{"path": o.path, "recipe": o.recipe, "score": o.score,
                          "verified": o.verified,
                          "verdicts": o.verdicts} for o in rep.outcomes],
        }, ensure_ascii=False, indent=2))
    return 0


def cmd_chain(args) -> int:
    if args.list:
        for cat, names in sorted(transforms.CATEGORIES.items()):
            print(f"[{cat}] {', '.join(sorted(names))}")
        return 0
    if not args.recipe or not args.file:
        print("用法：chain <配方> <文件>；或 chain --list 查看可用变换")
        return 1
    ctx = Ctx(keys=[_b(k) for k in args.key])
    steps = transforms.parse_recipe(args.recipe, ctx)
    with open(args.file, "rb") as fh:
        data = fh.read()
    out = transforms.apply_recipe(data, steps, ctx)
    print(f"配方：{transforms.recipe_description(steps)}")
    print(f"{len(data)} → {len(out)} 字节")
    for v in oracles.evaluate(out):
        print(f"  {v}")
    try:
        again = transforms.encode_recipe(out, steps, ctx)
        print("重新加密复核:", "通过" if again == data else "不一致")
    except Exception as exc:
        print("重新加密复核: 不可用（该配方含不可逆步骤）", exc)
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(out)
        print("已写出", args.out)
    else:
        sys.stdout.buffer.write(out[:4096] + ("\n...[截断]".encode() if len(out) > 4096 else b""))
        sys.stdout.buffer.write(b"\n")
    return 0


def cmd_pair(args) -> int:
    rep = recover.analyze_pair(args.plain, args.cipher)
    print(f"明文 {rep.plain_len} 字节，密文 {rep.cipher_len} 字节")
    for note in rep.notes:
        print(" ·", note)
    if rep.layer:
        kind = rep.layer.get("kind")
        print("密钥流分析:", kind)
        if kind == "常数":
            print("  单字节 XOR 常量:", hex(rep.layer["key"][0]))
        elif kind == "短周期重复密钥":
            print("  周期:", rep.layer.get("period"), "密钥:", rep.layer["key"])
        elif kind.startswith("伪随机"):
            ks = rep.layer["keystream"]
            print(f"  密钥流前 32 字节: {ks[:32].hex()}")
            print("  （同密钥同初始化的其它文件可用该密钥流异或前 %d 字节）" % len(ks))
    if rep.table:
        print("还原出的字符表:", rep.table.decode("latin-1"))
    return 0


def cmd_table(args) -> int:
    plain = None
    if args.pair_plain:
        with open(args.pair_plain, "rb") as fh:
            plain = fh.read()
    entries = []
    for path in args.cipher:
        with open(path, "rb") as fh:
            data = fh.read()
        fmt = args.fmt or pipeline.guess_format(path, data)
        known = []
        if plain and (args.pair_cipher is None or os.path.basename(path) == os.path.basename(args.pair_cipher)):
            known.append((0, plain))
        else:
            magic = alphabets.FORMAT_MAGIC.get(fmt, b"")
            if magic:
                known.append((0, magic))
        oracle = pipeline.format_oracle(fmt) or (lambda b, p: oracles.best(b, partial=p))
        ref = alphabets.reference_segments(
            "jpeg", open(args.reference, "rb").read() if args.reference else None) if fmt == "jpeg" else None
        entries.append(alphabets.Stream(os.path.basename(path), data, fmt=fmt,
                                        known_spans=known, oracle=oracle, ref_segments=ref))
    solver = alphabets.TableSolver(entries, log=print)
    sols = solver.run()
    if not sols:
        print("没有解出字符表")
        return 1
    for i, sol in enumerate(sols[:5]):
        print(f"--- 候选 {i}: 置信度 {sol.score:.3f}")
        print("    字符表:", sol.table().decode("latin-1"))
        for note in sol.notes:
            print("   ", note)
    return 0


def cmd_oracle(args) -> int:
    with open(args.file, "rb") as fh:
        data = fh.read()
    info = oracles.describe(data)
    for k, v in info.items():
        print(f"{k}: {v}")
    return 0


def cmd_transforms(args) -> int:
    for cat, names in sorted(transforms.CATEGORIES.items()):
        print(f"[{cat}]")
        for n in sorted(names):
            print(f"    {n:12s} {transforms.REGISTRY[n].help}")
    return 0


def cmd_identify(args) -> int:
    if args.tags:
        print("可用标签：", "、".join(identify.all_tags()))
        return 0
    target = args.target
    data: object = target
    if os.path.isfile(target):
        with open(target, "rb") as fh:
            data = fh.read()
        print(f"文件 {target}（{len(data)} 字节）：")  # type: ignore[arg-type]
    hits = identify.identify(data, args.include or None, args.exclude or None)
    if args.json:
        import json
        print(json.dumps([{"name": h.name, "value": h.value, "offset": h.offset,
                           "tags": list(h.tags), "confidence": h.confidence,
                           "hashcat": h.hashcat, "description": h.description}
                          for h in hits], ensure_ascii=False, indent=2))
        return 0
    if not hits:
        print("没识别出已知特征。")
        if isinstance(data, str):
            enc = identify.guess_encodings(data)
            for name, note in enc:
                print(f"  · 疑似 {name}：{note}")
        return 0
    print(f"共 {len(hits)} 条线索：")
    for h in hits:
        print("  " + h.line().replace("\n", "\n  "))
    return 0


def cmd_xor(args) -> int:
    with open(args.file, "rb") as fh:
        data = fh.read()
    if args.hex:
        import binascii
        data = binascii.unhexlify(re.sub(rb"[\s]", b"", data))
        print(f"十六进制输入 → {len(data)} 字节")
    common = [int(v, 0) for v in args.most_common] if args.most_common else [0x20, 0x00, 0xFF]
    print(f"数据 {len(data)} 字节，最高频字符候选 {[hex(v) for v in common]}")
    print("最可能的密钥长度（等字符计数）：",
          [f"{n}({s:.3f})" for n, s in xoranalysis.guess_key_lengths(data, args.max_length)])
    results = xoranalysis.auto_xor(data, args.max_length, most_common=common)
    if not results:
        print("没有结果")
        return 1
    for r in results[:8]:
        print("  " + r.line())
    best = results[0]
    print(f"\n最优：密钥长度 {best.key_length}，密钥 = {best.key!r}")
    if best.detail:
        print(f"      结构校验：{best.detail}")
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(best.plaintext)
        print("已写出", args.out)
    return 0


def cmd_basedecode(args) -> int:
    target = args.target
    if os.path.isfile(target):
        with open(target, "rb") as fh:
            data = fh.read()
    else:
        data = target.encode()
    allow = [a.strip() for a in args.allow.split(",")] if args.allow else None
    results = baseN.magic_decode(data, args.depth, allow)
    if not results:
        print("没有可用的 Base 解码链")
        return 1
    for r in results[:8]:
        print("  " + r.line())
    best = results[0]
    print(f"\n最优链路：{' → '.join(best.chain)}")
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(best.data)
        print("已写出", args.out)
    return 0


def cmd_carve(args) -> int:
    if args.list_sigs:
        print("\n".join(carve.all_signatures()))
        return 0
    with open(args.file, "rb") as fh:
        blob = fh.read()
    report = carve.scan(blob, args.file, min_magic=args.min_magic, depth=args.depth)
    print(carve.report_text(report))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(carve.report_json(report))
        print("报告已写出", args.json)
    if args.extract:
        out_dir = args.out or (args.file + "_carved")
        written = carve.extract(report, out_dir)
        for path in written:
            print("  已导出", path)
    return 0


def cmd_crack(args) -> int:
    with open(args.file, "rb") as fh:
        data = fh.read()
    if args.type == "caesar":
        results = crack.crack_caesar(data)
    elif args.type == "affine":
        results = crack.crack_affine(data)
    elif args.type == "vigenere":
        results = crack.crack_vigenere(data, 20 if args.deep else 12)
    elif args.type == "sub":
        results = crack.crack_substitution(data, restarts=8 if args.deep else 4)
    elif args.type == "railfence":
        results = crack.crack_railfence(data, 12 if args.deep else 8)
    elif args.type == "columnar":
        results = crack.crack_columnar(data, 7 if args.deep else 5)
    elif args.type == "xor":
        results = [crack.CrackResult("单字节 XOR", f"密钥={r.key.hex()}", r.plaintext,
                                     r.score, "枚举 256 种")
                   for r in xoranalysis.single_byte_bruteforce(data)]
    else:
        results = crack.crack_all(data, deep=args.deep, top=8)
    if not results:
        print("没有结果（文本可能太短，或不是古典密码）")
        return 1
    for r in results:
        print("  " + r.line())
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(results[0].plaintext)
        print("已写出", args.out)
    return 0


def cmd_verify(args) -> int:
    plain: Optional[bytes] = None
    if args.plain:
        if args.plain.startswith("@"):
            with open(args.plain[1:], "rb") as fh:
                plain = fh.read()
        else:
            plain = args.plain.encode()
    ciphertext = None
    if args.ciphertext_hex:
        import binascii
        ciphertext = binascii.unhexlify(re.sub(rb"[\s]", b"", args.ciphertext_hex.encode()))

    space = verify.Keyspace(kind=args.keyspace, length=args.length, derive=args.derive,
                            words_file=args.words_file)
    if args.range_expr:
        a, _, b = args.range_expr.partition(":")
        space.start = int(a)
        space.end = int(b) if b else 0
        space.kind = "range"

    keys: List[bytes] = []
    labels: List[str] = []
    for k in args.key:
        keys.append(k.encode())
        labels.append(k)
    for path in args.keys_file:
        with open(path, "rb") as fh:
            for line in fh:
                token = line.strip()
                if token:
                    keys.append(token)
                    labels.append(token.decode("utf-8", "replace"))

    results = verify.run_verify(
        args.binary, ciphers_list=[c.strip() for c in args.cipher.split(",") if c.strip()],
        keys=keys, key_labels=labels, keyspace=space, key_script=args.key_script,
        key_transforms=[t.strip() for t in args.key_transform.split(",") if t.strip()],
        verify_plain=plain, try_lenprefix=args.try_lenprefix,
        ciphertext=ciphertext, ciphertext_offset=args.ciphertext_offset,
        ciphertext_length=args.ciphertext_length, threshold=args.threshold,
        max_candidates=args.limit, time_budget=args.timeout, log=print,
        emulate_script=args.emulate_script)

    if not results:
        print("\n没有确认出密钥。可以试试：")
        print("  · 方式 B 需要密文位置：--ciphertext-offset <文件偏移> --ciphertext-length <长度>")
        print("  · 方式 A 需要已知明文：--plain 'CTF{' --try-lenprefix")
        print("  · 加密变体不确定：--cipher des,des3,aes,rc4 --key-transform raw,bitrev,reverse,bitrev_all")
        print("  · 派生逻辑特殊：--key-script 把你的推导写成 keys() 生成器")
        return 1
    print("\n================ 确认结果 ================")
    for r in results:
        print("  " + r.line())
        print(f"     输入={r.label}  密钥hex={r.key.hex()}")
    best = results[0]
    if best.plaintext:
        print("\n解出的明文：")
        print("  " + best.plaintext[:200].decode("utf-8", "replace").replace("\n", "\n  "))
    return 0


def cmd_fragments(args) -> int:
    from . import fragments as _frag
    with open(args.file, "rb") as fh:
        blob = fh.read()
    crib = args.crib.encode() if args.crib else None
    frags = _frag.collect_fragments(blob, min_len=args.min_len)
    results = _frag.reassemble_flags(frags, crib=crib, max_parts=args.max_parts,
                                     budget=args.budget)
    print(f"{args.file}（{len(blob)} 字节）收集到 {len(frags)} 个候选片段")
    if not results:
        print("没有拼出 flag。可以试试：--crib 给出前缀 / --min-len 1 放宽片段门槛")
        for frag in frags[:12]:
            print("  ·", frag)
        return 1
    if args.json:
        import json
        print(json.dumps([{"flag": f.decode("utf-8", "replace"),
                           "parts": [{"kind": p.kind, "text": p.text.decode("utf-8", "replace"),
                                      "offset": p.offset} for p in path]}
                          for f, path in results], ensure_ascii=False, indent=2))
        return 0
    print(f"拼出 {len(results)} 个候选：")
    for flag, path in results:
        print(f"  => {flag.decode('utf-8', 'replace')}")
        for frag in path:
            print(f"       + {frag}")
    return 0


def _auto_solve_args(work: str, s: dict) -> argparse.Namespace:
    """把当前会话参数组装成 solve 的参数对象。"""
    return argparse.Namespace(
        paths=[work], out=s.get("out"), depth=s.get("depth", 4), beam=s.get("beam", 12),
        timeout=s.get("timeout", 60.0), work=s.get("work", 20000), deep=s.get("deep", False),
        key=list(s.get("keys", [])), keys_file=list(s.get("keys_file", [])),
        keys_from=list(s.get("keys_from", [])), key_script=s.get("key_script"),
        fmt=s.get("fmt", ""), reference=s.get("reference"), table=s.get("table"),
        crib=s.get("crib"), crib_regex=bool(s.get("crib_regex", False)),
        no_flag_prefix=bool(s.get("no_flag_prefix", False)),
        verify_binary=s.get("verify_binary"), verify_plain=s.get("verify_plain"),
        verify_cipher=s.get("verify_cipher", "des,des3,aes,rc4,rc4v,xor"),
        verify_key_transform=s.get("verify_key_transform", "raw,bitrev"),
        ciphertext_offset=s.get("ciphertext_offset", -1),
        ciphertext_length=s.get("ciphertext_length", 0),
        keyspace=s.get("keyspace", "none"), length=s.get("length", 6),
        derive=s.get("derive", "raw"), verify_limit=s.get("verify_limit", 2000000),
        no_fragments=bool(s.get("no_fragments", False)),
        recursive=bool(s.get("recursive", False)), json=False)


MENU = """
────────────────────────────────────────────────────────────
 没解出来很正常——逆向题大多需要额外一点信息。可以直接在这里补：
   1  输入密钥重试（也支持 hex: 前缀，如 hex:637a524037000000）
   2  输入已知明文片段（crib，如 flag{ 或 XJUSEC{）后重试
   3  加大预算重试（timeout×3 + --deep）
   4  指定密钥派生脚本（.py，定义 keys() 生成器）
   5  密钥确认：用程序内密文反查（输入 程序文件 与 密文偏移）
   6  换个工具试：identify / fragments / carve / crack / xor / basedecode
   7  打开输出目录
   8  换一个目标路径
   q  退出
────────────────────────────────────────────────────────────"""


def _run_tool(work: str, name: str) -> None:
    """菜单里"换个工具试试"的分发。"""
    path = work
    if os.path.isdir(path):
        files = [os.path.join(path, f) for f in sorted(os.listdir(path))
                 if os.path.isfile(os.path.join(path, f))]
        if not files:
            print("目录里没有文件")
            return
        # 优先挑二进制/可疑文件
        path = max(files, key=lambda f: os.path.getsize(f))
        print(f"（对最大的文件操作：{os.path.basename(path)}）")
    try:
        if name == "identify":
            cmd_identify(argparse.Namespace(target=path, include=[], exclude=[],
                                            tags=False, json=False))
        elif name == "fragments":
            cmd_fragments(argparse.Namespace(file=path, crib=None, min_len=3, max_parts=6,
                                             budget=400000, json=False))
        elif name == "carve":
            cmd_carve(argparse.Namespace(file=path, extract=False, out=None, depth=0,
                                         json=None, min_magic=4, list_sigs=False))
        elif name == "crack":
            cmd_crack(argparse.Namespace(file=path, type="auto", deep=False, out=None))
        elif name == "xor":
            cmd_xor(argparse.Namespace(file=path, max_length=32, most_common=[], hex=False,
                                       out=None))
        elif name == "basedecode":
            cmd_basedecode(argparse.Namespace(target=path, depth=8, allow=None, out=None))
    except Exception as exc:                     # 菜单里出错不要弄崩会话
        print(f"  工具执行出错：{type(exc).__name__}: {exc}")


def _interactive_menu(work: str, state: dict, force: bool = False) -> int:
    """失败后的交互会话：补信息、换工具、反复重试，直到用户退出。

    之所以放在 Python 里而不是 .bat 里：中文提示、UTF-8、输入解析都更好处理。
    ``force`` 用于非交互环境（脚本喂输入）也能走菜单。
    """
    if not sys.stdin or (not sys.stdin.isatty() and not force):
        return 1 if not state.get("solved") else 0
    print(MENU)
    while True:
        try:
            choice = input("选择> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        low = choice.lower()
        if low in ("q", "quit", "exit", "退出"):
            return 0 if state.get("solved") else 1

        if choice == "1":
            raw = input("密钥（hex: 前缀表示十六进制）> ").strip()
            if raw:
                key = _key_bytes(raw)
                state.setdefault("keys", []).append(key)
                print(f"  已加入密钥 {key!r}，重试…")
        elif choice == "2":
            raw = input("已知明文片段/正则（crib）> ").strip()
            if raw:
                state["crib"] = raw
                print(f"  已设置 crib={raw!r}（只认命中它的结果），重试…")
        elif choice == "3":
            state["timeout"] = float(state.get("timeout", 60)) * 3
            state["deep"] = True
            state["work"] = max(20000, int(state.get("work", 20000)) * 3)
            print(f"  预算加大到 timeout={state['timeout']:.0f}s + --deep，重试…")
        elif choice == "4":
            raw = input("密钥派生脚本路径> ").strip().strip('"')
            if os.path.isfile(raw):
                state["key_script"] = raw
                print("  已设置 key-script，重试…")
            else:
                print(f"  找不到文件：{raw}")
                continue
        elif choice == "5":
            binary = input("程序文件路径> ").strip().strip('"')
            if not os.path.isfile(binary):
                print(f"  找不到文件：{binary}")
                continue
            off = input("密文在程序里的文件偏移（十六进制，如 0x6EE02；不知道就回车）> ").strip()
            state["verify_binary"] = binary
            if off:
                try:
                    state["ciphertext_offset"] = int(off, 16) if off.lower().startswith("0x") \
                        else int(off)
                except ValueError:
                    print("  偏移解析失败，忽略")
            length = input("密文字节长度（回车=到文件尾）> ").strip()
            if length.isdigit():
                state["ciphertext_length"] = int(length)
            print("  已设置密钥确认参数（会先反查密钥再解密），重试…")
        elif choice == "6":
            name = input("工具名（identify/fragments/carve/crack/xor/basedecode）> ").strip().lower()
            _run_tool(work, name)
            print(MENU)
            continue
        elif choice == "7":
            try:
                os.startfile(state.get("out") or os.getcwd())      # type: ignore[attr-defined]
                print("  已打开输出目录")
            except Exception as exc:
                print(f"  打开失败：{exc}")
            continue
        elif choice == "8":
            raw = input("新的目标路径> ").strip().strip('"')
            new = pipeline.clean_target(raw)
            if os.path.exists(new):
                work = new
                print(f"  目标已切换为：{work}\n[侦察]")
                cmd_scan(argparse.Namespace(paths=[work],
                                            recursive=bool(state.get("recursive"))))
                print("\n[一条龙]")
            else:
                print(f"  路径不存在：{new}")
                continue
        else:
            print(MENU)
            continue

        print("\n[一条龙重试]")
        rc = cmd_solve(_auto_solve_args(work, state))
        if rc == 0:
            state["solved"] = True
            print("\n✔ 这次有结果了。上面就是解出来的内容，输出目录里也有。")
            print("  还想继续试别的参数就接着选，或者按 q 退出。")
        else:
            print("\n仍然没有结果。")
        print(MENU)


def cmd_pyc(args) -> int:
    """读 .pyc：版本、常量、名字池、反汇编；``--solve`` 还会尝试直接还原 flag。"""
    from . import formula as _formula
    from . import pyc as _pyc
    with open(args.file, "rb") as fh:
        blob = fh.read()
    print(_pyc.report(blob, want_dis=args.dis, as_json=args.json))
    if not args.solve:
        return 0
    try:
        root = _pyc.load_code(blob)
    except Exception as exc:
        print(f"\n[!] 无法解析 code object：{exc}")
        return 1
    info = _pyc.summary(root)
    hex_blobs = [bytes.fromhex(h) for h in info["hex"] if len(h) >= 12]
    ints = [c for c in root.consts if isinstance(c, int)]
    if not hex_blobs:
        print("\n[!] 没找到十六进制常量，跳过公式搜索")
        return 1
    crib = args.crib.encode() if args.crib else None
    print(f"\n[公式搜索] 十六进制常量 {len(hex_blobs)} 个，整数常量 {sorted(set(ints))}，"
          f"crib={crib or _formula.guess_crib(info['strings'])}")
    found = _formula.crack_pyc_constants(hex_blobs, info["strings"], ints, crib=crib,
                                         budget_seconds=args.timeout)
    if not found:
        print("  没有命中。可以试试 --crib 指定前缀，或用 --dis 看反汇编自己读算法")
        return 1
    print(f"  命中 {len(found)} 个：")
    for note, hit in found:
        print(f"    [{hit.score:.2f}] 目标={note}")
        print(f"        {hit.formula}")
        print(f"        → {hit.plaintext.decode('utf-8', 'replace')}")
    return 0


def cmd_formula(args) -> int:
    """逐字节线性公式反推：给"目标字节 + 已知前缀"，还原全文。"""
    from . import formula as _formula
    if args.target.startswith("@"):
        with open(args.target[1:], "rb") as fh:
            raw = fh.read()
        target = bytes.fromhex(re.sub(rb"[^0-9a-fA-F]", b"", raw).decode()) \
            if re.fullmatch(rb"[\s0-9a-fA-F]+", raw[:4096]) else raw
    elif os.path.isfile(args.target):
        with open(args.target, "rb") as fh:
            target = fh.read()
    else:
        target = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", args.target))
    crib = args.crib.encode()
    print(f"目标字节 {len(target)} 字节，crib={crib!r}")
    hits = _formula.solve_blob(target, crib, top=args.top, offset=args.offset,
                               budget_seconds=args.timeout)
    if not hits:
        print("没有解出公式。可以试试：加长 crib、换 --offset、或用 pyc --dis 先看算法")
        return 1
    for hit in hits:
        print("  " + hit.line())
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(hits[0].plaintext)
        print("已写出", args.out)
    return 0


def _read_blob(path: str) -> bytes:
    """读输入文件；``-`` 表示**从 stdin 读**。

    为什么要支持 stdin：遇到杀软把样本锁住（`open()` 直接 Access denied）时，
    `unrar p 样本.rar 样本.exe | autocrypt unpack -` 这种"流式读进内存"是唯一可行路径。
    """
    if path in ("-", "/dev/stdin"):
        import sys
        return sys.stdin.buffer.read()
    with open(path, "rb") as fh:
        return fh.read()


def cmd_triage(args) -> int:
    """逆向题指路：侦察一遍，给出排好序的下一步命令。"""
    from . import triage as _triage
    try:
        info = _triage.triage_path(args.file)
    except OSError as exc:
        # 实测常见：样本被杀软隔离/锁住。给一句人话，别甩 traceback。
        print(f"读不了 {args.file}：{exc}")
        print("  若文件还在但被占用，可以走管道：unrar p ... | python plainseek.py triage -")
        return 2
    if getattr(args, "json", False):
        import json
        payload = dict(info)
        payload["next_steps"] = [{"command": c, "why": w} for c, w in info["next_steps"]]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(_triage.format_report(info))
    return 0


def cmd_unpack(args) -> int:
    """UPX 自动脱壳（在内存里跑壳的 stub，dump 出平铺镜像）。"""
    from . import unpack as _unpack
    blob = _read_blob(args.file)
    print(f"输入：{len(blob)} 字节")
    flat, oep, notes = _unpack.unpack_in_memory(blob, max_ins=args.max_ins)
    for note in notes:
        print(f"  · {note}")
    if not flat:
        print("\n脱壳失败——原因见上面的说明（不是所有壳都能靠模拟执行脱掉）")
        return 1
    out = args.out
    if not out:
        import os
        base = args.file if args.file not in ("-", "/dev/stdin") else "stdin"
        out = os.path.splitext(base)[0] + ".unpacked.bin"
    with open(out, "wb") as fh:
        fh.write(flat)
    print(f"\n已写出：{out}（{len(flat)} 字节，入口 0x{oep:x}）")
    print("下一步可以：scan / sig / crackme / emu 直接对这个文件跑")
    return 0


def cmd_gui(args) -> int:
    """GUI/CrackMe 的"自动判定"辅助：找候选校验入口，并试着让程序自己判对错。"""
    from . import emu as _emu, gui as _gui
    blob = open(args.file, "rb").read()
    img = _emu.load_image(blob)
    print(img.describe().splitlines()[0])
    print(_gui.report(img))
    if args.discover:
        print("\n[自动发现可用判定] 标准：同一个入口下两个不同输入给出**不同**结论")
        found = _gui.discover(img, max_ins=args.max_ins)
        if not found:
            print("  ✗ 没找到可用判定。常见原因：")
            print("    · 成功/失败文案是运行时从资源加载或拼装出来的（探针读不到文本）")
            print("    · 校验在窗口消息/定时器里，需要特定消息或控件句柄才能触发")
            print("    · 程序一进校验就先检查 strlen、控件状态等前置条件")
            print("  这时可以退回**手工路线**：`emu --break`/`--trace-cfg` 找到"
                  "成功分支与失败分支的地址，再用 `coverage` 看走了哪条。")
        for item in found:
            print(f"  ✔ 入口 0x{item['entry']:x}（{item['why']}）"
                  f" 参数={[hex(a) for a in item['args']]}")
            print(f"     各输入判定：{item['verdicts']}")
    return 0


def cmd_sig(args) -> int:
    """签名扫描：加密常量（含"被改过的常量"）+ 打包器 + 熵（借鉴 findcrypt / DIE）。"""
    from . import sigscan as _sig
    from . import emu as _emu
    with open(args.file, "rb") as fh:
        blob = fh.read()
    try:
        img = _emu.load_image(blob)
    except _emu.EmuError as exc:
        print(f"[X] {exc}")
        return 2
    print(f"文件：{args.file}（{len(blob)} 字节）")
    print(_sig.report(img))
    if args.crib:
        extra = [d for d in _sig.decrypt_strings(img, limit=10, try_crib=True)
                 if d not in _sig.decrypt_strings(img, limit=10)]
        if extra:
            print("  多字节异或候选（启发式，需人工确认）：")
            for text, addr, note in extra[:10]:
                print(f"    0x{addr:x}  {text!r}   ← {note}")
        else:
            print("  多字节异或候选：无")
    if args.json:
        import json
        print(json.dumps({
            "packer": (lambda v: v.line() if v else "")(
                _sig.detect_packer(img)),
            "entropy": _sig.section_entropy_table(img),
            "hits": [{"name": h.name, "at": hex(h.at), "similarity": h.similarity,
                      "exact": h.exact, "diffs": h.diffs}
                     for h in _sig.scan_crypto(img)],
        }, ensure_ascii=False, indent=2))
    return 0


def cmd_crackme(args) -> int:
    """CrackMe 辅助：静态找比较点/输入点/可疑字符串，再（可选）模拟执行跑一遍。

    吾爱破解/看雪上的 CrackMe 分两派：控制台小工具（读输入→比较→打印对错）适合
    **模拟执行直接判对错**；GUI 程序（Qt/MFC/Delphi）校验发生在点按钮之后，
    模拟窗口消息不现实，只能走**静态**——所以这个命令两条路都给出：
    先静态列出"读取输入的点""比较的点（含能读出来的字符串）""成败提示串"，
    再加 ``--run`` 把程序真跑起来看它说什么。
    """
    from . import crackme as _crackme
    from . import emu as _emu
    with open(args.file, "rb") as fh:
        blob = fh.read()
    try:
        img = _emu.load_image(blob)
    except _emu.EmuError as exc:
        print(f"[X] {exc}")
        return 2
    print(f"文件：{args.file}（{len(blob)} 字节）")
    print(_crackme.report(img))
    if args.run:
        stdin = (args.stdin or "").encode("utf-8", "surrogateescape")
        if stdin and not stdin.endswith(b"\n"):
            stdin += b"\n"
        res = _emu.run_main(blob, stdin=stdin, max_ins=args.max_ins)
        print(f"\n[模拟执行] 入口 0x{res['entry_used']:x}（{res['entry_why']}）"
              f"  停止：{res['stop']}")
        if res["stdout"]:
            print("  ── 程序输出 ──")
            for line in res["stdout"].splitlines()[:40]:
                print("  | " + line)
        for api, a, b in (res.get("comparisons") or [])[:8]:
            show = lambda v: (v[:60].decode("latin-1", "replace")       # noqa: E731
                              if all(32 <= c < 127 for c in v[:60])
                              else v[:24].hex(" "))
            print(f"  | {api}: {show(a)!r}  vs  {show(b)!r}")
        for guess in res.get("expected") or []:
            print(f"  ★ 疑似程序期望的输入：{guess!r}")
        verdict = {True: "程序认为这个输入是对的",
                   False: "程序认为这个输入是错的",
                   None: "没看出明确的成败字样"}[res["result"]]
        print(f"  判定：{verdict}")
    return 0


def cmd_emu(args) -> int:
    """模拟执行取证：把"跑一遍才知道的常量"挖出来（ELF x86-64）。

    逆向题里有一大类，答案**不在文件里，而在程序跑起来之后**：运行时用 LCG +
    洗牌生成的置换表、被改过常量的密码算法、自修改代码解密出来的真代码。
    这个命令就是为它们准备的：``--call`` 跑一个函数，然后把"它改写了哪块内存"
    直接报出来（如果改写的正好是 ``0..n-1`` 的一个排列，还会自动标成"置换表"）。
    """
    from . import emu as _emu
    with open(args.file, "rb") as fh:
        blob = fh.read()
    try:
        img = _emu.load_image(blob)
    except _emu.EmuError as exc:
        print(f"[X] {exc}")
        return 2
    anchors = [a.encode("utf-8", "surrogateescape") for a in (args.anchor or [])]
    if isinstance(img, _emu.ElfImage):
        print(_emu.report(blob, anchors))
    else:
        from . import pe as _pe
        print(_pe.report(blob, anchors))

    # --run / --stdin：把程序自己跑起来，让它自己判"这个输入对不对"。
    # PE 的导入表会被接管（strcmp/memcmp/fgets/printf… 全部由宿主实现），
    # TEB/PEB 也会铺好，所以反调试探测一律看到"没有调试器"。
    if args.run or args.stdin is not None or args.stdin_file or args.list_candidates:
        stdin = b""
        if args.stdin_file:
            with open(args.stdin_file, "rb") as fh:
                stdin = fh.read()
        if args.stdin is not None:
            stdin = args.stdin.encode("utf-8", "surrogateescape")
            if not stdin.endswith(b"\n"):
                stdin += b"\n"
        cands = _emu.find_check_functions(img)
        if args.list_candidates or not args.call:
            if cands:
                print("\n[校验函数候选]（按证据强度排序）")
                for addr, why, weight in cands:
                    print(f"  0x{addr:x}  权重={weight}  {why}")
            elif args.list_candidates:
                print("\n没找到明显的校验函数候选（可以用 --call 手动指定）")
        if args.run or args.stdin is not None or args.stdin_file:
            res = _emu.run_main(blob, stdin=stdin, max_ins=args.max_ins,
                                addr=int(args.call, 0) if args.call else 0,
                                stop_at=[int(b, 0) for b in (args.break_at or [])],
                                coverage=bool(args.trace_cfg))
            print(f"\n[运行程序] 入口 0x{res['entry_used']:x}（{res['entry_why']}）")
            print(f"  停止：{res['stop']}   指令数={res['ins']}")
            if res.get("hit"):
                regs = ", ".join(f"{k}=0x{v:x}" for k, v in res["regs"].items())
                print(f"  ── 断点命中，寄存器现场 ──\n  | {regs}")
                # 断点处最有用的是"寄存器指向的可读字符串"（比较的两个操作数常在这）
                for name, value in res["regs"].items():
                    if name in ("esp", "ebp"):
                        continue
                    ptr = value & (0xFFFFFFFF if img.bits == 32 else
                                   0xFFFFFFFFFFFFFFFF)
                    text = _emu.read_mem(img, ptr, 64, uc=res["raw"]["_uc"])
                    printable = text.split(b"\x00")[0]
                    if len(printable) >= 3 and all(32 <= c < 127 for c in printable):
                        print(f"  | {name} → {printable!r}")
            for note in res["api_notes"][:10]:
                print(f"  · {note}")
            out = res["stdout"]
            if out:
                print("  ── 程序输出 ──")
                for line in out.splitlines()[:40]:
                    print("  | " + line)
            if res.get("comparisons"):
                print("  ── 程序内部比较了什么（CrackMe 的期望值通常就在这儿）──")
                for api, a, b in res["comparisons"][:8]:
                    show = lambda v: (v[:60].decode("latin-1", "replace")  # noqa: E731
                                      if all(32 <= c < 127 for c in v[:60])
                                      else v[:24].hex(" "))
                    print(f"  | {api}: {show(a)!r}  vs  {show(b)!r}")
            for guess in res.get("expected") or []:
                print(f"  ★ 疑似程序期望的输入：{guess!r}")
            # FLOSS 式"字符串解密"：模拟执行前后做了内存差分，把**新出现的可打印串**
            # 挑出来（栈串、异或串、运行时解出来的提示语都算）。
            if res.get("raw", {}).get("changes"):
                from . import sigscan as _sig
                print("  ── 运行时新出现的字符串（内存差分，FLOSS 思路）──")
                shown = 0
                for at, data in res["raw"]["changes"]:
                    for text in _sig.new_strings(b"", data, min_len=5, limit=12):
                        print(f"  | 0x{at:x}: {text!r}")
                        shown += 1
                        if shown >= 20:
                            break
                    if shown >= 20:
                        break
                if not shown:
                    print("  | （没有新字符串，可能只是写表/写缓冲）")
            verdict = {True: "✔ 程序认为这个输入是对的",
                       False: "✗ 程序认为这个输入是错的",
                       None: "? 没看出明确的成败字样，自己看上面的输出"}[res["result"]]
            print(f"  判定：{verdict}")
            if args.trace_cfg and res.get("coverage"):
                lines = _emu.trace_disasm(img, res["coverage"], limit=args.max_ins)
                print(f"\n[真实执行轨迹反汇编] 覆盖 {len(res['coverage'])} 个地址，"
                      f"解出 {len(lines)} 条指令（前 60 条）：")
                for addr, mnem, ops in lines[:60]:
                    print(f"    0x{addr:x}  {mnem:<10} {ops}")
                if len(lines) > 60:
                    print(f"    …（共 {len(lines)} 条）")
            return 0 if res["result"] is not False else 1

    did = False
    for spec in (args.imm or []):
        addr, _, cnt = spec.partition(":")
        vals = _emu.immediates(img, int(addr, 0), count=int(cnt or 24))
        print(f"\n[立即数] 0x{int(addr, 0):x} 附近的可疑常量：")
        for v in vals:
            note = ""
            # 顺手对"被改过的密码算法"给点提示：标准常量 / 常见 delta 的影子
            if v in (0x9E3779B9, 0x9E3779B1, 0x61C88647, 0x85EBCA6B, 0xC2B2AE35):
                note = "  ← 标准常量（没被改）"
            elif 0x10000000 < v < 0xFFFFFFFF and (v >> 24) & 0xFF:
                note = "  ← 疑似轮常量/delta"
            print(f"   0x{v:08x}{note}")
        did = True

    if args.call:
        addr = int(args.call, 0)
        argv = [int(a, 0) for a in (args.args or [])]
        res = _emu.run_function(img, addr, argv, max_ins=args.max_ins,
                                trace=args.trace)
        print(f"\n[模拟执行] 0x{addr:x}({', '.join(hex(a) for a in argv)})：")
        print(f"  指令数={res['ins']}  返回 rax=0x{res['ret']:x}({res['ret']})")
        print(f"  停止原因：{res['stop']}")
        for i, at in enumerate(res["trace"][:12]):
            print(f"    → 0x{at:x}")
        if res["trace"] and len(res["trace"]) > 12:
            print(f"    …（共 {len(res['trace'])} 条）")
        for at, data in res["changes"]:
            preview = data[:32].hex(" ")
            print(f"  [改写内存] 0x{at:x} len={len(data)}：{preview}"
                  f"{' …' if len(data) > 32 else ''}")
        for at, n in res["tables"]:
            table = _emu.read_mem(img, at, n, uc=res["_uc"])
            print(f"  ★ 运行时生成的置换表 @0x{at:x} n={n}：{table.hex(' ')}")
            print("    （0..n-1 的排列 → 洗牌表 / S 盒 / 字符表就是这种特征）")
        if args.dump_to:
            os.makedirs(args.dump_to, exist_ok=True)
            for idx, (at, data) in enumerate(res["changes"]):
                path = os.path.join(args.dump_to, f"change_{idx}_0x{at:x}.bin")
                with open(path, "wb") as fh:
                    fh.write(data)
                print(f"  已写出 {path}")
        for spec in (args.dump or []):
            addr_s, _, size_s = spec.partition(":")
            mem_addr, size = int(addr_s, 0), int(size_s or 64, 0)
            data = _emu.read_mem(img, mem_addr, size, uc=res["_uc"])
            print(f"  [读内存] 0x{mem_addr:x} 起 {size} 字节：{data.hex(' ')}")
        did = True

    if not did:
        print("\n（只做了侦察。想看某个函数干了什么：--call 0x地址；"
              "想看它的常量：--imm 0x地址；找函数入口：--anchor '提示字符串'）")
    return 0


def cmd_stego(args) -> int:
    """隐写分析：BMP 位平面提取 + WAV 音频（含把频谱图还原成终端点阵）。

    为什么要有这个命令：链式搜索那套"试算法"对隐写完全无效——你没法给一堆
    错位提取的字节打分。这里的思路是**枚举结构组合 + 文本判据筛选**，
    外加"把看不懂的东西画出来 / 打成 ASCII"给人看。
    """
    from . import stego as _stego
    with open(args.file, "rb") as fh:
        data = fh.read()
    kind = args.kind
    if kind == "auto":
        if data[:2] == b"BM":
            kind = "bmp"
        elif data[:4] == b"RIFF":
            kind = "wav"
        else:
            print("[!] 既不是 BMP 也不是 WAV；可用 --kind 强制指定")
            return 2
    print(f"文件 {args.file}（{len(data)} 字节，按 {kind.upper()} 处理）")
    info = _stego.report(data, kind)
    if info:
        print(info)

    if kind == "bmp":
        cands = _stego.scan_lsb(data, top=args.top)
        if not cands:
            print("没有找到「看起来像文本」的位平面。可能：数据被加密了（先拿密钥，"
                  "再用 --dump 导出原始位流去做解密），或用了更复杂的像素排列。")
        else:
            print(f"\n位平面候选（按「像文本」排序，共 {len(cands)} 条）：")
            for cand in cands:
                preview = cand.head.replace("\n", " ")[:60]
                print(f"  [{cand.score:.3f}] {cand.tag()}  开头={preview!r}")
        if args.spectrogram or args.dump:
            pass
        if args.dump:
            # 导出"指定的那一组"位流，方便拿密钥后离线解密（隐写题的常见组合拳）
            p = _stego.bmp_pixels(data)
            if p:
                buf = _stego.lsb_extract(p, args.channel or "b", args.bit,
                                         not args.lsb_first, args.order,
                                         stride=args.stride,
                                         snake=args.snake,
                                         skip_pixels=args.skip_pixels)
                with open(args.dump, "wb") as fh:
                    fh.write(buf)
                print(f"已导出位流 {len(buf)} 字节 → {args.dump}"
                      f"（通道={args.channel or 'b'} 位={args.bit} 顺序={args.order}"
                      f"{' 蛇形' if args.snake else ''}"
                      f"{f' 跳过{args.skip_pixels}像素' if args.skip_pixels else ''}）")
        return 0

    # WAV：能自动的先自动，不能自动的（画成频谱图）就导出给人看
    code = _stego.dtmf_decode(_stego.wav_info(data))
    if code:
        print(f"DTMF 试解：{code}")
    if args.spectrogram:
        out = _stego.spectrogram_png(data, args.spectrogram)
        if out:
            print(f"频谱图已导出 → {out}（用看图软件打开，出题人常把密钥「画」在这里）")
        else:
            print("[!] 需要 numpy + Pillow 才能导出频谱图；也可以用 Audacity 自己看")
    if args.ascii_art:
        art = _stego.tone_grid_ascii(data)
        if art:
            print("\n" + art)
        else:
            print("[!] 频谱点阵还原失败（音频太短或需要 numpy）")
    if args.dump:
        info_w = _stego.wav_info(data)
        if info_w:
            with open(args.dump, "wb") as fh:
                fh.write(info_w.samples)
            print(f"已导出原始采样 → {args.dump}（{info_w.describe()}）")
    return 0


def cmd_auto(args) -> int:
    """给"拖进来就能跑"用的入口：文件 / 文件夹 / zip 都能吃。

    * zip → 安全解压到 ``<名字>_extracted`` 再处理（附件通常就是压缩包）；
    * 逐个文件侦察（scan），再交给一条龙（solve）；
    * ``--menu``（启动器默认开启）：解不出来时留在窗口里，让你补密钥 / crib /
      派生脚本 / 密钥确认参数，或换别的工具，反复重试直到退出。
    """
    import zipfile
    target = pipeline.clean_target(args.target)
    if not os.path.exists(target):
        print(f"[X] 路径不存在：{target}")
        return 2

    work = target
    if os.path.isfile(target) and zipfile.is_zipfile(target):
        base = os.path.splitext(os.path.abspath(target))[0] + "_extracted"
        os.makedirs(base, exist_ok=True)
        print(f"检测到压缩包 → 解压到 {base}")
        with zipfile.ZipFile(target) as zf:
            for info in zf.infolist():
                name = info.filename
                dest = os.path.abspath(os.path.join(base, name))
                if not dest.startswith(os.path.abspath(base)):      # 防 zip-slip
                    print(f"  跳过可疑条目：{name}")
                    continue
                zf.extract(info, base)
        work = base

    print("=" * 62)
    print(" autocrypt 一条龙：文件 / 文件夹 / 压缩包通吃")
    print("=" * 62)
    print(f"目标：{work}\n")
    print("[1/2] 侦察")
    cmd_scan(argparse.Namespace(paths=[work], recursive=args.recursive))

    print("\n[2/2] 一条龙解密")
    state = {
        "out": args.out, "depth": args.depth, "beam": args.beam, "timeout": args.timeout,
        "work": args.work, "deep": args.deep, "keys": list(args.key),
        "keys_file": list(args.keys_file), "keys_from": list(args.keys_from),
        "key_script": args.key_script, "fmt": args.fmt, "reference": args.reference,
        "table": args.table, "crib": args.crib, "crib_regex": args.crib_regex,
        "no_flag_prefix": args.no_flag_prefix, "verify_binary": args.verify_binary,
        "verify_plain": args.verify_plain, "verify_cipher": args.verify_cipher,
        "verify_key_transform": args.verify_key_transform,
        "ciphertext_offset": args.ciphertext_offset,
        "ciphertext_length": args.ciphertext_length, "keyspace": args.keyspace,
        "length": args.length, "derive": args.derive, "verify_limit": args.verify_limit,
        "no_fragments": args.no_fragments, "recursive": args.recursive, "solved": False,
    }
    rc = cmd_solve(_auto_solve_args(work, state))
    if rc == 0:
        state["solved"] = True
    if rc != 0:
        _suggest_next_steps(work)
    # 交互终端默认开启菜单；--no-menu 关闭；--menu 强制开启（脚本喂输入也能用）
    want_menu = bool(getattr(args, "menu", False)) or (
        not getattr(args, "no_menu", False) and sys.stdin is not None and sys.stdin.isatty())
    if want_menu:
        return _interactive_menu(work, state, force=bool(getattr(args, "menu", False)))
    return rc


def _suggest_next_steps(work: str) -> None:
    """解不出来时，按目录里**实际有什么**给出下一步命令建议。

    这一条很重要：链式搜索失败**不代表没救**，而是说明这题属于另一类
    （要跑程序 / 要拆隐写 / 要读字节码）。与其让人对着"没有解出结果"发呆，
    不如直接告诉他："这目录里有 ELF，去用 emu；有 BMP/WAV，去用 stego。"
    """
    found = {"elf": [], "pe": [], "bmp": [], "wav": [], "pyc": [], "arch": []}
    root = work if os.path.isdir(work) else os.path.dirname(os.path.abspath(work))
    for dirpath, _dirs, files in os.walk(root):
        if os.path.basename(dirpath).lower() in ("recovered", "recovered_v2",
                                                 "recovered_final", "out"):
            continue
        for name in files:
            path = os.path.join(dirpath, name)
            low = name.lower()
            try:
                with open(path, "rb") as fh:
                    head = fh.read(8)
            except OSError:
                continue
            if low.endswith(".pyc") or (len(head) >= 4 and head[0:2] in (b"\x42\x0d",)
                                        and head[2] == 0x0D):
                found["pyc"].append(path)
            elif head[:4] == b"\x7fELF":
                found["elf"].append(path)
            elif head[:2] == b"MZ":
                found["pe"].append(path)
            elif head[:2] == b"BM":
                found["bmp"].append(path)
            elif head[:4] == b"RIFF":
                found["wav"].append(path)
            elif low.endswith((".zip", ".tar", ".gz", ".7z", ".rar")):
                found["arch"].append(path)
    tips = []
    if found["elf"] or found["pe"]:
        target = (found["elf"] or found["pe"])[0]
        tips.append(f"这是**可执行文件**，答案可能只在「跑起来之后」才存在：\n"
                    f"      python autocrypt.py emu \"{target}\" --anchor 「提示字符串」\n"
                    f"      （先看段/入口，再 --call 某个函数，看它改写了哪块内存；"
                    f"若出现 ★ 置换表，就是运行时生成的表）")
    if found["bmp"] or found["wav"]:
        for target in (found["bmp"] + found["wav"])[:2]:
            tips.append(f"这是**隐写**素材：\n"
                        f"      python autocrypt.py stego \"{target}\""
                        + (" --spectrogram spec.png --ascii-art" if target in found["wav"] else ""))
    if found["pyc"]:
        tips.append(f"这是 **Python 字节码**：\n"
                    f"      python autocrypt.py pyc \"{found['pyc'][0]}\" --solve --dis")
    if found["arch"]:
        tips.append(f"里面还有压缩包（可能是二次打包）：\n"
                    f"      python autocrypt.py auto \"{found['arch'][0]}\"")
    if not tips:
        return
    print("\n" + "=" * 62)
    print(" 没解出来 ≠ 没救：按目录里的文件类型，下一步可以这么走")
    print("=" * 62)
    for tip in tips:
        print("  · " + tip)
    print("  · 想让工具带着密钥/前缀再试一遍：进交互菜单（默认已开启），"
          "或加 --key / --crib 重跑")


def cmd_bulk(args) -> int:
    with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
        lines = [line.strip() for line in fh if line.strip()]
    out_lines: List[str] = []
    for i, line in enumerate(lines):
        hits = identify.identify(line)
        kind = hits[0].name if hits else "未知"
        decoded = baseN.magic_decode_best(line.encode())
        text = ""
        if decoded and decoded.score > 0.3:
            try:
                text = decoded.data.decode("utf-8", "replace")
            except Exception:
                text = decoded.data.hex()
        print(f"[{i:03d}] {kind:32s} {line[:36]}")
        if text:
            print(f"      → {' → '.join(decoded.chain)}: {text[:80]}")
            out_lines.append(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out_lines))
        print("结果已写出", args.out)
    return 0


def cmd_selftest(args) -> int:
    from . import selftest
    return selftest.main()


def main(argv: Optional[List[str]] = None) -> int:
    _setup_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = {
        "scan": cmd_scan, "solve": cmd_solve, "chain": cmd_chain, "pair": cmd_pair,
        "table": cmd_table, "oracle": cmd_oracle, "transforms": cmd_transforms,
        "identify": cmd_identify, "xor": cmd_xor, "basedecode": cmd_basedecode,
        "carve": cmd_carve, "crack": cmd_crack, "bulk": cmd_bulk, "verify": cmd_verify,
        "fragments": cmd_fragments, "auto": cmd_auto, "pyc": cmd_pyc,
        "formula": cmd_formula, "stego": cmd_stego, "emu": cmd_emu,
        "crackme": cmd_crackme, "sig": cmd_sig, "gui": cmd_gui, "unpack": cmd_unpack,
        "triage": cmd_triage,
        "selftest": cmd_selftest,
    }[args.cmd]
    return handler(args)
