"""模拟执行脚本模板 —— 需要跑程序自己的密钥构造/解密机器码时用。

用法：
    python autocrypt.py verify <程序> --keyspace digits --length 6 \
        --key-script examples/keyderive_template.py \
        --emulate-script examples/emulate_template.py

工具会做三件事：
1. 按 ``--keyspace`` / ``--key-script`` 枚举候选密钥（带"输入"标签）；
2. 对每个候选调用本脚本的 ``verify(key, blob, label)``；
3. 用结构判据（长度前缀+flag、flag 正则、文件格式…）判断你返回的字节，命中即停。

你只需要把"程序怎么用这个密钥解出明文"这一段补上。两种常见写法：

A. 直接调密码库复刻程序逻辑（不需要 unicorn，最快）
B. 用 unicorn 跑程序里的机器码（需要 pip install unicorn）

官方题解 `distorted` 就是这么验证机器码的：把 PT_LOAD 段映射进 Unicorn，
设置寄存器，emu_start(起始地址, 结束地址)。下面 B 段留了骨架。
"""

from __future__ import annotations

import struct


def verify(key: bytes, blob: bytes, label: str):
    """返回解出来的明文（bytes）；返回 None 表示这个候选不是答案。"""
    return _by_library(key, blob, label)
    # return _by_unicorn(key, blob, label)


def _by_library(key: bytes, blob: bytes, label: str):
    """写法 A：用 pycryptodome 复刻程序逻辑（示例：DES-ECB + 位反转密钥）。"""
    try:
        from Crypto.Cipher import DES
    except Exception:
        return None
    k = bytes(int(f"{b:08b}"[::-1], 2) for b in key[:8])       # 位选取表反转 → 密钥按位倒序
    cipher = DES.new(k, DES.MODE_ECB)
    # 这里要填"密文在程序里的位置"；也可以换成程序里那段的实际偏移
    ciphertext = blob[0x6EE02:0x6EE02 + 48] if len(blob) > 0x6EE02 + 48 else b""
    if not ciphertext:
        return None
    return cipher.decrypt(ciphertext)


def _by_unicorn(key: bytes, blob: bytes, label: str):
    """写法 B：用 Unicorn 跑程序自己的解密机器码。

    需要你先用 IDA/Ghidra/radare2 找到：
      * 解密函数地址（start / end）
      * 密钥缓冲区、输入缓冲区的虚拟地址，以及调用的寄存器约定
    下面按 x86-64 的常见约定写，按需改。
    """
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
        from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX
    except Exception:
        return None

    EMU_BASE = 0x100000
    BUF_KEY = 0x200000
    BUF_DATA = 0x210000
    STACK = 0x220000

    emu = Uc(UC_ARCH_X86, UC_MODE_64)
    for base, size in ((0, 0x10000), (EMU_BASE, 0x200000), (STACK, 0x10000),
                       (BUF_KEY, 0x10000), (BUF_DATA, 0x10000)):
        emu.mem_map(base, size)

    # 把程序里需要执行的代码/数据搬进模拟器（PE 用 pefile、ELF 用 pyelftools 更省事）
    emu.mem_write(EMU_BASE, blob[:0x100000])          # 简化：整段搬到固定基址
    emu.mem_write(BUF_KEY, key)
    emu.mem_write(BUF_DATA, blob[0x6EE02:0x6EE02 + 48])
    emu.reg_write(UC_X86_REG_RSP, STACK + 0x8000)
    emu.reg_write(UC_X86_REG_RDI, BUF_KEY)
    emu.reg_write(UC_X86_REG_RSI, BUF_DATA)
    emu.reg_write(UC_X86_REG_RDX, 48)

    try:
        emu.emu_start(EMU_BASE + 0x449E40, EMU_BASE + 0x44A300, count=2_000_000)
    except Exception:
        return None
    return bytes(emu.mem_read(BUF_DATA, 48))
