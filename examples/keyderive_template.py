"""密钥派生脚本模板 —— 把程序里的派生逻辑照抄成十几行，剩下交给 autocrypt。

用法：
    python autocrypt.py verify <程序> --keyspace digits --length 6 \
        --key-script examples/keyderive_template.py --cipher des --key-transform bitrev

要点：
* ``keys(ctx)`` 是生成器，逐个产出候选密钥；
* 强烈建议 **yield (输入, 密钥)** 两元组，这样工具能把"哪个输入是对的"直接报给你；
* 生成器里只写"程序怎么从输入算密钥"这一段，不用管解密和判断——
  解密与判断由工具用"程序里存着的密文"或结构判据完成。

下面这个示例就是真实题目 `100w`（易语言 + DES 位选取表反转）的派生逻辑：
输入 6 位数字 → MD5 → 按五行公式得到一个 5 字符串密钥 → 右侧补零到 8 字节。
"""

from __future__ import annotations

import hashlib


def _num_prefix(text: str) -> int:
    """照抄程序的 num()：从开头读十进制数字，遇到非数字停止；开头即非数字得 0。"""
    digits = ""
    for ch in text:
        if ch.isdigit():
            digits += ch
        else:
            break
    return int(digits) if digits else 0


def keys(ctx=None):
    for i in range(1_000_000):
        token = f"{i:06d}"
        h = hashlib.md5(token.encode()).hexdigest()
        # 1) MD5 前几位的算术平均
        part1 = chr((ord(h[0]) + ord(h[5]) + ord(h[7])) // 3)
        # 2) h[1:5] 转数字后对 3 取模
        part2 = str(_num_prefix(h[1:5]) % 3)
        # 3) h[13:15] 转数字后 mod 26 再加 60
        part3 = chr(_num_prefix(h[13:15]) % 26 + 60)
        # 4) h 各字符 ASCII 之和减去常数
        part4 = chr((sum(h.encode()) - 2380) & 0xFF)
        # 5) 再 MD5 一次，取首位十六进制字符的 ASCII 码 mod 90
        part5 = str(ord(hashlib.md5(h.encode()).hexdigest()[0]) % 90)
        text_key = part1 + part2 + part3 + part4 + part5

        # 程序在按钮回调里把第 2 个字符加了 72，然后只保留前 5 个字符
        text_key = text_key[:1] + chr(ord(text_key[1]) + 72) + text_key[2:]
        text_key = text_key[:5]

        # 文本密钥循环异或进 8 字节缓冲区（不足补零）
        key_buf = text_key.encode("latin-1", "ignore")[:5]
        key_buf = key_buf + b"\x00" * (8 - len(key_buf))
        yield token, key_buf
