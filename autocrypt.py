#!/usr/bin/env python3
"""autocrypt —— 一条龙解密工具（入口）。

用法：
    python autocrypt.py scan  <文件或目录>
    python autocrypt.py solve <文件或目录> -o <输出目录>
    python autocrypt.py chain "rev,hex,xor:0x5a" <文件>
    python autocrypt.py pair  <明文> <密文>
    python autocrypt.py selftest

详细说明见 README.md。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dkit.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
