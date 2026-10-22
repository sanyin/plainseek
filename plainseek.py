#!/usr/bin/env python3
"""plainseek —— 从文件到明文，一层层找，每一步给证据（入口）。

用法：
    python plainseek.py scan   <文件或目录>
    python plainseek.py triage <文件>              # 逆向题：侦察 + 下一步建议
    python plainseek.py auto   <文件/目录/压缩包>  # 常见编码与多层加密，全自动
    python plainseek.py solve  <文件或目录> -o <输出目录>
    python plainseek.py selftest

命名说明：plainseek 是**寻明文**，不是"保证给出明文"。
能全自动的那一档见 README「A 档」，需要人工判断的见「B 档」。

详细说明见 README.md / README.en.md。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pseek.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
