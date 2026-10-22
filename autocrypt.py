#!/usr/bin/env python3
"""向后兼容入口：这个工具已更名为 **plainseek**，本文件只做转发。

老命令继续可用，只是会多一行提示：

    python autocrypt.py scan ./x      # 老写法（仍然能用）
    python plainseek.py scan ./x      # 新写法

为什么留着它：改名不该打断别人（也包括我自己）已经写好的脚本和快捷方式。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pseek.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.stderr.write(
        "[提示] autocrypt 已更名为 plainseek，建议改用 `python plainseek.py ...`\n"
    )
    sys.exit(main())
