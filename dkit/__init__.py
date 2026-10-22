"""兼容别名：包已更名为 :mod:`pseek`。

这个包不包含任何实现，只是把 ``dkit`` 指到 ``pseek`` 上，
好让改名之前写的脚本（``from dkit import ciphers``）继续能跑。

新代码请直接用::

    from pseek import ciphers

如果哪天确认没人再用旧名字，删掉这个目录即可。
"""

import sys

import pseek

# 让 `import dkit.x` / `from dkit import x` 都落到 pseek 上
sys.modules[__name__] = pseek
