"""实验：确定 Python 3.10 marshal 里哪些对象会占 ref 槽。

做法：对同一份数据试几种"占槽策略"，看哪种能完整解析出来。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import ensure_repo_on_path, sample      # noqa: E402

ensure_repo_on_path()
from pseek import pyc                                # noqa: E402

blob = sample("_投稿测试/R10_pyc/check.pyc").read_bytes()


class Variant(pyc._Reader):
    """mode: strings_all=所有字符串占槽；interned_only=只有 INTERNED 占槽（默认）"""

    def __init__(self, data, version="3.10", strings_all=False):
        super().__init__(data, version)
        self.strings_all = strings_all

    def _typed(self, ch, ref=False):
        if ch in (b"s", b"t", b"u", b"a", b"A", b"z", b"Z"):
            if ch in (b"s", b"t"):
                value = self.string()
            elif ch == b"u":
                value = self.unicode()
            elif ch in (b"a", b"A"):
                value = self.string().decode("ascii", "replace")
            else:
                value = self.short_string().decode("ascii", "replace")
            take = ref or ch in (b"t", b"A", b"Z") or self.strings_all
            if take:
                self.refs.append(value)
            return value
        return super()._typed(ch, ref)


for strings_all in (False, True):
    body = blob[16:]
    r = Variant(body, "3.10", strings_all=strings_all)
    try:
        root = r.object()
        print(f"strings_all={strings_all}: 解析成功，refs={len(r.refs)}，"
              f"顶层={root.name!r}，子 code={[c.name for c in root.walk()]}")
        info = pyc.summary(root)
        print("   hex 常量:", info["hex"][:2])
    except Exception as exc:
        print(f"strings_all={strings_all}: 失败 {type(exc).__name__}: {exc}（已用 refs={len(r.refs)}）")
