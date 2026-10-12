"""实验：确定 Python 3.13 marshal 里 code object 的字段布局。

做法：marshall 一个已知的小函数，然后按 3.10 的解析方式走一遍字段，
把每一段读到的原始值打印出来，和内存里 co_* 的真实值对照。
"""
import importlib.util
import marshal
import os
import struct
import sys

# 仓库根目录由 __file__ 推出，别写本机绝对路径（公开仓库里别人也能直接跑）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

src = "def f(a, b=1):\n    x = a + b\n    return x * 2\n"
code = compile(src, "<t>", "exec")
inner = [c for c in code.co_consts if hasattr(c, "co_code")][0]

real = {
    "argcount": inner.co_argcount,
    "posonly": inner.co_posonlyargcount,
    "kwonly": inner.co_kwonlyargcount,
    "nlocals": inner.co_nlocals,
    "stacksize": inner.co_stacksize,
    "flags": inner.co_flags,
    "firstlineno": inner.co_firstlineno,
    "len(code)": len(inner.co_code),
    "consts": len(inner.co_consts),
    "names": list(inner.co_names),
    "varnames": list(inner.co_varnames),
    "freevars": list(inner.co_freevars),
    "cellvars": list(inner.co_cellvars),
    "filename": inner.co_filename,
    "name": inner.co_name,
    "qualname": getattr(inner, "co_qualname", None),
}
print("真实值：")
for k, v in real.items():
    print(f"   {k:14s} {v}")

blob = marshal.dumps(inner)
print(f"\nmarshal 数据 {len(blob)} 字节，首字节 {blob[:1]!r}")
pos = 1                                   # 跳过 'c'
ints = []
for i in range(6):
    val = struct.unpack("<i", blob[pos:pos + 4])[0]
    ints.append(val)
    print(f"   前 6 个 int32 候选[{i}] = {val}")
    pos += 4
print("  接下来 8 个字节:", blob[pos:pos + 8])
print("  （若第 6 个 int 就是 flags，说明 3.13 仍然写 nlocals；否则只写 5 个）")
print("  真实 nlocals/stacksize/flags =", inner.co_nlocals, inner.co_stacksize, inner.co_flags)
