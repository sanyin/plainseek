"""对 12 套投稿题跑"片段拼接"，并与期望 flag 对照（分辨真解 / 诱饵）。"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import ensure_repo_on_path, sample      # noqa: E402

ensure_repo_on_path()
from pseek import fragments                          # noqa: E402

ROOT = str(sample("_投稿测试"))
flags = {}
with open(os.path.join(ROOT, "_flags.tsv"), encoding="utf-8") as fh:
    for line in fh:
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 2:
            flags[parts[0]] = parts[1]

print(f"{'题目':<16} {'真flag命中':<10} {'候选数':<6} {'最像的拼接结果':<52} 用时")
print("-" * 108)
summary = []
for challenge in sorted(flags):
    d = os.path.join(ROOT, challenge)
    if not os.path.isdir(d):
        continue
    expected = flags[challenge].encode()
    best_print = ""
    n_cand = 0
    hit = False
    used = 0.0
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name)
        if not os.path.isfile(p) or name == "solve.log" or name.endswith(".txt"):
            continue          # readme 里不含 flag，跳过（题目描述不算附件内容）
        try:
            with open(p, "rb") as fh:
                blob = fh.read()
        except OSError:
            continue
        t0 = time.time()
        try:
            frags = fragments.collect_fragments(blob)
            res = fragments.reassemble_flags(frags, crib=b"XJUSEC{")
        except Exception as exc:
            print(f"{challenge:<16} 异常 {exc}")
            continue
        used += time.time() - t0
        n_cand += len(res)
        for flag, path in res:
            if not best_print:
                best_print = flag.decode("utf-8", "replace")
            if flag == expected:
                hit = True
                best_print = flag.decode("utf-8", "replace") + "  ← 真 flag"
                break
    summary.append((challenge, hit, n_cand))
    print(f"{challenge:<16} {'✔' if hit else '✘':<10} {n_cand:<6} {best_print[:50]:<52} {used:.1f}s")

print("-" * 108)
print(f"片段拼接命中真 flag：{sum(1 for _, h, _ in summary if h)}/{len(summary)}")
