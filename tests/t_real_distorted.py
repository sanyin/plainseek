"""实测：distorted 题目（自定义 Base64 字符表 + 改造 RC4）。

只剥掉 RC4 层，剩下的"密码表被打乱的 Base64"完全交给 TableSolver 用结构约束还原，
不再像原题解那样硬编码枚举 720 种排列。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dkit import alphabets, oracles
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import sample                            # noqa: E402

KEY = b"CCB_M4gic_K3y_2026"
ROOT = str(sample("待解题/attachment"))
EXPECTED = b"mBVfrIouxs947KW1YbLS/CM8tUGARHQ+0TEgzp6kNFyDea3j5lPZqdXh2nOciJvw"


def crypt(data):
    state = list(range(256))
    cursor = 0
    for index in range(256):
        cursor = (cursor + state[index] + KEY[index % len(KEY)]) & 255
        state[index], state[cursor] = state[cursor], state[index]
    index = cursor = 0
    output = bytearray()
    for value in data:
        index = (index + 1) & 255
        cursor = (cursor + state[index]) & 255
        state[index], state[cursor] = state[cursor], state[index]
        mask = state[(state[index] * state[cursor] + 0x72) & 255] ^ 0x37
        output.append(value ^ mask)
    return bytes(output)


def load(name):
    with open(os.path.join(ROOT, name), "rb") as fh:
        return fh.read()


readme_plain = load("readme.txt")
readme_enc = crypt(load("readme.txt.enc"))
flag_enc = crypt(load("flag.txt.enc"))
logo_enc = crypt(load("logo.jpg.enc"))

print("RC4 剥离后 readme 层:", readme_enc[:48])
print("字符表识别:", alphabets.detect_alphabets(logo_enc))

text_oracle = oracles.get_oracle("text").check
jpeg_oracle = oracles.get_oracle("jpeg").check
ref = alphabets.reference_segments("jpeg", None, (64, 64))
print("参考 JPEG 段数:", len(ref) if ref else 0)

streams = [
    # 最"硬"的约束（图片结构）放前面，回溯时最先剪枝
    alphabets.Stream("logo.jpg", logo_enc, fmt="jpeg",
                     known_spans=[(0, b"\xff\xd8\xff")],
                     oracle=jpeg_oracle, ref_segments=ref),
    alphabets.Stream("readme.txt", readme_enc, oracle=text_oracle,
                     known_spans=[(0, readme_plain)]),
    alphabets.Stream("flag.txt", flag_enc, fmt="flag", oracle=text_oracle),
]

solver = alphabets.TableSolver(streams, log=lambda m: print("  [solver]", m))
sols = solver.run()
print("冲突:", solver.conflicts)
print("搜索节点:", solver.nodes, "解数量:", len(sols))
for i, sol in enumerate(sols[:3]):
    table = sol.table()
    print(f"--- 解 {i}: score={sol.score:.3f} complete={sol.complete} notes={sol.notes}")
    print("  字符表:", table.decode("latin-1"))
    print("  与标准答案一致:", table == EXPECTED)
    print("  flag   :", sol.plaintexts.get("flag.txt", b"")[:80])
if sols:
    best = sols[0]
    print("readme 还原正确:", best.plaintexts.get("readme.txt") == readme_plain)
    logo = best.plaintexts.get("logo.jpg", b"")
    print("logo 还原:", oracles.evaluate(logo)[:1], "长度", len(logo))
