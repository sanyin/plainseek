"""证据黑板与完成门控：让"找到 flag"和"确认 flag"变成两件事。

这套东西借鉴自看雪上那个自动逆向框架 **r0re**（作者 fyrlove，基于 Cairn 架构）：

* 它把分析状态拆成三类对象：**Fact**（已观察到的事实）、**Intent**（下一步要做的事）、
  **Hint**（人给的干预）。Fact 还分 ``kind=fact / dead_end``（**死路也要留下来**，
  免得后面重复走）和 ``verified``（**只有真实工具输出才置位**，模型/启发式的自述不算）；
* 它还给了最值得抄的一条工程约束：**完成是一个状态机，不是一句话**。候选答案先进
  "待验证"，必须有独立验证证据（verifier + 产物 + 通过事件）才能 finalize；
  验证不过就把失败原因留着，接着往下走，而不是重跑一遍。

为什么我的工具**特别需要**这个：投稿包 12 题里有 3 题（R02/R08/R09）会主动喂你一个
诱饵 flag，我上一轮还抓到一次真·假阳性（PNG 二进制里凑出 ``jc_{8_&vfo9?_uL_}`` 还给了
0.95 高分）。根因就是"形状像 flag"和"证据支持这是 flag"被混为一谈了。

所以这里把证据分成等级，只有强证据才允许 finalize：

===========  ==========================================================
等级          含义（本工具里的具体来源）
===========  ==========================================================
``binary``   跟**二进制里的密文/已知明文**对上了（``verify`` 的三种模式）
``emulate``  **真的把程序自己的校验跑通了**（``emu`` 模拟执行返回成功分支）
``oracle``   结构判据强通过（PNG/ZIP/gzip 的 CRC 全对、文件格式完整校验通过）
``roundtrip`` 反向解出来的结果**再加密回去等于原密文**（自洽性）
``shape``    只有"形状"：拼出 ``xxx{...}``、命中 crib 前缀——**弱证据，不算确认**
``text``     语言模型觉得像人话/像 flag——最弱，只用来排序
===========  ==========================================================

``shape`` / ``text`` 的结果会进"待验证候选"，并在报告里明确标出来；想只要确认过的结果，
用 ``--strict``（只输出 verified）。这样诱饵 flag 依然会被捞出来当**线索**，但不会再
被当成"解出来了"。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

# 证据等级（数值越大越硬）。只有 >= STRONG 才允许 finalize。
EVIDENCE_LEVELS = {
    "text": 0,          # 语言模型 / 像人话
    "shape": 1,         # 形状：xxx{...}、crib 前缀命中
    "heuristic": 2,     # 启发式打分很高，但没有外部校验
    "roundtrip": 3,     # 解出来再加密回去 == 原密文
    "oracle": 4,        # 结构判据（CRC / 段结构 / 格式完整）通过
    "emulate": 5,       # 程序自己的校验逻辑被模拟执行跑通
    "binary": 6,        # 与二进制里的密文/已知明文对上
}
STRONG_EVIDENCE = 4          # >= oracle 才算"确认"
_EVIDENCE_NOTE = {
    "text": "语言模型判定（最弱，只用于排序）",
    "shape": "只有形状（命中前缀/闭合花括号），可能被诱饵或噪声骗过",
    "heuristic": "启发式高分，无外部校验",
    "roundtrip": "反向结果再加密回去与原密文一致（自洽）",
    "oracle": "结构判据通过（CRC/段结构/格式完整）",
    "emulate": "程序自身校验被模拟执行跑通",
    "binary": "与程序内密文/已知明文对上",
}


def evidence_level(kind: str) -> int:
    return EVIDENCE_LEVELS.get(kind, 0)


def evidence_note(kind: str) -> str:
    return _EVIDENCE_NOTE.get(kind, kind)


@dataclass
class Fact:
    text: str
    kind: str = "fact"                  # fact / dead_end
    verified: bool = False              # 只有真实工具输出才算
    creator: str = "tool"
    evidence: str = ""
    artifacts: List[str] = field(default_factory=list)
    at: float = field(default_factory=time.time)

    def line(self) -> str:
        mark = {"dead_end": "✗", "fact": "·"}.get(self.kind, "·")
        v = "[已验证]" if self.verified else ""
        tail = f"  ← {self.evidence}" if self.evidence else ""
        return f"{mark} {self.text}{v}{tail}"


@dataclass
class Candidate:
    """候选答案：可以有很多个，但只有过了门控的才能算结果。"""
    flag: bytes
    source: str                         # 哪个模块给出的（chain/fragments/pyc/verify…）
    kind: str = "shape"                 # 证据等级
    detail: str = ""
    artifacts: List[str] = field(default_factory=list)
    passed: Optional[bool] = None       # 验证结果：None=待验证
    verify_how: str = ""
    failed_reason: str = ""
    at: float = field(default_factory=time.time)

    @property
    def level(self) -> int:
        return evidence_level(self.kind)

    @property
    def strong(self) -> bool:
        return self.level >= STRONG_EVIDENCE

    @property
    def finalized(self) -> bool:
        return self.passed is True and self.strong

    def line(self) -> str:
        text = self.flag.decode("utf-8", "replace")
        state = ("✔已确认" if self.finalized else
                 "?待验证" if self.passed is None else
                 "✗未通过")
        return (f"[{state} {self.kind}] {text}"
                f"  （来自 {self.source}）"
                + (f"  验证：{self.verify_how}" if self.verify_how else "")
                + (f"  失败原因：{self.failed_reason}" if self.failed_reason else ""))


class Board:
    """一块"事实黑板"。工具每得出一个结论就往上面写，最后按门控决定能不能收工。"""

    def __init__(self, origin: str = "", goal: str = "找出能通过校验的答案（flag）"):
        self.origin = origin
        self.goal = goal
        self.facts: List[Fact] = []
        self.intents: List[str] = []
        self.hints: List[str] = []
        self.candidates: List[Candidate] = []
        if origin:
            self.facts.append(Fact(origin, creator="human", evidence="题目来源"))

    # ------------------------------------------------------------- 写入
    def add_fact(self, text: str, kind: str = "fact", verified: bool = False,
                 creator: str = "tool", evidence: str = "",
                 artifacts: Sequence[str] = ()) -> Fact:
        fact = Fact(text=text, kind=kind, verified=verified, creator=creator,
                    evidence=evidence, artifacts=list(artifacts))
        self.facts.append(fact)
        return fact

    def dead_end(self, text: str, reason: str = "") -> Fact:
        """记一条**死路**：r0re 里专门保留这类事实，避免后面重复走同一条路。"""
        return self.add_fact(text, kind="dead_end", evidence=reason)

    def add_intent(self, what: str) -> None:
        if what and what not in self.intents:
            self.intents.append(what)

    def add_hint(self, text: str) -> None:
        """人给的干预：可以是密钥、crib、偏移、或"这条路别走了"。"""
        self.hints.append(text)

    def propose(self, flag: bytes, source: str, kind: str = "shape",
                detail: str = "", artifacts: Sequence[str] = ()) -> Candidate:
        """登记一个候选答案（此时**还不算结果**）。"""
        cand = Candidate(flag=flag, source=source, kind=kind, detail=detail,
                         artifacts=list(artifacts))
        self.candidates.append(cand)
        return cand

    def verify(self, cand: Candidate, ok: bool, how: str,
               kind: Optional[str] = None) -> Candidate:
        """给候选补上验证结果。``how`` 要写清楚"凭什么说它对"。"""
        cand.passed = ok
        cand.verify_how = how
        if kind:
            cand.kind = kind
        if not ok:
            cand.failed_reason = how
            self.dead_end(f"候选 {cand.flag.decode('utf-8', 'replace')} 未通过验证",
                          reason=how)
        else:
            self.add_fact(f"{cand.flag.decode('utf-8', 'replace')} 通过验证",
                          verified=True, evidence=how, artifacts=cand.artifacts)
        return cand

    # ------------------------------------------------------------- 收取
    def finalized(self) -> List[Candidate]:
        return [c for c in self.candidates if c.finalized]

    def pending(self) -> List[Candidate]:
        return [c for c in self.candidates if c.passed is None and c.strong]

    def best_unverified(self) -> Optional[Candidate]:
        """没有确认答案时，给一个"最像的候选"（并明确标注它是未验证的）。"""
        unverified = [c for c in self.candidates if not c.finalized]
        if not unverified:
            return None
        return max(unverified, key=lambda c: (c.level, len(c.flag)))

    def can_finalize(self) -> bool:
        """完成门控：至少有一个候选过了强证据验证。"""
        return bool(self.finalized())

    # ------------------------------------------------------------- 输出
    def report(self, limit_dead_ends: int = 6) -> str:
        lines: List[str] = []
        lines.append("【证据黑板】" + (f"来源：{self.origin}" if self.origin else ""))
        lines.append(f"  目标：{self.goal}")
        if self.hints:
            lines.append("  人工干预（Hint）：" + "；".join(self.hints))
        facts = [f for f in self.facts if f.kind == "fact"]
        dead = [f for f in self.facts if f.kind == "dead_end"]
        if facts:
            lines.append(f"  事实 {len(facts)} 条：")
            for f in facts[-10:]:
                lines.append("    " + f.line())
        if dead:
            lines.append(f"  已排除路线 {len(dead)} 条（死路也保留，避免重复走）：")
            for f in dead[-limit_dead_ends:]:
                lines.append("    " + f.line())
        if self.intents:
            lines.append("  下一步建议：")
            for i in self.intents[:5]:
                lines.append("    → " + i)
        if self.candidates:
            confirmed = self.finalized()
            others = [c for c in self.candidates if not c.finalized]
            lines.append(f"  候选 {len(self.candidates)} 个"
                         f"（已确认 {len(confirmed)}，未确认 {len(others)}）：")
            for c in confirmed:
                lines.append("    " + c.line())
            for c in others[:8]:
                lines.append("    " + c.line())
            if others and not confirmed:
                lines.append("    ⚠ 以上都**没有通过强证据验证**，只能当线索："
                             "诱饵 flag 和噪声都长这样。")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps({
            "origin": self.origin, "goal": self.goal,
            "facts": [f.__dict__ for f in self.facts],
            "intents": self.intents, "hints": self.hints,
            "candidates": [{**c.__dict__, "flag": c.flag.decode("utf-8", "replace"),
                            "finalized": c.finalized} for c in self.candidates],
        }, ensure_ascii=False, indent=2)

    def suggest_intents(self) -> None:
        """按当前事实，补几条"下一步"（对应 r0re 的 reason 阶段，这里做最朴素的版本）。"""
        text = " ".join(f.text for f in self.facts)
        if not self.finalized() and self.candidates:
            self.add_intent("候选都没过强证据：用 `verify --plain/--ciphertext-offset` "
                            "或 `emu --call <校验函数>` 拿硬证据，别靠形状")
        if "PE" in text or "MZ" in text:
            self.add_intent("这是 Windows PE：用 `emu --pe --call <校验函数> "
                            "--stdin <候选>` 让它自己判对错")
        if "PyInstaller" in text:
            self.add_intent("PyInstaller：先 `unpack` 出归档，再 `frozen` 提取冻结模块，"
                            "必要时与官方同版本运行时做差分")
        if "SMC" in text or "自修改" in text:
            self.add_intent("自修改代码：先用 `emu` 跑解密循环（内存改写差分能直接看到结果）")
