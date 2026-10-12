"""链式搜索引擎：多层加密自动叠加还原。

思路很朴素但很有效：把数据当作搜索状态，每一层挑"看起来该用"的变换去试，
用 oracles 给结果打分，保留最有希望的一批继续往下解（beam search）。
"两三个加密叠在一起"就自然变成搜索树里的一条路径——不需要事先知道层数。
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import oracles, recover, transforms
from .oracles import SUCCESS_SCORE, Verdict
from .transforms import Ctx, Step

# 变换优先级：先试"信息量最大/最可能"的，搜索树更省
_PRIORITY = {
    "compress": 0, "encoding": 1, "cipher": 2, "byte": 3, "bit": 4, "xor": 5,
    "classic": 6, "prng": 7, "misc": 8,
}


# 命中这些说明"这是最终明文"，可以收工；
# 而 ZLIB/ZIP/PNG 这类只是"包了一层"，值得继续往下解。
TERMINAL_LABELS = {"FLAG", "FLAG?", "UTF-8 文本", "ASCII 文本", "中文文本", "英文文本",
                   "疑似文本", "UTF-8(含不可打印)", "JSON", "XML/HTML"}


def is_terminal(verdict: Verdict) -> bool:
    return verdict.label in TERMINAL_LABELS


def _same_bytes(a: bytes, b: bytes) -> bool:
    """复核比较：十六进制文本大小写不敏感。"""
    if a == b:
        return True
    if len(a) != len(b):
        return False
    probe = b[:64]
    if probe and set(probe) <= set(b"0123456789abcdefABCDEF\r\n \t"):
        return a.lower() == b.lower()
    return False


@dataclass
class Result:
    data: bytes
    steps: List[Step]
    score: float
    verdicts: List[Verdict] = field(default_factory=list)
    roundtrip: Optional[bool] = None

    @property
    def recipe(self) -> str:
        return transforms.recipe_str(self.steps)

    def describe(self) -> str:
        chain = transforms.recipe_description(self.steps)
        best = self.verdicts[0] if self.verdicts else Verdict(0, "无")
        rt = {True: "，重新加密复核通过", False: "，重新加密复核失败",
              None: ""}[self.roundtrip]
        return f"[{self.score:.2f}] {chain} → {best}{rt}"


@dataclass
class _Node:
    data: bytes
    steps: List[Step]
    qscore: float
    verdict: Optional[Verdict] = None


class Engine:
    """通用链式解密搜索。"""

    def __init__(self, ctx: Optional[Ctx] = None, depth: int = 4, beam: int = 12,
                 success: float = SUCCESS_SCORE, work_limit: int = 20000,
                 time_budget: float = 90.0, min_detect: float = 0.25,
                 per_transform_cap: int = 24, log: Optional[Callable[[str], None]] = None,
                 stop_on_success: bool = True, transforms_whitelist: Optional[Sequence[str]] = None,
                 transforms_blacklist: Sequence[str] = ()):
        self.ctx = ctx or Ctx()
        self.depth = depth
        self.beam = beam
        self.success = success
        self.work_limit = work_limit
        self.time_budget = time_budget
        self.min_detect = min_detect
        self.per_transform_cap = per_transform_cap
        self.log = log or (lambda _m: None)
        self.stop_on_success = stop_on_success
        names = transforms_whitelist or sorted(
            transforms.REGISTRY,
            key=lambda n: (_PRIORITY.get(transforms.REGISTRY[n].category, 9), n))
        self.chain = [transforms.REGISTRY[n] for n in names
                      if n in transforms.REGISTRY and n not in transforms_blacklist]
        self.work = 0
        self.deadline = 0.0
        self.results: List[Result] = []
        self._original: Optional[bytes] = None
        self.stats: Dict[str, int] = {}

    # -- 主流程 -----------------------------------------------------------
    def solve(self, data: bytes, label: str = "data") -> List[Result]:
        self.work = 0
        self.deadline = time.monotonic() + self.time_budget
        self.results = []
        self._original = data
        # 记录"输入本身"的判定：用它来排除"假进展"——
        # 有些变换（例如 latin-1/gbk 这类编码转换）会原样保留文件头，
        # 于是"解出来还是 ELF"也会命中同一判据，其实什么都没做。
        original_verdicts = oracles.evaluate(data)
        self._original_label = (original_verdicts[0].label
                                if original_verdicts and original_verdicts[0].score >= 0.5 else None)
        start_q = oracles.quick_score(data)
        beam: List[_Node] = [_Node(data, [], start_q)]
        self.log(f"初始：{len(data)} 字节，快速评分 {start_q:.2f}")

        for layer in range(1, self.depth + 1):
            if self._out_of_budget():
                self.log(f"预算用尽（第 {layer} 层，已执行 {self.work} 次变换）")
                break
            children: Dict[str, _Node] = {}
            for node in beam:
                for child in self._expand(node):
                    key = hashlib.sha1(child.data).hexdigest()
                    old = children.get(key)
                    if old is None or child.qscore > old.qscore:
                        children[key] = child
            if not children:
                self.log(f"第 {layer} 层没有可用变换")
                break
            ranked = sorted(children.values(), key=lambda n: -n.qscore)
            selected = self._select_beam(ranked)
            self.log(f"第 {layer} 层：候选 {len(ranked)} 个，最高快速评分 {ranked[0].qscore:.2f}"
                     f"，保留 {len(selected)} 条分支")
            # Ciphey 的做法：让"这一层真正解出好东西"的译码器下一层优先跑
            for node in ranked[:8]:
                if node.steps:
                    name = node.steps[-1].name
                    self.stats[name] = self.stats.get(name, 0) + 1
            if self.stats:
                self.chain.sort(key=lambda t: (-self.stats.get(t.name, 0),
                                               _PRIORITY.get(t.category, 9), t.name))
            # 命中检查：设了 crib 时，crib 就是唯一判据——不能再拿"快速评分"筛掉候选，
            # 否则"解出来是二进制但确实含 crib"的正确答案会被漏掉。
            crib_active = self.ctx.crib is not None or self.ctx.crib_regex is not None
            for node in selected:
                if not crib_active and node.qscore < 0.4:
                    continue
                res = self._check(node, label)
                if res:
                    self.results.append(res)
                    self.log(f"  命中：{res.describe()}")
            if self.results and self.stop_on_success and any(
                    is_terminal(r.verdicts[0]) for r in self.results if r.verdicts):
                break
            beam = selected
        self.results.sort(key=lambda r: -r.score)
        return self.results

    def _select_beam(self, ranked: List[_Node]) -> List[_Node]:
        """beam 选择：既看分数，也保证"每种变换至少留一条分支"。

        否则像 AES/DES 这种"解开一层后中间结果是高熵密文、评分很低"的正确路径，
        会在第一层就被整体丢掉。
        """
        chosen = ranked[: self.beam]
        names = {n.steps[-1].name for n in chosen if n.steps}
        cap = max(self.beam + 4, self.beam * 3)
        for node in ranked:
            if len(chosen) >= cap:
                break
            if node.steps and node.steps[-1].name not in names:
                names.add(node.steps[-1].name)
                chosen.append(node)
        return chosen

    # -- 单层展开 ---------------------------------------------------------
    def _expand(self, node: _Node) -> List[_Node]:
        out: List[_Node] = []
        for t in self.chain:
            if self._out_of_budget():
                return out
            conf = t.detect(node.data, self.ctx)
            if conf < self.min_detect:
                continue
            params_list = t.params(node.data, self.ctx)
            if len(params_list) > self.per_transform_cap:
                params_list = params_list[: self.per_transform_cap]
            for params in params_list:
                if self._out_of_budget():
                    return out
                self.work += 1
                work_params = dict(params)
                try:
                    out_data = t.run(node.data, work_params, self.ctx)
                except Exception:
                    continue
                if not out_data or out_data == node.data:
                    continue
                qs = oracles.quick_score(out_data)
                if qs >= 0.8:
                    # 快速评分高（多半是命中了某个 magic）时，立刻做一次完整校验，
                    # 免得"只看头部就以为解对了"的候选把 beam 刷满
                    verdicts = oracles.evaluate(out_data)
                    qs = verdicts[0].score if verdicts else min(qs, 0.6)
                out.append(_Node(out_data, node.steps + [Step(t.name, work_params)], qs))
        return out

    def _out_of_budget(self) -> bool:
        return self.work > self.work_limit or time.monotonic() > self.deadline

    # -- 命中判定 ---------------------------------------------------------
    def _check(self, node: _Node, label: str) -> Optional[Result]:
        crib_hit = self._crib_verdict(node.data)
        crib_active = self.ctx.crib is not None or self.ctx.crib_regex is not None
        if crib_active and crib_hit is None:
            return None                       # 设了 crib 就只认命中 crib 的结果
        verdicts = oracles.evaluate(node.data, only=None)
        if crib_hit is not None:
            verdicts.insert(0, crib_hit)
        # 已知明文/格式提示也算一票（但只有够长的前缀才足以判定"解对了"）
        if self.ctx.known_spans:
            prefix = self.ctx.known_spans[0][1]
            if prefix and node.data.startswith(prefix):
                score = 0.9 if len(prefix) >= 12 else 0.8
                verdicts.append(Verdict(score, "已知明文前缀匹配", prefix[:16].hex()))
                verdicts.sort(key=lambda v: -v.score)
        if not verdicts:
            return None
        best = verdicts[0]
        if crib_hit is None and best.score < self.success:
            return None
        # 假进展：输入本来就已经被识别成某种格式，解出来还是同一种格式 →
        # 说明这个变换没带来新信息（典型是编码转换原样保留了文件头），不算解出
        if crib_hit is None and self._original_label and best.label == self._original_label:
            return None
        roundtrip = self._roundtrip(node)
        return Result(node.data, node.steps, best.score, verdicts, roundtrip)

    def _crib_verdict(self, data: bytes) -> Optional[Verdict]:
        """crib 命中检查：既支持正则，也支持固定字节串。"""
        if self.ctx.crib_regex is not None:
            m = self.ctx.crib_regex.search(data)
            if m:
                try:
                    text = m.group(0).decode("latin-1")
                except Exception:
                    text = "<binary>"
                return Verdict(1.0, "crib 命中", text[:80])
            return None
        if self.ctx.crib:
            idx = data.find(self.ctx.crib)
            if idx >= 0:
                return Verdict(1.0, "crib 命中", f"@{idx}")
        return None

    def _roundtrip(self, node: _Node) -> Optional[bool]:
        """把明文按配方逆序重新加密，能还原原始数据才算"复核通过"。"""
        if self._original is None:
            return None
        try:
            again = transforms.encode_recipe(node.data, node.steps, self.ctx)
        except Exception:
            return None
        return _same_bytes(again, self._original)


def solve_bytes(data: bytes, ctx: Optional[Ctx] = None, **kw) -> List[Result]:
    return Engine(ctx, **kw).solve(data)


# --------------------------------------------------------------------------
# 多文件：把最优配方套用到同目录其它文件，交叉验证
# --------------------------------------------------------------------------


@dataclass
class FileResult:
    path: str
    plaintext: bytes
    recipe: str
    score: float
    verdicts: List[str] = field(default_factory=list)


def apply_recipe_to(data: bytes, steps: Sequence[Step], ctx: Ctx) -> bytes:
    return transforms.apply_recipe(data, steps, ctx)


def verify_roundtrip(original: bytes, plaintext: bytes, steps: Sequence[Step],
                     ctx: Ctx) -> Optional[bool]:
    """把解出来的明文按配方逆序重新加密，看能否还原成原始数据。"""
    try:
        again = transforms.encode_recipe(plaintext, steps, ctx)
    except Exception:
        return None
    return _same_bytes(again, original)


def solve_group(paths: Sequence[str], ctx: Optional[Ctx] = None, **kw) -> List[FileResult]:
    """对一个文件组求解：先用信息量最大的文件搜链，再把链套到其它文件上。"""
    ctx = ctx or Ctx()
    engine = Engine(ctx, **kw)
    results: List[FileResult] = []
    best: Optional[Result] = None
    for path in paths:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        found = engine.solve(data, label=path)
        if found:
            best = found[0]
            break
    if not best:
        return results
    for path in paths:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        try:
            plain = apply_recipe_to(data, best.steps, ctx)
        except Exception:
            continue
        verdicts = [str(v) for v in oracles.evaluate(plain)]
        results.append(FileResult(path, plain, best.recipe, best.score, verdicts))
    return results
