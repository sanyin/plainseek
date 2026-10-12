"""一条龙编排：把各个模块串成"给目录就能出明文"的流水线。

流程（能走通哪步走哪步，走不通就退回通用链式搜索）：

1. **侦察**：列出文件、识别格式、找"明文/密文"配对。
2. **密钥收集**：命令行给的、文件里的、二进制字符串里的、用户脚本生成的。
3. **流加密家族识别**：用"明文/密文对照"或"字符集约束"试出
   XOR 常量 / 重复密钥 / RC4 家族掩码常量（0x72、0x37 这种）。
4. **密码表还原**：如果密文是"字符表被打乱的 Base64"，用已知明文 + 文件结构
   （magic、JPEG 段、CRC、flag 前缀）把整张表解出来。
5. **通用链式搜索**：剩下的文件用 transforms + oracles 做 beam search，
   自动叠加多层。
6. **复核**：重新加密比对 + 结构校验，输出明文与报告。
"""

from __future__ import annotations

import base64
import importlib.util
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import alphabets, ciphers, oracles, recover, search, transforms
from .oracles import SUCCESS_SCORE, Verdict
from .transforms import Ctx, Step

BINARY_EXT = {".exe", ".dll", ".elf", ".so", ".bin", ".out", ".sys", ".o", ".a", ".dylib"}
BINARY_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"#!")
SKIP_EXT = {".pyc", ".zip", ".rar", ".7z", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf"}


@dataclass
class Options:
    out_dir: Optional[str] = None
    depth: int = 4
    beam: int = 12
    timeout: float = 90.0
    work_limit: int = 20000
    deep: bool = False
    keys: List[bytes] = field(default_factory=list)
    key_files: List[str] = field(default_factory=list)
    keys_from: List[str] = field(default_factory=list)
    key_script: Optional[str] = None
    fmt: str = ""
    reference: Optional[str] = None
    assume_flag_prefix: bool = True
    max_stream_keys: int = 400
    table: Optional[bytes] = None
    recursive: bool = False
    # crib：已知明文串或正则（CyberChef Magic 的 crib）。设了就只认命中的结果。
    crib: Optional[str] = None
    crib_is_regex: bool = False
    # 密钥确认（verify.py）：拿程序里存着的密文/明文常量反查候选密钥
    verify_binary: Optional[str] = None
    verify_plain: Optional[str] = None
    verify_ciphers: str = "des,des3,aes,rc4,rc4v,xor"
    verify_key_transforms: str = "raw,bitrev"
    ciphertext_offset: int = -1
    ciphertext_length: int = 0
    keyspace_kind: str = "none"
    keyspace_length: int = 6
    derive: str = "raw"
    verify_limit: int = 2_000_000
    fragments: bool = True          # 兜底：flag 片段收集与拼接
    verify_emulate: bool = False    # 把候选喂回程序自己跑一遍（最强证据）
    emulate_max_ins: int = 400000
    emulate_binaries: List[str] = field(default_factory=list)
    log: Callable[[str], None] = print


@dataclass
class Outcome:
    path: str
    plaintext: bytes
    steps: List[Step]
    score: float
    verdicts: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    verified: Optional[bool] = None
    source: str = ""

    @property
    def recipe(self) -> str:
        return transforms.recipe_str(self.steps)

    def summary(self) -> str:
        head = self.plaintext[:80]
        try:
            text = head.decode("utf-8")
            text = text.replace("\n", "\\n")
        except UnicodeDecodeError:
            text = head.hex(" ")
        return f"{os.path.basename(self.path)}: [{self.score:.2f}] {self.recipe} → {text}"


@dataclass
class Report:
    outcomes: List[Outcome] = field(default_factory=list)
    pairs: List[recover.PairReport] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    elapsed: float = 0.0
    keys_tried: int = 0

    def by_path(self, path: str) -> Optional[Outcome]:
        for o in self.outcomes:
            if o.path == path:
                return o
        return None


# --------------------------------------------------------------------------
# 工具函数
# --------------------------------------------------------------------------

def clean_target(path: str) -> str:
    """修复 cmd 传参的两个坑（拖拽/粘贴路径时很常见）：

    * 路径末尾的反斜杠：``"D:\\dir\\"`` 里的 ``\\"`` 会被当成转义引号，
      结果是**后面的参数被吞进路径**（变成 ``D:\\dir" -o ...``）；
    * 从资源管理器地址栏复制的路径常带尾反斜杠，直接拼上引号也会出问题。

    只在"原样用不了"时才尝试修复，正常路径不受影响。
    """
    if not path or os.path.exists(path):
        return path
    fixed = path
    for marker in ('"', " -o ", " --"):
        if marker in fixed:
            fixed = fixed.split(marker, 1)[0]
    fixed = fixed.strip().rstrip("\\/")
    if len(fixed) == 2 and fixed[1] == ":":          # 根目录 D: → D:\
        fixed += "\\"
    return fixed or path


def list_files(targets: Sequence[str], recursive: bool = False) -> List[str]:
    out: List[str] = []
    for raw in targets:
        t = clean_target(raw)
        if os.path.isdir(t):
            if recursive:
                for root, _dirs, names in os.walk(t):
                    for n in sorted(names):
                        out.append(os.path.join(root, n))
            else:
                for n in sorted(os.listdir(t)):
                    p = os.path.join(t, n)
                    if os.path.isfile(p):
                        out.append(p)
        elif os.path.isfile(t):
            out.append(t)
    return out


def is_encrypted_candidate(path: str) -> bool:
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    if any(name.endswith(s) for s in recover.PAIR_SUFFIXES):
        return True
    return ext in {".enc", ".locked", ".crypt", ".bin", ".data", ".out", ".cipher"}


def guess_format(path: str, data: bytes) -> str:
    """先从文件名猜，再从 magic 猜。"""
    fmt = alphabets.format_of_name(os.path.basename(path))
    if fmt:
        return fmt
    head = data[:16]
    table = {
        b"\x89PNG": "png", b"\xff\xd8\xff": "jpeg", b"GIF8": "gif", b"PK\x03\x04": "zip",
        b"\x1f\x8b": "gzip", b"%PDF": "pdf", b"\x7fELF": "elf", b"MZ": "pe", b"BM": "bmp",
        b"SQLite": "sqlite", b"BZh": "bz2", b"\xfd7zXZ": "xz", b"ID3": "mp3", b"RIFF": "wav",
    }
    for magic, name in table.items():
        if head.startswith(magic):
            return alphabets.normalize_format(name)
    return ""


def format_oracle(fmt: str) -> Optional[Callable]:
    fmt = alphabets.normalize_format(fmt)
    mapping = {
        "png": "png", "jpeg": "jpeg", "gif": "gif", "bmp": "bmp", "zip": "zip",
        "gz": "gzip", "gzip": "gzip", "bz2": "bzip2", "xz": "xz", "pdf": "pdf", "elf": "elf",
        "pe": "pe", "sqlite": "sqlite", "mp3": "mp3", "wav": "riff", "tiff": "tiff",
        "7z": "sevenz", "rar": "rar", "json": "json", "riff": "riff", "webp": "webp",
    }
    name = mapping.get(fmt)
    if not name:
        return None
    try:
        return oracles.get_oracle(name).check
    except KeyError:
        return None


def load_key_script(path: str, ctx: Ctx) -> List[bytes]:
    """加载用户脚本：里面应有 keys(ctx) 生成器，或 KS 列表。"""
    spec = importlib.util.spec_from_file_location("autocrypt_keyscript", path)
    if spec is None or spec.loader is None:
        return []
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out: List[bytes] = []
    fn = getattr(mod, "keys", None)
    if callable(fn):
        try:
            for k in fn(ctx):
                out.append(k if isinstance(k, bytes) else str(k).encode())
        except Exception:
            pass
    ks = getattr(mod, "KS", None)
    if isinstance(ks, (list, tuple)):
        for k in ks:
            out.append(k if isinstance(k, bytes) else str(k).encode())
    return out


def read_key_file(path: str) -> List[bytes]:
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return []
    keys = [line.strip() for line in blob.splitlines() if line.strip()]
    keys.append(blob.strip())
    return [k for k in keys if k]


KEY_SUFFIX_BASIC = ("", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "!", "!!",
                    "01", "07", "10", "13", "20", "21", "22", "23", "24", "25", "26", "27",
                    "66", "88", "99", "123")
KEY_SUFFIX_FULL = KEY_SUFFIX_BASIC + tuple(f"{i:02d}" for i in range(100)) + (
    "666", "888", "1234", "12345", "2024", "2025", "2026", "2027", "admin", "pass")


def expand_keys(keys: Sequence[bytes], top: int = 12, deep: bool = False) -> List[bytes]:
    """密钥变体生成。

    逆向题里密钥常常**不是**以完整字符串存在的：程序可能只把前 16 字节放在
    只读数据里，最后几位由指令临时写入（真实题目 distorted 就是这样：
    二进制里只有 ``CCB_M4gic_K3y_20``，末两位是代码拼上去的）。
    所以对"最像口令"的若干个候选做前后缀扩展，且变体紧跟母串，保证排序靠前。
    """
    out: List[bytes] = []
    seen: Set[bytes] = set()

    def push(cand: bytes) -> None:
        if cand not in seen and 1 <= len(cand) <= 64:
            seen.add(cand)
            out.append(cand)

    wide = 4 if deep else 2
    for index, base in enumerate(keys):
        push(base)
        if index >= top or len(base) < 5:
            continue
        # 只有最靠前的几个候选才值得用完整的两位数后缀表（否则组合爆炸）
        suffixes = KEY_SUFFIX_FULL if (deep and index < wide) else KEY_SUFFIX_BASIC
        if not deep:
            suffixes = KEY_SUFFIX_BASIC
        for suffix in suffixes:
            push(base + suffix.encode())
    return out


def collect_keys(files: Sequence[str], opts: Options, log: Callable) -> List[bytes]:
    keys: List[bytes] = list(opts.keys)
    for kf in opts.key_files:
        keys += read_key_file(kf)
    binaries = list(opts.keys_from)
    for path, data in files:
        if path in binaries:
            continue
        ext = os.path.splitext(path)[1].lower()
        # 按扩展名，或按内容（ELF/PE/Mach-O/脚本）判断是不是可执行文件——
        # 逆向题的密钥经常就藏在无扩展名的程序里
        if ext in BINARY_EXT or (not is_encrypted_candidate(path)
                                 and data[:4].startswith(BINARY_MAGIC)
                                 and len(data) < (64 << 20)):
            binaries.append(path)
    if binaries:
        keys += recover.harvest_keys(binaries)
    if opts.key_script:
        keys += load_key_script(opts.key_script, Ctx())
    # 从所有密文同目录的文本文件里也抓一抓（有时密钥写在 readme 里）
    for path, data in files:
        if len(data) < 4096 and not is_encrypted_candidate(path):
            for token in recover.strings(data, 6):
                keys.append(token.strip())
    uniq: List[bytes] = []
    seen = set()
    for k in keys:
        if k and k not in seen and len(k) <= 256:
            seen.add(k)
            uniq.append(k)
    if opts.deep:
        before = len(uniq)
        uniq = expand_keys(uniq, top=16, deep=True)
        log(f"深度模式：密钥候选扩展到 {len(uniq)} 个（原 {before} 个）")
    else:
        uniq = expand_keys(uniq, top=12, deep=False)
    log(f"密钥候选：{len(uniq)} 个（按“像密钥”程度排序）")
    return uniq


# --------------------------------------------------------------------------
# 流加密层识别
# --------------------------------------------------------------------------

@dataclass
class StreamLayer:
    kind: str                       # xor常数 / 重复密钥 / rc4家族 / 无
    params: Dict[str, object] = field(default_factory=dict)
    plain_maker: Optional[Callable[[bytes], bytes]] = None
    note: str = ""


def find_stream_layer(cipher: bytes, keys: Sequence[bytes], log: Callable,
                      have_charsets: Sequence[str] = ("base64", "printable", "hex"),
                      timeout: float = 20.0) -> Optional[StreamLayer]:
    """在不知道密钥的情况下，靠"解密结果必须是某种字符集"把流加密层试出来。"""
    deadline = time.time() + timeout
    for charset in have_charsets:
        allowed = recover.charset_for(charset)
        check = recover.charset_check_len(allowed)
        for key in keys:
            if time.time() > deadline:
                return None
            hits = recover.rc4_family_recover(cipher, key, allowed=allowed, check=check)
            for hit in hits:
                params = {"key": key, "mask": hit["mask"], "p1": hit["p1"], "p2": hit["p2"],
                          "ksa": hit["ksa"]}
                plain = ciphers.rc4(cipher, key, mask_id=hit["mask"], p1=hit["p1"],
                                    p2=hit["p2"], ksa_id=hit["ksa"])
                if not _charset_ok(plain, allowed):
                    continue
                note = (f"RC4 家族：密钥={key[:24]!r} 掩码公式#{hit['mask']} "
                        f"p1={hex(hit['p1'])} p2={hex(hit['p2'])}（约束：{charset} 字符集）")
                log("  " + note)
                return StreamLayer("rc4家族", params,
                                   lambda d, p=params: ciphers.rc4(
                                       d, p["key"], mask_id=p["mask"], p1=p["p1"], p2=p["p2"],
                                       ksa_id=p["ksa"]), note)
    return None


def _charset_ok(data: bytes, allowed) -> bool:
    if not data:
        return False
    bad = sum(1 for b in data if b not in allowed)
    if len(data) >= 32:
        return bad == 0                     # 长数据必须一个越界字节都没有
    return bad <= max(1, len(data) // 200)


# --------------------------------------------------------------------------
# 密码表流水线
# --------------------------------------------------------------------------

def table_pipeline(streams_in: List[Tuple[str, bytes]], pair_stream: Optional[Tuple[str, bytes]],
                   pair_plain: Optional[bytes], opts: Options, log: Callable) -> Optional[bytes]:
    """对"自定义字符表 Base64"层做还原：返回还原出的 64 字符表。"""
    if not streams_in:
        return None
    entries: List[alphabets.Stream] = []
    for path, data in streams_in:
        fmt = opts.fmt or guess_format(path, data)
        known: List[Tuple[int, bytes]] = []
        oracle = None
        ref = None
        ref_spans: List[Tuple[int, bytes]] = []
        if pair_stream and path == pair_stream[0] and pair_plain:
            known.append((0, pair_plain))
            oracle = oracles.get_oracle("text").check
        else:
            magic = alphabets.FORMAT_MAGIC.get(alphabets.normalize_format(fmt), b"")
            if magic:
                known.append((0, magic))
            if opts.assume_flag_prefix and os.path.basename(path).lower().startswith(("flag", "key", "ans")):
                known.append((0, b"flag{"))
            oracle = format_oracle(fmt) or (lambda b, p: oracles.best(b, partial=p))
            if alphabets.normalize_format(fmt) == "jpeg":
                ref = alphabets.reference_segments(
                    "jpeg", open(opts.reference, "rb").read() if opts.reference else None)
                ref_spans = alphabets.reference_spans(ref)
        entries.append(alphabets.Stream(os.path.basename(path), data, fmt=fmt,
                                        known_spans=known, oracle=oracle, ref_segments=ref,
                                        ref_spans=ref_spans))
    solver = alphabets.TableSolver(entries, log=log)
    sols = solver.run()
    if not sols:
        log("  密码表还原失败")
        return None
    best = sols[0]
    log(f"  密码表还原成功（置信度 {best.score:.2f}）")
    for note in best.notes[:6]:
        log(f"    · {note}")
    return best.table()


def verify_custom_chain(original: bytes, plaintext: bytes, table: bytes,
                        stream_params: Optional[Dict[str, object]]) -> bool:
    """复核：明文 → 标准 Base64 → 自定义表替换 → 流加密 → 应等于原始密文。"""
    try:
        encoded = base64.b64encode(plaintext)
        std = alphabets.B64_STD.chars
        mapped = bytes(table[std.index(bytes([ch]))] if bytes([ch]) in std else ch for ch in encoded)
    except Exception:
        return False
    if stream_params:
        mapped = ciphers.rc4(mapped, stream_params["key"], mask_id=stream_params["mask"],
                             p1=stream_params["p1"], p2=stream_params["p2"],
                             ksa_id=stream_params.get("ksa", 0))
    return mapped == original


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def run(paths: Sequence[str], opts: Options) -> Report:
    started = time.time()
    log = opts.log
    rep = Report()
    files: List[Tuple[str, bytes]] = []
    for path in list_files(paths, opts.recursive):
        try:
            with open(path, "rb") as fh:
                files.append((path, fh.read()))
        except OSError:
            continue
    if not files:
        log("没有可读文件")
        return rep
    log(f"共 {len(files)} 个文件")

    keys = collect_keys(files, opts, log)
    rep.keys_tried = len(keys)
    by_path = dict(files)

    # --- 先做密钥确认：程序里存着的密文/明文常量就是标准答案 ---
    confirmed: Optional[Outcome] = None
    if opts.verify_binary:
        from . import verify as _verify
        log(f"先做密钥确认（目标程序：{os.path.basename(opts.verify_binary)}）…")
        space = _verify.Keyspace(opts.keyspace_kind, opts.keyspace_length, opts.derive)
        plain = None
        if opts.verify_plain:
            if opts.verify_plain.startswith("@"):
                try:
                    with open(opts.verify_plain[1:], "rb") as fh:
                        plain = fh.read()
                except OSError:
                    plain = opts.verify_plain[1:].encode()
            else:
                plain = opts.verify_plain.encode()
        confs = _verify.run_verify(
            opts.verify_binary,
            ciphers_list=[c.strip() for c in opts.verify_ciphers.split(",") if c.strip()],
            keys=keys[:200], keyspace=space, key_script=opts.key_script,
            key_transforms=[t.strip() for t in opts.verify_key_transforms.split(",") if t.strip()],
            verify_plain=plain, try_lenprefix=True,
            ciphertext_offset=opts.ciphertext_offset, ciphertext_length=opts.ciphertext_length,
            max_candidates=opts.verify_limit, log=log)
        if confs:
            best = confs[0]
            log(f"  ✅ 密钥确认成功：输入={best.label!r} 密钥={best.key!r}（{best.mode}）")
            rep.notes.append(f"密钥确认：输入={best.label!r} 密钥={best.key!r} 方式={best.mode}")
            keys = [best.key] + [k for k in keys if k != best.key]
            if best.plaintext:
                verdicts = oracles.evaluate(best.plaintext)
                score = verdicts[0].score if verdicts else 0.8
                confirmed = Outcome(
                    opts.verify_binary, best.plaintext,
                    [Step("verify", {"input": best.label, "key": best.key.decode("latin-1", "ignore"),
                                     "mode": best.mode, "cipher": best.cipher})],
                    score, [str(v) for v in verdicts[:4]],
                    [f"密钥由程序内密文确认（{best.mode}，偏移 0x{best.offset:x}）"],
                    True, "密钥确认")
        else:
            log("  密钥确认没有命中，继续按常规流程搜索")

    pairs = recover.find_pairs([p for p, _ in files])
    if pairs:
        log(f"发现 {len(pairs)} 组明文/密文配对")
    for plain_path, cipher_path in pairs:
        pr = recover.analyze_pair(plain_path, cipher_path)
        rep.pairs.append(pr)
        log(f"  配对 {os.path.basename(plain_path)} ↔ {os.path.basename(cipher_path)}："
            f"{pr.layer.get('kind', '未知')}")
        for note in pr.notes:
            log(f"    · {note}")

    # 密文候选
    targets = [p for p, _ in files if is_encrypted_candidate(p)]
    if not targets:
        targets = [p for p, _ in files if p not in {pp for pp, _ in pairs}]
    ctx = Ctx(keys=keys[:400], deep=opts.deep, log=log)
    if confirmed is not None:
        rep.outcomes.append(confirmed)
        log("  已把确认出的密钥记为本次结果（其余文件也会优先用它）")
    if opts.table:
        ctx.tables[opts.table.decode("latin-1", "ignore")] = opts.table
    if opts.crib:
        text = opts.crib
        is_regex = opts.crib_is_regex or (len(text) > 2 and text.startswith("/") and text.endswith("/"))
        if is_regex:
            pattern = text[1:-1] if text.startswith("/") and text.endswith("/") else text
            try:
                ctx.crib_regex = re.compile(pattern.encode(), re.I)
                log(f"使用 crib 正则：{pattern}")
            except re.error as exc:
                log(f"crib 正则非法（{exc}），改按普通字符串处理")
                ctx.crib = pattern.encode()
        else:
            ctx.crib = text.encode()
            log(f"使用 crib 字符串：{text!r}（只认命中它的结果）")

    # --- 第一段：流加密层 + 密码表 -------------------------------------
    stream_layer: Optional[StreamLayer] = None
    pair_plain_bytes: Optional[bytes] = None
    pair_cipher_bytes: Optional[bytes] = None
    if pairs:
        plain_path, cipher_path = pairs[0]
        pair_plain_bytes = by_path[plain_path]
        pair_cipher_bytes = by_path[cipher_path]

        # 先用"明文⊕密文"看看是不是最朴素的 XOR / 重复密钥
        layer = recover.analyze_stream_layer(pair_plain_bytes, pair_cipher_bytes)
        kind = str(layer.get("kind", ""))
        if kind == "常数":
            log("  识别为单字节 XOR")
            key = layer["key"]
            stream_layer = StreamLayer("xor常数", {"value": key[0]},
                                       lambda d, k=key: bytes(b ^ k[0] for b in d),
                                       f"单字节 XOR 常量 {key[0]:#x}")
        elif kind == "短周期重复密钥":
            log(f"  识别为重复密钥 XOR（周期 {layer.get('period')}）")
            key = layer["key"]
            stream_layer = StreamLayer("重复密钥", {"key": key},
                                       lambda d, k=key: transforms._repeat_xor(d, k),
                                       f"重复密钥 XOR，周期 {layer.get('period')}")
        if stream_layer is None:
            # 用"解出来必须是某种字符集"来试流加密家族（改造 RC4 就在这里被抓住）
            log("  尝试识别流加密家族（字符集约束 + 常量枚举，限时枚举密钥候选）…")
            stream_layer = find_stream_layer(pair_cipher_bytes,
                                             keys[: max(1, opts.max_stream_keys)], log,
                                             timeout=min(120.0, max(20.0, opts.timeout)))
        if stream_layer is None:
            # 退而求其次：把"明文⊕密文"当密钥流复用（同密钥同初始化时成立）
            ks = recover.xor_keystream(pair_plain_bytes, pair_cipher_bytes)
            if ks:
                ctx.keystreams.append(ks)
                log("  未能确定算法，先把明文/密文异或结果当密钥流备用")

    if stream_layer and stream_layer.plain_maker:
        log(f"  流加密层：{stream_layer.note}")
        # 用同一层解所有密文候选，得到"下一层"数据
        decrypted: List[Tuple[str, bytes]] = []
        for path in targets:
            try:
                decrypted.append((path, stream_layer.plain_maker(by_path[path])))
            except Exception:
                continue
        if decrypted:
            pair_entry = None
            if pairs:
                pname = os.path.basename(pairs[0][1])
                for path, data in decrypted:
                    if os.path.basename(path) == pname:
                        pair_entry = (path, data)
            table = table_pipeline(decrypted, pair_entry, pair_plain_bytes, opts, log)
            if table:
                step_layer = Step("rc4v", dict(stream_layer.params)) if stream_layer.kind == "rc4家族" \
                    else Step("xor", dict(stream_layer.params))
                step_table = Step("b64solve", {"table": table})
                for path, data in decrypted:
                    try:
                        plain = alphabets.decode_with_mapping(
                            data, {table[v]: v for v in range(len(table))},
                            alphabets.alphabet_from_charset(table))
                    except Exception:
                        continue
                    verdicts = oracles.evaluate(plain)
                    score = verdicts[0].score if verdicts else 0.0
                    original = by_path[path]
                    verified = verify_custom_chain(original, plain, table,
                                                   stream_layer.params if stream_layer.kind == "rc4家族" else None)
                    rep.outcomes.append(Outcome(path, plain, [step_layer, step_table], score,
                                                [str(v) for v in verdicts[:4]],
                                                [stream_layer.note, "密码表已还原"],
                                                verified, "流加密+密码表流水线"))
                log(f"  流水线解出 {len([o for o in rep.outcomes if o.path in dict(decrypted)])} 个文件")

    # --- 第二段：通用链式搜索（处理剩下没解开的） ----------------------
    solved = {o.path for o in rep.outcomes if o.score >= SUCCESS_SCORE or o.verified is True}
    remaining = [p for p in targets if p not in solved]
    if remaining:
        log(f"进入通用链式搜索：{len(remaining)} 个文件")
        engine = search.Engine(ctx, depth=opts.depth, beam=opts.beam, time_budget=opts.timeout,
                               work_limit=opts.work_limit, log=log)
        for path in remaining:
            data = by_path[path]
            fmt = opts.fmt or guess_format(path, data)
            magic = alphabets.FORMAT_MAGIC.get(fmt, b"")
            ctx.fmt = fmt
            ctx.known_spans = [(0, magic)] if magic else []
            if opts.assume_flag_prefix and os.path.basename(path).lower().startswith(
                    ("flag", "key", "ans")):
                ctx.known_spans.insert(0, (0, b"flag{"))
            results = engine.solve(data, label=path)
            if not results:
                # 再补一刀：像"人写的字母文本"就直接跑古典密码破解
                outcome = _classical_fallback(path, data, ctx, log)
                if outcome:
                    rep.outcomes.append(outcome)
                    continue
                # 最后：flag 片段收集 + 拼接（逆向题"flag 被拆成几段"那一类）
                if opts.fragments:
                    outcome = _fragments_fallback(path, data, ctx, log)
                    if outcome:
                        rep.outcomes.append(outcome)
                        continue
                # Python 字节码题：读常量 + 逐字节线性公式反推
                outcome = _pyc_fallback(path, data, ctx, log)
                if outcome:
                    rep.outcomes.append(outcome)
                continue
            best = results[0]
            rep.outcomes.append(Outcome(path, best.data, best.steps, best.score,
                                        [str(v) for v in best.verdicts[:4]],
                                        [best.describe()], best.roundtrip, "链式搜索"))
            log(f"  {os.path.basename(path)}: {best.describe()}")

    # --- 把候选喂回程序自己跑一遍（可选，但这是最硬的证据）----------------
    if opts.verify_emulate and rep.outcomes:
        log("\n[模拟执行确认] 把候选输入喂回程序，让它自己判对错")
        try:
            confirm_by_emulation(rep, opts, log,
                                 binaries=list(opts.emulate_binaries) or None)
        except Exception as exc:                       # 确认失败不该让整条流水线崩
            log(f"  模拟执行确认过程出错（忽略）：{type(exc).__name__}: {exc}")

    # --- 输出 -----------------------------------------------------------
    rep.elapsed = time.time() - started
    if opts.out_dir:
        write_outputs(rep, opts.out_dir, log)
    return rep


def _classical_fallback(path: str, data: bytes, ctx: Ctx, log: Callable) -> Optional[Outcome]:
    """链式搜索没结果时的兜底：像字母文本就直接跑古典密码破解。

    注意：base64/hex 这类文本"字母比例"也高，但基本没有空格，很容易被瞎破解出
    一堆假结果，所以要求"字母 + 空格"占比 ≥ 0.9；并且**必须尊重 crib**。
    """
    from . import crack, langscore
    blob = data[:4096]
    if len(data) < 40 or langscore.printable_ratio(blob) < 0.95:
        return None
    letters_spaces = sum(1 for b in blob if 65 <= b <= 90 or 97 <= b <= 122 or b == 0x20)
    if letters_spaces / len(blob) < 0.9:
        return None
    results = crack.crack_all(data, deep=ctx.deep)
    if not results:
        return None
    best = results[0]
    if best.score < 0.5:
        return None
    if ctx.crib is not None and ctx.crib not in best.plaintext:
        return None
    if ctx.crib_regex is not None and not ctx.crib_regex.search(best.plaintext):
        return None
    log(f"  古典密码兜底：{best.kind} {best.params} 得分 {best.score:.2f}")
    return Outcome(path, best.plaintext, [Step("classical", {"kind": best.kind,
                                                             "found": best.params.replace(",", ";")})],
                   best.score, [f"{best.kind} 得分 {best.score:.2f}"],
                   [f"古典密码兜底：{best.kind}"], None, "古典密码破解")


def _fragments_fallback(path: str, data: bytes, ctx: Ctx, log: Callable) -> Optional[Outcome]:
    """兜底：flag 被拆成几段（明文/hex/base64…）散落在程序里 → 收集并拼接。"""
    from . import fragments
    if len(data) < 64 or len(data) > (64 << 20):
        return None
    found = fragments.best_flag(data, crib=ctx.crib)
    if not found:
        return None
    flag, parts = found
    if ctx.crib and not flag.startswith(ctx.crib):
        return None
    kinds = [p.kind for p in parts]
    quality = fragments.flag_quality(flag)
    if quality < 0.6:
        log(f"  片段拼接出 {flag.decode('utf-8', 'replace')!r}，但正文不像真 flag，"
            f"按噪声丢弃")
        return None
    log(f"  片段拼接成功：{flag.decode('utf-8', 'replace')}（{'+'.join(kinds)}）")
    return Outcome(path, flag, [Step("fragments", {"parts": "+".join(kinds)})],
                   0.95 * quality,
                   [f"flag 片段拼接（{len(parts)} 段：{'、'.join(kinds)}）"],
                   [f"片段来源：{[str(p) for p in parts]}",
                    "⚠ 逆向题常在附件里埋诱饵 flag：命中这一条也要用题目环境验证过再提交"],
                   None, "flag 片段拼接")


def _pyc_fallback(path: str, data: bytes, ctx: Ctx, log: Callable) -> Optional[Outcome]:
    """兜底：Python 字节码（.pyc）→ 读常量 + 逐字节线性公式搜索还原 flag。"""
    from . import formula as _formula
    from . import pyc as _pyc
    if _pyc.pyc_version(data) is None and not data[:2] == b"\x63\x00":
        return None
    try:
        root = _pyc.load_code(data)
    except Exception as exc:
        log(f"  .pyc 解析失败：{type(exc).__name__}: {exc}")
        return None
    info = _pyc.summary(root)
    hex_blobs = [bytes.fromhex(h) for h in info["hex"] if len(h) >= 12]
    if not hex_blobs:
        return None
    ints = [c for c in root.consts if isinstance(c, int)]
    log(f"  .pyc：Python {_pyc.pyc_version(data)}，code={info['codes']}，"
        f"十六进制常量 {len(hex_blobs)} 个")
    found = _formula.crack_pyc_constants(hex_blobs, info["strings"], ints, crib=ctx.crib)
    if not found:
        return None
    note, hit = found[0]
    log(f"  逐字节公式还原成功：{hit.plaintext.decode('utf-8', 'replace')}（目标={note}）")
    return Outcome(path, hit.plaintext, [Step("formula", {"a": hit.formula.a, "b": hit.formula.b,
                                                          "c": hit.formula.c, "rol": hit.formula.r,
                                                          "xor": hit.formula.k, "target": note})],
                   max(hit.score, 0.95),
                   [f"字节码常量 + 线性公式反推（{hit.formula}）"],
                   [f"code objects：{info['codes']}", f"目标字节来源：{note}"],
                   None, "Python 字节码还原")


def write_outputs(rep: Report, out_dir: str, log: Callable) -> None:
    os.makedirs(out_dir, exist_ok=True)
    for o in rep.outcomes:
        # 复核通过（重新加密能还原）的和结构校验过关的都写出来
        if o.score < SUCCESS_SCORE and o.verified is not True:
            continue
        name = os.path.basename(o.path)
        for suffix in recover.PAIR_SUFFIXES:
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                break
        dest = os.path.join(out_dir, name)
        try:
            with open(dest, "wb") as fh:
                fh.write(o.plaintext)
            log(f"  写出 {dest}")
        except OSError as exc:
            log(f"  写出失败 {dest}: {exc}")
    report_path = os.path.join(out_dir, "解密报告.md")
    try:
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(render_report(rep))
        log(f"  写出报告 {report_path}")
    except OSError:
        pass


def outcome_evidence(outcome) -> Tuple[str, str]:
    """给一条结果定"证据等级"（借鉴看雪 r0re 的完成门控）。

    只看分数是不够的：投稿包实测里，**形状像 flag** 的东西既可能是真答案，
    也可能是出题人埋的诱饵，还可能是二进制噪声凑出来的（曾出现过
    ``jc_{8_&vfo9?_uL_}`` 这种 0.95 分的假阳性）。所以要区分：

    * ``binary``   —— 用了程序里存的密文/已知明文做确认（``verify`` 那一步）；
    * ``roundtrip``—— 解出来的结果**重新加密回去等于原密文**（自洽性验证）；
    * ``oracle``   —— 结构判据强通过：CRC 全对、段结构完整、确实是完整文件；
    * ``shape``    —— 只有形状：拼出 ``xxx{...}``、命中 crib 前缀（**诱饵长这样**）；
    * ``heuristic``/``text`` —— 启发式/语言模型认为像，最弱。

    返回 ``(等级, 依据)``。
    """
    from . import board as _board
    steps = {s.name for s in getattr(outcome, "steps", []) or []}
    verdicts = " ".join(getattr(outcome, "verdicts", []) or [])
    if "verify" in steps:
        return "binary", "用程序内密文/已知明文确认过"
    if getattr(outcome, "verified", None) is True:
        return "roundtrip", "结果重新加密回去与原密文一致"
    if any(k in verdicts for k in ("CRC 全通过", "结构", "段结构", "完整")):
        return "oracle", "结构判据强通过"
    if "fragments" in steps:
        return "shape", "flag 片段拼接（形状判据，可能是诱饵）"
    if "formula" in steps or "classical" in steps:
        return "shape", "恒定/线性关系推出来的形状"
    if getattr(outcome, "score", 0) >= SUCCESS_SCORE:
        return "heuristic", "启发式高分，无外部校验"
    del _board
    return "text", "仅语言模型觉得像"


def evidence_summary(outcomes) -> str:
    """把若干条结果按证据等级汇总成人话（报告开头的那段"到底哪个能信"）。"""
    from . import board as _board
    graded = [(o, *outcome_evidence(o)) for o in outcomes]      # Outcome 不可哈希
    confirmed = [g for g in graded
                 if _board.evidence_level(g[1]) >= _board.STRONG_EVIDENCE]
    weak = [g for g in graded if g not in confirmed]
    lines: List[str] = []
    if confirmed:
        lines.append(f"✅ 已确认 {len(confirmed)} 条（有强证据，可以直接采用）：")
        for o, kind, why in confirmed:
            lines.append(f"   · [{kind}] {o.plaintext[:80]!r} ← {why}")
    if weak:
        lines.append(f"⚠ 未确认 {len(weak)} 条（**只能当线索**，诱饵 flag 就长这样）：")
        for o, kind, why in weak:
            lines.append(f"   · [{kind}] {o.plaintext[:80]!r} ← {why}")
        lines.append("   建议：用 `verify`（拿程序内密文反查）或 `emu --run --stdin 候选`"
                     "（让程序自己判对错）把它升级成强证据，再提交。")
    return "\n".join(lines)


def confirm_by_emulation(rep: Report, opts, log: Callable,
                         binaries: Optional[List[str]] = None,
                         max_candidates: int = 6) -> int:
    """**把候选 flag 喂回程序自己跑一遍**（模拟执行），通过就升级成强证据。

    这是逆向题里最硬的一步验证：不看代码怎么写的，直接问程序"这个输入对不对"。
    它能一次性解决两个老大难问题：

    * 诱饵 flag —— 出题人埋的假答案喂进去，程序会明确说不对；
    * 形状假阳性 —— 噪声拼出来的 ``xxx{...}`` 同样过不了程序这一关。

    PE 会被接管导入表（``strcmp``/``memcmp``/``fgets``/``printf`` 全由宿主实现）并
    铺好 TEB/PEB，所以反调试探测一律看到"没有调试器"，**不需要也不应该真的运行样本**。
    返回升级成功的结果条数。
    """
    from . import emu as _emu
    if binaries is None:
        roots = set()
        for o in rep.outcomes:
            roots.add(os.path.dirname(os.path.abspath(o.path)))
        binaries = []
        for root in roots:
            for name in sorted(os.listdir(root)) if os.path.isdir(root) else []:
                path = os.path.join(root, name)
                if not os.path.isfile(path):
                    continue
                try:
                    with open(path, "rb") as fh:
                        head = fh.read(4)
                except OSError:
                    continue
                if head[:4] in (b"\x7fELF",) or head[:2] == b"MZ":
                    binaries.append(path)
    if not binaries:
        log("  模拟执行确认：目录里没有可执行文件，跳过")
        return 0
    candidates = [o for o in rep.outcomes if o.plaintext.strip()][:max_candidates]
    if not candidates:
        return 0
    upgraded = 0
    for outcome in candidates:
        flag = outcome.plaintext.strip()
        if len(flag) < 4 or b" " in flag[:4]:
            continue
        for binary in binaries[:3]:
            try:
                with open(binary, "rb") as fh:
                    blob = fh.read()
            except OSError:
                continue
            try:
                res = _emu.run_main(blob, stdin=flag + b"\n",
                                    max_ins=getattr(opts, "emulate_max_ins", 400000))
            except Exception as exc:
                log(f"  模拟执行 {os.path.basename(binary)} 失败："
                    f"{type(exc).__name__}: {exc}")
                continue
            where = os.path.basename(binary)
            if res["result"] is True:
                outcome.verified = True
                outcome.score = max(outcome.score, 0.99)
                outcome.verdicts.append("模拟执行：程序自身判定为正确")
                outcome.notes.append(
                    f"用 `{where}` 模拟执行确认（入口 0x{res['entry_used']:x}，"
                    f"{res['entry_why']}）：{res['stdout'].strip()[-60:]!r}")
                log(f"  ★ 模拟执行确认：`{where}` 接受 "
                    f"{flag.decode('utf-8', 'replace')}（证据升级为 emulate）")
                upgraded += 1
                break
            if res["result"] is False:
                outcome.notes.append(f"模拟执行：`{where}` 判定该候选**错误**"
                                     f"（{res['stdout'].strip()[-40:]!r}）")
                log(f"  ✗ 模拟执行：`{where}` 不接受 "
                    f"{flag.decode('utf-8', 'replace')} —— 多半是诱饵/假阳性")
    return upgraded


def render_report(rep: Report) -> str:
    lines = ["# 一条龙解密报告", ""]
    lines.append(f"- 耗时：{rep.elapsed:.1f} 秒")
    lines.append(f"- 密钥候选：{rep.keys_tried} 个")
    lines.append(f"- 明文/密文配对：{len(rep.pairs)} 组")
    lines.append("")
    if rep.outcomes:
        lines.append("## 证据等级（先看这段：哪些能信、哪些只是线索）")
        lines.append("```")
        lines.append(evidence_summary(rep.outcomes))
        lines.append("```")
        lines.append("")
    if rep.pairs:
        lines.append("## 配对分析")
        for pr in rep.pairs:
            lines.append(f"- `{os.path.basename(pr.plain_path)}` ↔ "
                         f"`{os.path.basename(pr.cipher_path)}`：{pr.layer.get('kind', '未知')}")
            for note in pr.notes:
                lines.append(f"  - {note}")
        lines.append("")
    lines.append("## 结果")
    for o in rep.outcomes:
        kind, why = outcome_evidence(o)
        lines.append(f"### `{os.path.basename(o.path)}`　评分 {o.score:.2f}"
                     f"{'（复核通过）' if o.verified else ''}　证据={kind}")
        lines.append(f"- 证据依据：{why}")
        lines.append(f"- 来源：{o.source}")
        lines.append(f"- 配方：`{o.recipe}`")
        for v in o.verdicts:
            lines.append(f"- 校验：{v}")
        for note in o.notes:
            lines.append(f"- 说明：{note}")
        preview = o.plaintext[:200]
        try:
            text = preview.decode("utf-8").replace("\r", "")
        except UnicodeDecodeError:
            text = preview.hex(" ")
        lines.append("- 明文预览：")
        lines.append("```")
        lines.append(text)
        lines.append("```")
        lines.append("")
    return "\n".join(lines)
