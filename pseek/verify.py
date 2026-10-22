"""密钥确认：拿"程序里存着的密文"当标准答案，反查候选密钥。

思路（逆向题里非常常见的一种破法）
--------------------------------
逆向题经常把**密文**直接放在程序里，密钥由输入派生。这种情况下我们不需要
知道明文——只要有两种确认方式之一，就能把密钥空间砍到一个点：

* **方式 A：加密已知明文 → 在程序里找这段密文**
  程序里同时有明文常量和它的密文（crackme 常见）时，这个方向极其好用：
  对候选密钥做一次加密，然后 ``binary.find(密文)``，命中即确认。
  分组密码只需要**一个已知分组**（8/16 字节）就够。

* **方式 B：解密已知密文 → 用结构判据验证明文**
  已经从逆向里定位到密文（偏移或十六进制）时，对候选密钥解密，
  看解出来的东西是否满足：``长度前缀+flag``、flag 正则、文本、文件格式……
  每个候选密钥只要一次解密 + 一次判据，100 万个候选也就是十几秒。

配合 ``--keyspace``（数字/十六进制掩码）+ ``--derive``（md5/sha1/…）或
``--key-script``（把程序里的派生逻辑照抄成十几行），就能把"6 位输入"这种
空间全自动枚举出来，并且**由程序里的密文自证**，不需要人眼判断。

* **方式 C：交给用户自己的模拟执行脚本**（``pseek/examples/emulate_template.py``）
  要模拟密钥构造/解密机器码时，用 ``--emulate-script``：工具负责枚举候选密钥、
  调用你的脚本、再用结构判据判定结果。
"""

from __future__ import annotations

import hashlib
import importlib.util
import itertools
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from . import ciphers, langscore, oracles


# --------------------------------------------------------------------------
# 候选密钥空间
# --------------------------------------------------------------------------

@dataclass
class Keyspace:
    """枚举"输入"，并按 derive 规则派生成密钥。"""

    kind: str = "none"          # none | digits | hex | lower | alnum | range | words
    length: int = 6
    derive: str = "raw"         # raw | md5 | sha1 | sha256 | md5_hex | sha1_hex | sha256_hex
    words_file: Optional[str] = None
    start: int = 0
    end: int = 0

    def __str__(self) -> str:
        if self.kind == "none":
            return "（不枚举）"
        return f"{self.kind}×{self.length} 派生={self.derive}"


def _derive(token: bytes, derive: str) -> List[bytes]:
    """把枚举出来的输入派生成密钥候选（一个输入可能给出多个候选）。"""
    rules = [r.strip() for r in derive.split("+") if r.strip()] or ["raw"]
    out: List[bytes] = []
    for rule in rules:
        if rule == "raw":
            out.append(token)
        elif rule in ("md5", "sha1", "sha256"):
            out.append(hashlib.new(rule, token).digest())
        elif rule.endswith("_hex"):
            out.append(hashlib.new(rule[:-4], token).hexdigest().encode())
        elif rule == "upper":
            out.append(token.upper())
        elif rule == "lower":
            out.append(token.lower())
        elif rule.startswith("pad"):
            # pad8 / pad16：右侧补零到指定长度
            try:
                size = int(rule[3:] or "8")
            except ValueError:
                size = 8
            out.append(token + b"\x00" * max(0, size - len(token)))
    return [k for k in out if k]


def keyspace_tokens(space: Keyspace, limit: int = 0) -> Iterator[str]:
    kind = space.kind
    n = 0
    if kind in ("digits", "hex", "lower", "alnum"):
        alphabets = {
            "digits": "0123456789",
            "hex": "0123456789abcdef",
            "lower": "abcdefghijklmnopqrstuvwxyz",
            "alnum": "0123456789abcdefghijklmnopqrstuvwxyz",
        }
        alphabet = alphabets[kind]
        for combo in itertools.product(alphabet, repeat=max(1, space.length)):
            yield "".join(combo)
            n += 1
            if limit and n >= limit:
                return
    elif kind == "range":
        end = space.end or (space.start + 10 ** max(1, space.length))
        for value in range(space.start, end):
            yield str(value).zfill(max(1, space.length)) if space.length else str(value)
            n += 1
            if limit and n >= limit:
                return
    elif kind == "words":
        path = space.words_file
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    token = line.strip()
                    if token:
                        yield token
                        n += 1
                        if limit and n >= limit:
                            return


def keyspace_keys(space: Keyspace, limit: int = 0) -> Iterator[Tuple[str, bytes]]:
    """产出 (标签, 密钥候选)。标签就是"输入"，最后要报给用户。"""
    if space.kind == "none":
        return
    for token in keyspace_tokens(space, limit):
        for key in _derive(token.encode(), space.derive):
            yield token, key


def load_key_script(path: str):
    """加载用户脚本：可定义 keys(ctx) 生成器，或 KS 列表。

    生成器可以 ``yield key`` 或 ``yield (label, key)``（推荐后者，方便报出"输入"）。
    """
    spec = importlib.util.spec_from_file_location("autocrypt_verify_script", path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def script_keys(mod, ctx=None) -> Iterator[Tuple[str, bytes]]:
    fn = getattr(mod, "keys", None)
    if callable(fn):
        for item in fn(ctx):
            if isinstance(item, tuple) and len(item) == 2:
                label, key = item
                yield str(label), key if isinstance(key, bytes) else str(key).encode()
            else:
                key = item if isinstance(item, bytes) else str(item).encode()
                yield key.decode("utf-8", "replace"), key


# --------------------------------------------------------------------------
# 密码规格与加解密
# --------------------------------------------------------------------------

DEFAULT_CIPHERS = ("des", "des3", "aes", "rc4", "rc4v", "xor", "xtea", "xxtea", "tea")


def parse_cipher(text: str) -> Dict[str, object]:
    """解析 ``des:mode=ecb,key_transform=bitrev`` 这样的密码规格。"""
    name, _, body = text.partition(":")
    params: Dict[str, object] = {}
    if body:
        for pair in body.split(","):
            if not pair.strip():
                continue
            k, _, v = pair.partition("=")
            k, v = k.strip(), v.strip()
            if v.lower().startswith("0x"):
                params[k] = int(v, 16)
            else:
                try:
                    params[k] = int(v)
                except ValueError:
                    params[k] = v
    return {"name": name.strip(), "params": params}


def encrypt_with(spec: Dict[str, object], key: bytes, data: bytes,
                 key_transform: str = "raw") -> bytes:
    """按规格加密（用于"加密已知明文→在程序里找密文"）。"""
    name = str(spec["name"])
    p = dict(spec.get("params") or {})
    k = ciphers.transform_key(key, key_transform)
    if name == "des":
        return ciphers.des_crypt(data, k, mode=str(p.get("mode", "ecb")),
                                 transform="raw", decrypt=False)
    if name == "des3":
        return ciphers.des3_crypt(data, k, mode=str(p.get("mode", "ecb")),
                                  transform="raw", decrypt=False)
    if name == "aes":
        return ciphers.aes_crypt(data, k, mode=str(p.get("mode", "ecb")), decrypt=False)
    if name in ("rc4", "rc4v"):
        return ciphers.rc4(data, k, mask_id=int(p.get("mask", 0 if name == "rc4" else 1)),
                           p1=int(p.get("p1", 0x72 if name == "rc4v" else 0)),
                           p2=int(p.get("p2", 0x37 if name == "rc4v" else 0)),
                           ksa_id=int(p.get("ksa", 0)), drop=int(p.get("drop", 0)))
    if name == "xor":
        return bytes(b ^ (k[i % len(k)] if k else 0) for i, b in enumerate(data))
    if name == "xtea":
        return ciphers.xtea_crypt(data, k, decrypt=False, endian=str(p.get("endian", "<")))
    if name == "xxtea":
        return ciphers.xxtea_crypt(data, k, decrypt=False, endian=str(p.get("endian", "<")))
    if name == "tea":
        return ciphers.tea_crypt(data, k, decrypt=False, endian=str(p.get("endian", "<")))
    raise ValueError(f"不支持的密码规格：{name}")


def decrypt_with(spec: Dict[str, object], key: bytes, data: bytes,
                 key_transform: str = "raw") -> bytes:
    name = str(spec["name"])
    p = dict(spec.get("params") or {})
    k = ciphers.transform_key(key, key_transform)
    if name == "des":
        return ciphers.des_crypt(data, k, mode=str(p.get("mode", "ecb")), transform="raw")
    if name == "des3":
        return ciphers.des3_crypt(data, k, mode=str(p.get("mode", "ecb")), transform="raw")
    if name == "aes":
        return ciphers.aes_crypt(data, k, mode=str(p.get("mode", "ecb")))
    if name in ("rc4", "rc4v"):
        return ciphers.rc4(data, k, mask_id=int(p.get("mask", 0 if name == "rc4" else 1)),
                           p1=int(p.get("p1", 0x72 if name == "rc4v" else 0)),
                           p2=int(p.get("p2", 0x37 if name == "rc4v" else 0)),
                           ksa_id=int(p.get("ksa", 0)), drop=int(p.get("drop", 0)))
    if name == "xor":
        return bytes(b ^ (k[i % len(k)] if k else 0) for i, b in enumerate(data))
    if name == "xtea":
        return ciphers.xtea_crypt(data, k, endian=str(p.get("endian", "<")))
    if name == "xxtea":
        return ciphers.xxtea_crypt(data, k, endian=str(p.get("endian", "<")))
    if name == "tea":
        return ciphers.tea_crypt(data, k, endian=str(p.get("endian", "<")))
    raise ValueError(f"不支持的密码规格：{name}")


BLOCK_SIZES = {"des": 8, "des3": 8, "aes": 16, "xtea": 8, "xxtea": 4, "tea": 8}


def confirm_threshold_note() -> str:
    """说明为什么确认阈值不能设低。"""
    return ("确认阈值默认 0.85：弱判据（例如“疑似 flag” 0.8、只看 magic 的格式判定）"
            "刻意被排除在“确认”之外——百万级枚举下，任何假阳性率高于百万分之一的判据"
            "都必然误报。")


def _pad(data: bytes, block: int, mode: str) -> bytes:
    if block <= 1:
        return data
    rest = len(data) % block
    if rest == 0:
        return data
    if mode == "pkcs7":
        pad = block - rest
        return data + bytes([pad]) * pad
    return data + b"\x00" * (block - rest)


_PRINTABLE_PLUS_NUL = bytes(range(0x20, 0x7F)) + b"\x00\t\n\r"
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{8,}")


def _plausible_plain(data: bytes) -> bool:
    """便宜的先验：明文应当基本由可打印字符 + NUL 组成（自写格式常有零填充）。

    注意要**跳过开头 4 字节**再看比例：很多格式是"长度前缀 + 文本"，
    长度字节本身（如 0x1c）不是可打印字符，不跳过就会把正确答案也筛掉。

    这一步能把绝大多数错误密钥在一次 translate 内淘汰，否则每个候选都跑全量
    oracle，100 万候选要几分钟。最后那条兜底只是"放行"候选，不代表判定通过——
    真正的判定仍然由 oracle 做。
    """
    if len(data) < 4:
        return False
    body = data[4:] if len(data) > 12 else data
    if len(body.translate(None, _PRINTABLE_PLUS_NUL)) * 20 <= len(body):
        return True
    if len(data.translate(None, _PRINTABLE_PLUS_NUL)) * 10 <= len(data):
        return True
    return bool(_PRINTABLE_RUN.search(data))


# --------------------------------------------------------------------------
# 确认
# --------------------------------------------------------------------------

@dataclass
class Confirm:
    key: bytes
    label: str
    cipher: str
    key_transform: str
    offset: int = -1
    plaintext: bytes = b""
    ciphertext: bytes = b""
    score: float = 0.0
    mode: str = ""
    note: str = ""

    def line(self) -> str:
        where = f"程序内偏移 0x{self.offset:x}" if self.offset >= 0 else "结构判据命中"
        text = self.plaintext[:64]
        try:
            shown = text.decode("utf-8", "replace").replace("\n", "\\n")
        except Exception:
            shown = text.hex(" ")
        return (f"[{self.mode}] 输入={self.label!r} 密钥={self.key!r} "
                f"密码={self.cipher}({self.key_transform}) {where} → {shown}")


def harvest_plaintext_candidates(blob: bytes, min_len: int = 8, limit: int = 64) -> List[bytes]:
    """从程序里抓"可能是明文常量"的串（含 flag 形式）。"""
    out: List[bytes] = []
    seen = set()
    for m in re.finditer(rb"[\x20-\x7e]{%d,64}" % min_len, blob[: 8 << 20]):
        token = m.group(0)
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
        if len(out) >= limit:
            break
    for m in re.finditer(rb"[A-Za-z0-9_]{2,20}\{[ -~]{6,120}\}", blob[: 8 << 20]):
        if m.group(0) not in seen:
            seen.add(m.group(0))
            out.insert(0, m.group(0))
    return out[:limit]


def plaintext_templates(prefix: bytes, block: int, try_lenprefix: bool = False,
                        max_len: int = 64) -> List[bytes]:
    """由一个已知明文前缀生成候选分组（补零/PKCS7/长度前缀变体）。"""
    out: List[bytes] = []
    out.append(_pad(prefix, block, "zero"))
    pkcs = _pad(prefix, block, "pkcs7")
    if pkcs != out[0]:
        out.append(pkcs)
    if try_lenprefix:
        for size in (4, 2):
            for endian in ("little", "big"):
                for length in range(6, max_len + 1):
                    head = length.to_bytes(size, endian) + prefix
                    cand = _pad(head, block, "zero")
                    if cand not in out:
                        out.append(cand)
    return out


def run_verify(binary_path: str, ciphers_list: Sequence[str] = DEFAULT_CIPHERS,
               keys: Sequence[bytes] = (), key_labels: Sequence[str] = (),
               keyspace: Optional[Keyspace] = None, key_script: Optional[str] = None,
               key_transforms: Sequence[str] = ("bitrev", "raw", "reverse", "bitrev_all"),
               verify_plain: Optional[bytes] = None, try_lenprefix: bool = False,
               ciphertext: Optional[bytes] = None, ciphertext_offset: int = -1,
               ciphertext_length: int = 0, threshold: float = 0.85,
               max_candidates: int = 2_000_000, time_budget: float = 300.0,
               log: Callable[[str], None] = print,
               emulate_script: Optional[str] = None) -> List[Confirm]:
    """全部确认流程。返回按分数/命中方式排序的确认结果。"""
    with open(binary_path, "rb") as fh:
        blob = fh.read()
    log(f"目标程序：{binary_path}（{len(blob)} 字节）")

    # 密文来源
    target_ct: Optional[bytes] = None
    if ciphertext:
        target_ct = ciphertext
        log(f"使用给定密文：{len(target_ct)} 字节")
    elif ciphertext_offset >= 0:
        end = ciphertext_offset + ciphertext_length if ciphertext_length else len(blob)
        target_ct = blob[ciphertext_offset:end]
        log(f"使用程序内偏移 0x{ciphertext_offset:x} 起的 {len(target_ct)} 字节作为密文")

    # 明文模板
    if verify_plain:
        templates = plaintext_templates(verify_plain, 8, try_lenprefix)
        templates16 = plaintext_templates(verify_plain, 16, try_lenprefix)
        log(f"已知明文前缀 {verify_plain[:24]!r} → {len(templates)} 个 8 字节模板 / "
            f"{len(templates16)} 个 16 字节模板"
            + ("（含长度前缀变体）" if try_lenprefix else ""))
    else:
        harvested = harvest_plaintext_candidates(blob)
        templates = [_pad(p, 8, "zero") for p in harvested[:32]]
        templates16 = [_pad(p, 16, "zero") for p in harvested[:32]]
        log(f"未指定已知明文 → 从程序里抓了 {len(harvested)} 个候选明文常量")

    specs = [parse_cipher(c) for c in ciphers_list]
    results: List[Confirm] = []
    deadline = time.time() + time_budget
    tried = 0

    def key_stream() -> Iterator[Tuple[str, bytes]]:
        seen = set()
        for i, k in enumerate(keys):
            label = key_labels[i] if i < len(key_labels) else k.decode("utf-8", "replace")
            if k and k not in seen:
                seen.add(k)
                yield label, k
        if keyspace:
            for label, k in keyspace_keys(keyspace):
                if k in seen:
                    continue
                seen.add(k)
                yield label, k
        if key_script:
            mod = load_key_script(key_script)
            if mod is not None:
                for label, k in script_keys(mod):
                    if k in seen:
                        continue
                    seen.add(k)
                    yield label, k

    def check_candidate(label: str, key: bytes) -> Optional[Confirm]:
        for spec in specs:
            name = str(spec["name"])
            block = BLOCK_SIZES.get(name, 1)
            for kt in key_transforms:
                # 方式 A：加密已知明文 → 在程序里找密文
                if target_ct is None:
                    pool = templates16 if block == 16 else templates
                    for pt in pool:
                        try:
                            ct = encrypt_with(spec, key, pt, kt)
                        except Exception:
                            continue
                        if len(ct) < 6:
                            continue
                        idx = blob.find(ct)
                        if idx >= 0:
                            return Confirm(key, label, name, kt, idx, pt, ct, 1.0, "A 加密反查",
                                           "程序里存有这段密文的明文常量")
                else:
                    # 方式 B：解密已知密文 → 结构判据
                    data = target_ct
                    if block > 1:
                        data = data[: len(data) - len(data) % block]
                        if not data:
                            continue
                    try:
                        pt = decrypt_with(spec, key, data, kt)
                    except Exception:
                        continue
                    # 便宜的先验过滤：明文必须"只由可打印字符和 NUL 组成"，
                    # 否则直接丢掉——不然后面全量 oracle 会拖慢几千倍
                    if not _plausible_plain(pt):
                        continue
                    verdicts = oracles.evaluate(pt)
                    score = verdicts[0].score if verdicts else 0.0
                    lang = langscore.score_bytes(pt).score
                    if score >= threshold or (not verdicts and lang >= threshold):
                        return Confirm(key, label, name, kt, ciphertext_offset, pt, target_ct,
                                       max(score, lang), "B 解密验证",
                                       str(verdicts[0]) if verdicts else "语言模型判定为文本")
        return None

    def scan_one(label: str, key: bytes) -> Optional[Confirm]:
        nonlocal tried
        tried += 1
        return check_candidate(label, key)

    # 方式 C：用户自备模拟执行脚本（每候选密钥调用一次）
    if emulate_script:
        mod = load_key_script(emulate_script)
        fn = getattr(mod, "verify", None) if mod else None
        if callable(fn):
            log("使用模拟执行脚本逐个候选验证…")
            for label, key in key_stream():
                if tried >= max_candidates or time.time() > deadline:
                    break
                tried += 1
                try:
                    produced = fn(key, blob, label)
                except Exception:
                    continue
                if not produced:
                    continue
                verdicts = oracles.evaluate(produced)
                score = verdicts[0].score if verdicts else 0.0
                if score >= threshold:
                    results.append(Confirm(key, label, "emulate", "raw", -1, produced, b"",
                                           score, "C 模拟执行", str(verdicts[0])))
                    log(f"  命中：{results[-1].line()}")
                    break
            return results

    log("开始枚举候选密钥…")
    started = time.time()
    for label, key in key_stream():
        if tried >= max_candidates or time.time() > deadline:
            log(f"达到上限（试了 {tried} 个候选）")
            break
        hit = scan_one(label, key)
        if hit:
            results.append(hit)
            log(f"  命中：{hit.line()}")
            break
        if tried % 50000 == 0:
            elapsed = time.time() - started
            rate = tried / elapsed if elapsed else 0
            log(f"  …已试 {tried} 个候选（{elapsed:.0f}s，{rate:.0f} 个/秒）")
    log(f"共尝试 {tried} 个候选密钥，得到 {len(results)} 个确认结果")
    return results
