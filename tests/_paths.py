"""测试用的路径解析 —— 把"本机私有样本目录"从测试代码里解耦出来。

公开仓库里不该出现 ``D:\\题目下载包\\...`` 这种本机绝对路径，否则别人 clone 下来
只会看到一堆 ``FileNotFoundError`` 而不知道原因。这里做三件事：

1. :func:`ensure_repo_on_path` —— 由 ``__file__`` 推出仓库根目录并加进 ``sys.path``，
   任何人 clone 下来都能 ``from pseek import ...``；
2. :func:`data_root` —— 私有样本目录优先读环境变量 ``AUTOCRYPT_DATA``，
   没设置就用"仓库的上一级目录"（本地开发的旧布局）；
3. :func:`sample` —— 取样本；**不存在时抛 ``MissingSample`` 并给出人话原因**，
   而不是让调用方在几十行之后崩在 ``FileNotFoundError``。

用法（在任何测试脚本开头）::

    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _paths import ensure_repo_on_path, sample

    ensure_repo_on_path()
    from pseek import ciphers          # 现在可以正常 import

    EXE = sample("待解题/100w_20260919162532.exe")
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

#: 仓库根目录（autocrypt/）
REPO_ROOT = Path(__file__).resolve().parent.parent


class MissingSample(Exception):
    """缺少本机私有样本——这是**预期内**的情况，不是测试失败。"""


def ensure_repo_on_path() -> Path:
    """把仓库根目录加进 ``sys.path``（幂等）。返回仓库根目录。"""
    root = str(REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    return REPO_ROOT


def data_root() -> Path:
    """私有样本根目录。

    * 环境变量 ``AUTOCRYPT_DATA`` 优先（推荐：`set AUTOCRYPT_DATA=D:\\你的题目目录`）；
    * 否则用仓库的上一级目录（本地开发时的旧布局）。
    """
    env = os.environ.get("AUTOCRYPT_DATA")
    if env:
        return Path(env).expanduser().resolve()
    return REPO_ROOT.parent


def sample(relative: str) -> Path:
    """取一个样本路径；**不存在时打印一行原因并以"跳过"退出（code 0）**。

    为什么直接退出而不抛异常给调用方：这些脚本都是"要么有样本、要么别跑"的一次性实验，
    在公开仓库里别人 clone 下来跑它们，最友好的结果是
    ``[跳过] 缺少本机样本：…（怎么设置 AUTOCRYPT_DATA）`` 之后干净退出，
    而不是甩一屏 traceback。需要自己处理缺样本的调用方请用 :func:`optional_sample`。
    """
    path = data_root() / relative
    if not path.exists():
        print(f"[跳过] 缺少本机样本：{path}")
        print("       这个脚本需要一份私有样本文件/目录，公开仓库里不会附带。")
        print("       样本在别处的话，设置环境变量后重跑：")
        print("         Windows cmd : set AUTOCRYPT_DATA=D:\\你的样本根目录")
        print("         PowerShell  : $env:AUTOCRYPT_DATA='D:\\你的样本根目录'")
        raise SystemExit(0)
    return path


def optional_sample(relative: str) -> Optional[Path]:
    """取样本；不存在则返回 ``None``（调用方自己决定跳过）。"""
    path = data_root() / relative
    return path if path.exists() else None
