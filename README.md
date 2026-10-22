# plainseek

**寻明文。** 一条解密流水线 + 一个带证据的逆向工作台。

> 它**不保证**给出明文。它做的是两件事：
> 把"能自动的"自动掉；把"不能自动的"变成一条**排好序、带证据的线索清单**。

[English](README.en.md) · [逐命令详解](docs/commands.md) · [实测基准线](BENCHMARK.md) · [MIT](LICENSE)

---

## 先说清楚它分两档

| 档 | 场景 | 期望 |
|---|---|---|
| **A 档：全自动** | 层层编码、被打乱的字符表、古典密码、结构可判的现代密码（AES/DES/RC4…）、flag 片段拼接、pyc 常量还原 | 一条命令跑完，给出明文 + 证据等级，**大多数情况确实能出** |
| **B 档：半自动** | 原生逆向题：加壳、自定义 VM、GUI、C++ 控制台、反调试 | 工具给**线索**（壳类型/运行时/加密常量/成败文案/输入通道）和**下一步该敲什么**，判断由你做 |

分档不是免责声明，是这个工具真实的能力边界。上一版把两档混着叫「一条龙」，**这是过度承诺，已经改掉**。

## 实测基准线

改进只看这三个数（细节与出处见 [BENCHMARK.md](BENCHMARK.md)）：

| 场景 | 结果 | 说明 |
|---|---|---|
| 自制投稿包（12 套多层/字符表类） | **真解 2/12** | 另 3/12 稳定捞到出题人埋的诱饵 flag（按纪律只标"待验证"） |
| 吾爱 2012 CrackMe 批量（33 个 exe） | **18/33** 找到候选校验入口 | 是"定位"成功率，不是"解出"成功率 |
| 吾爱 2026 春节（9 道） | **2 解出 / 1 脱壳成功 / 1 跑起来** | 之六、之十解出；之七 UPX 脱壳 + 认出 AES-128；之二 C++ 控制台能跑 |

论坛实题中**完整解出并自证**的 3 道：看雪 2019q2 第六题、《吾爱 2021 春节》之四、吾爱 2012CM（ying5567890）。
每道答案都用"程序自己认了"或"按原算法重算对得上"验证过。

## 它擅长什么

* **多层**：hex → 倒序 → zlib、base64 → AES-ECB、rot13 → XOR → gzip……链式搜索自己发现层数；
* **字符表被打乱**：靠 padding 位置、尾部比特、解码长度整除性还原，不靠枚举；
* **算法被改过**：AES S 盒改几个字节、DES 位选取表反转、TEA delta 换掉——签名扫描认得出**近似命中**并指出改了哪；
* **密钥在程序里**：`--verify-binary` 用程序内密文反查候选密钥，答"哪个密钥是对的"而不是"哪个像"；
* **加壳**：`unpack` 在模拟器里跑壳的 stub 脱 UPX（改过的 UPX 也行）；样本被杀软锁住时可用 `-` 从管道读；
* **让程序自己判对错**：`emu --run` / `gui --discover` 用 Unicorn + 300 多个 Win32 API 桩 + 假系统 DLL/PEB→Ldr 跑起来，只转述程序自己的成败文案。

## 它不做什么

| 不做 | 为什么 / 该用什么 |
|---|---|
| .NET（IL） | 不解析 IL，工具会直接说"去用 dnSpy / ILSpy" |
| Android APK / Web / pwn | 不在射程，只说该用 jadx / 浏览器 / pwndbg |
| 非 UPX 的壳 | 只报证据（壳名 + 置信度），不硬脱；建议 x64dbg + Scylla |
| GUI 消息循环 | 不模拟点按钮；走"直调校验函数"路线，只覆盖文案静态可达的那一类 |
| 依赖完整加载器环境的自写壳 | 加 API 桩推不动，工具会如实报"卡在哪"，不假装在推进 |

## 安装

```bash
pip install -r requirements.txt
```

只用标准库也能跑编码/古典密码那一半；`unicorn`/`capstone` 决定动态分析能不能用，`numpy`/`Pillow` 决定扫描与隐写。Python 3.8+（实测 3.13）。

## 5 分钟上手

**先指路**（新用户从这里开始，它告诉你这题值不值得花时间）：

```bash
python plainseek.py triage ./challenge.exe
```

输出长这样：身份（PE32 控制台）→ 外壳（无 / UPX / ?）→ 运行时（MSVC C++ / .NET / Go…）→ 输入通道（stdin / GUI）
→ 成败文案 → 加密常量 → **结论：A 档还是 B 档** → **下一步按优先级排好的命令**。

**A 档：直接跑**

```bash
python plainseek.py auto ./题目目录      # 侦察 + 链式解密 + 判定
python plainseek.py xor ./blob.bin       # 盲解 XOR
python plainseek.py basedecode ./str.txt # 递归 Base 解码
```

**B 档：按 triage 给的路线走**

```bash
python plainseek.py unpack cm.exe                      # UPX 先脱壳
python plainseek.py sig cm.unpacked.bin                # 看命中什么算法
python plainseek.py emu cm.exe --run --stdin "候选"     # 让程序自己判
python plainseek.py emu cm.exe --anchor "Correct" --break 0x401234
```

## 命令一览

| 组 | 命令 |
|---|---|
| 流水线 | `scan` `auto` `solve` `chain` `triage` |
| 编码 / 古典 | `basedecode` `xor` `crack` `identify` `transforms` |
| 结构 / 密码 | `table` `pair` `verify` `formula` `oracle` |
| 文件 / 隐写 | `carve` `stego` `fragments` `pyc` `bulk` |
| 二进制 | `sig` `unpack` `crackme` `emu` `gui` |
| 自检 | `selftest`（61 项，含负样本） |

逐条用法见 [docs/commands.md](docs/commands.md)。

## 证据分级（这个工具最该被看的部分）

| 级 | 含义 |
|---|---|
| 0 | 文本猜测（看着像文本） |
| 1 | 形状 / 格式合法（能解析成 JSON/PNG…） |
| 2 | 启发式（统计上像 flag） |
| 3 | 往返一致（重新加密能还原原密文） |
| 4 | 判定器认可（格式验证器通过） |
| 5 | 模拟执行（程序自己的代码接受了它） |
| 6 | 二进制自证（程序内密文确认了密钥） |

**只到 0–2 级的候选一律标"未验证"，不会拿去当答案。** 逆向题里"看起来完整但其实从不参与比较"的诱饵 flag 太常见了。

## 三条原则（都来自踩坑）

1. **证据门控**：候选必须过独立验证才算数；死路就留在死路，不往上爬；
2. **宁可少报**：多字节异或字符串解密默认关闭、打包器签名保守——噪声里的"命中"比没命中更害人；
3. **把坑写进注释**：TEB 假页、stdcall 元数、指令长度、跳进指令中间的花指令、`enter` 在翻译块里报怪错……
   这条代码库里每处非显然的绕法都带着"它为什么会这样"。

## 改过名

原名 `autocrypt`。改名原因：**它不是一个"自动的 crypt"**——夸大能力会让人第一次用就撞在失败率上。
现在叫 `plainseek`（寻明文），A/B 分档写进首页，基准线摆出来。

* 新入口：`python plainseek.py ...` / `plainseek.bat`
* 老入口仍可用：`python autocrypt.py ...`、`一条龙.bat`（都会转发并提示改名）

## 状态与局限

* 自检 **61/61** 通过（含负样本：喂错误输入必须被判错）。
  CI 每次提交跑 **Windows 3.10/3.13 + Linux 3.10/3.12**，两个平台都是门槛（首轮 CI 已全绿）；
* Windows 是主战场，Linux 上跑的是 ELF / 纯算法那部分；
* 模拟执行强于静态猜测、弱于真机；输出里的证据等级始终标着这一点；
* C++ 控制台题需要 CRT 初始化（`_initterm` / `__p__acmdln` / `realloc` / `getc` 已实现），
  但**起真线程或依赖真实时序**的程序仍可能提前退出，工具会报告在哪一步。

## 目录

```
plainseek.py        入口（autocrypt.py 为兼容壳）
plainseek.bat       Windows 双击启动（一条龙.bat 为兼容壳）
pseek/              实现
  triage.py         指路：侦察 + 排序好的下一步
  unpack.py         UPX 内存脱壳
  emu.py winapi.py fakedll.py   Unicorn 模拟执行 + Win32 桩 + 假系统 DLL
  oracles.py alphabets.py ciphers.py transforms.py recover.py   A 档主体
  board.py          证据门控黑板
  sigscan.py crackme.py gui.py stego.py pyc.py formula.py fragments.py verify.py
tests/              开发测试（私有样本走 AUTOCRYPT_DATA，缺样本会打印一行原因后跳过）
docs/commands.md    逐命令详解
.github/workflows/  CI：Windows + Linux 双门槛 + 入口兼容检查
```

## 许可

MIT。
