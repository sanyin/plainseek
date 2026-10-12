# autocrypt —— CTF 一条龙解密工具

> 目标：**给一个目录，尽量自动出明文**。不写死"某题某密钥"，而是
> 让工具自己去认字符表、自己去试加密参数、自己去叠层、自己去判断解没解对。

实测（详见下文「实测结果」）：

| 场景 | 结果 |
|---|---|
| 真实题 `distorted`（被打乱的 Base64 字符表 + 改造 RC4 + 伪造 UPX 壳） | ✅ 自动枚举出掩码常量 `p1=0x72 p2=0x37`、自动还原整张字符表、3 个文件逐字节还原，flag 命中 |
| 真实题 `100w`（易语言 + MD5 派生密钥 + DES 位选取表反转） | ✅ **全自动**：`--verify-binary` 用程序内密文反查出输入 `732425`（45.6 秒），flag 命中 |
| 合成题：自定义字符表 + RC4（无明文对照） | ✅ 仅靠文件结构约束还原 |
| 合成题：hex → 整串倒序 → zlib（三层叠加） | ✅ 链式搜索自动发现三层 |
| 合成题：Base64 → AES-ECB / Base64 → 长度前缀 → DES | ✅ 自动命中 |
| 借鉴同类工具补的能力：识别 / XOR 自动分析 / 递归 Base / 内嵌雕刻 / 古典破解 / crib | ✅ 见第三节 |
| 密钥确认（程序内密文自证 / 加密反查 / 模拟执行脚本） | ✅ 见第四节第 12 条 |
| 跨版本 `.pyc` 读取（3.0–3.13）+ 逐字节线性公式反推 | ✅ 见第四节第 14/15 条 |
| 隐写：BMP 位平面枚举 + WAV 频谱点阵/DTMF 解码 | ✅ 见第四节第 16 条 |
| 模拟执行取证（Unicorn）：跑函数、内存改写差分、自动认出运行时置换表 | ✅ 见第四节第 17 条 |
| `02_题目投稿包` 12 套逆向题实测（不看 writeup） | 真解 **2/12**（R01 片段拼接、R10 pyc 常量公式）；另 **3/12** 稳定捞到出题人埋的诱饵 flag（R02/R08/R09），可用来快速判断"这题有 bait"；其余 7 题需要模拟执行/解包/隐写能力，见 `_投稿测试/_测试报告.md` |
| 内置自检 | ✅ 30/30 通过 |

---

## 一、为什么它能"通用"

普通脚本是"这题用 A 密钥解 B 算法"；这个工具把解题拆成四个可复用的部件：

```
                    ┌──────────────────────────────────────────┐
   输入数据  ──▶    │ 探测层 oracles：这串字节像不像某种已知文件？ │
                    │  PNG 块 CRC / ZIP 条目 CRC / JPEG 段结构   │
                    │  / gzip CRC / UTF-8 / flag 正则 …          │
                    └───────────────┬──────────────────────────┘
                                    │ 打分（0~1，≥0.85 视为"解对了"）
                    ┌───────────────▼──────────────────────────┐
                    │ 变换层 transforms：编码/压缩/位运算/加密     │
                    │  每个变换自带 detect() 与参数候选枚举        │
                    └───────────────┬──────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
  密码表还原                  参数化加密家族                链式搜索
  alphabets.py                ciphers.py                  search.py
  （表被改了也能解）           （常量未知就枚举）            （几层都能叠）
```

### 1. "密码表改了也能跑" —— `alphabets.py`

出题人最爱干的事：把标准 Base64 字符表随机打乱。这时标准库解出来是垃圾，而且
**不会报错**。本工具的做法是把未知字符当成变量，用"解出来的字节必须像某个文件"
来约束求解：

* **已知明文对照**：目录里同时有 `readme.txt` 和 `readme.txt.enc` 时，
  直接反推出整张表的大部分映射；
* **结构约束**：剩下不知道的字符，用文件头 magic、PNG 块 CRC、JPEG 段结构
  （含与标准 JPEG Huffman 表的比对）、`flag{` 前缀等当约束，做增量回溯搜索；
* **参考文件注入**：JPEG 的段结构（marker、长度字段、DHT 标准表）直接当作
  "已知明文"喂给求解器——注意量化表（DQT）随 quality 变化、图像宽高随尺寸变化，
  这些字段会被自动跳过，所以参考图不必和原图一模一样；
* **两遍回退**：先按"标准 Huffman 表"严格比对，一个解都找不到时自动退回纯结构校验。

### 2. "两三个加密叠在一起也能跑" —— `search.py`

把数据当搜索状态，每层挑"看起来该用"的变换去试，用探测层打分，保留最有希望的
一批继续往下解（beam search）。两条关键设计：

* **每类变换至少留一条分支**：否则 AES/DES 这种"解开一层后中间结果是高熵密文、
  评分很低"的正确路径会在第一层就被丢掉；
* **命中"容器"不停手**：解出 zlib/zip/png 只是"剥了一层壳"，会继续往下解到
  文本/flag 才收工。

### 3. "常量被改了也能跑" —— `ciphers.py` + `recover.py`

改造版 RC4 的掩码公式、异或常量、KSA 变种都做成了参数。未知常量用
**字符集约束**枚举：解密结果必须全部落在某个字符集里（例如"必须是 Base64 字符"），
这个条件足以把 65536 种常量组合筛到唯一解。

两个加速点：
* PRGA 的状态演化与掩码公式无关 → 每个密钥只算一次轨迹，之后纯查表；
* 带异或常量的掩码可以在第 0 步就把候选从 256 个缩到"字符集大小"个。

### 4. 判断"解对了没有" —— `oracles.py`

这是自动化的地基。凡是**只看文件头**就给高分的探测都是自欺欺人
（用文件头反推密钥必然生成一个"假 PNG"），所以本工具的探测都做真实校验：
PNG 逐块 CRC32、ZIP 条目 CRC、JPEG 段结构与 Huffman 表合法性、gzip CRC+ISIZE、
7z/RAR 头 CRC、UTF-8 合法性、flag 正则……只看 magic 的探测一律压在成功线以下。

---

## 二、安装与依赖

* Python 3.8+（实测 3.13）
* 必需：无（只用标准库也能跑基础功能）
* 建议：
  * `pycryptodome` —— DES / 3DES / AES / ChaCha20 / Salsa20
  * `Pillow` —— 生成标准 JPEG 参考文件（用于比对 Huffman 表；没有它时跳过严格比对）
  * `capstone` / `unicorn` —— 需要反汇编/模拟执行机器码时另配

```bash
pip install pycryptodome pillow
```

目录结构：

```
autocrypt/
├── autocrypt.py          入口
├── 一条龙.bat            Windows 双击启动
├── README.md
└── dkit/
    ├── oracles.py        格式验证器（判断解没解对）
    ├── alphabets.py      字符表识别与还原
    ├── ciphers.py        参数化加密算法
    ├── transforms.py     变换注册表
    ├── recover.py        已知明文 / 密钥恢复 / 常量枚举
    ├── search.py         链式搜索引擎
    ├── pipeline.py       一条龙编排
    ├── cli.py            命令行
    └── selftest.py       自检
```

---

## 三、借鉴了哪些同类工具（以及具体借鉴了什么）

功能不是闭门造车，下面这些 GitHub 项目/文档的设计被吸收进来了：

| 来源 | 借鉴的点 | 在本工具里的落地 |
|---|---|---|
| [Ciphey / ciphey](https://github.com/bee-san/Ciphey) | 自然语言检查器（natural-language checker）、多层解码、时间预算、**按"哪个译码器真的解出东西"动态调优先级** | `langscore.py`（词表 + 自适应 n-gram 打分）、`search.Engine` 的译码器统计排序、`--timeout/--depth/--beam` |
| [CyberChef Magic](https://github.com/gchq/CyberChef/blob/master/src/core/operations/Magic.mjs) | **crib（已知明文/正则）过滤结果**、递归深度、Intensive 模式、每个中间结果都报熵与"还有哪些操作可能匹配" | `--crib` / `--crib-regex`（设了就只认命中的结果）、`--deep`、`scan` 报告里的熵与字符表猜测 |
| [pyWhat](https://github.com/bee-san/pyWhat) / [lemmeknow](https://github.com/swanandx/lemmeknow) | 正则库识别"这是什么"、标签过滤、递归在文本里找线索 | `identify.py` + `identify` 子命令（`--include/--exclude/--tags/--json`） |
| [Name-That-Hash](https://github.com/HashPals/Name-That-Hash) | 哈希识别**带 hashcat/john 模式号**、"只认真哈希不把 base64 当哈希"、流行度排序 | `identify.py` 里的哈希模式表（含 `hashcat -m` 提示）与 `/dev/null` 式"缺省不报"策略 |
| [xortool](https://github.com/xtaran/xortool) | **等字符计数猜密钥长度**、**最高频字符反推密钥**、`-c/-m/-l` 语义、"长度可能是 n 的倍数"这一坑 | `xoranalysis.py` + `xor` 子命令 + 引擎里的 `xormulti` 变换 |
| [hexforge](https://github.com/arvdch/hexforge) | **短 magic 误报的两层解法**（结构校验器 + 压缩区抑制）、格式感知的结尾定位、递归雕刻去重、单字节 XOR 混淆探测 | `carve.py` + `carve` 子命令（PNG/JPEG/ZIP/GZIP/PDF/BMP/7z/TAR/SQLite 结尾定位，IDAT/GZIP/ZIP 压缩区抑制） |
| [basecrack](https://github.com/mufeedvh/basecrack) / [BaseCrack-W](https://github.com/ha0-hh/basecrack-W) | 支持一大票 base 变体 + **magic 模式递归多层解码**及护栏 | `baseN.py`（base36/45/58/62/85/z85/91/32hex/32z/crockford…）+ `basedecode` 子命令 + `basemagic` 变换 |
| quipqiup / dcode 那一类古典密码服务 | 用 n-gram 统计 + 爬山法破单表替换；Kasiski/IC 定维吉尼亚密钥长度 | `crack.py` + `crack` 子命令（凯撒/仿射/维吉尼亚/单表替换/栅栏/列置换） |

**没有直接搬运代码**：都是各自的语言与实现方式（Rust/Python/JS），这里按同一思路重写并适配本工具的变换/评分框架；数据方面只用了一份公开的
[Google 10k 英文词表](https://github.com/first20hours/google-10000-english)（取前 3000 词）作为语言模型语料，
如果你把一份 quadgram 统计文件放到 `dkit/data/english_quadgrams.txt`，打分会自动切换成 quadgram。

---

## 四、用法

### 0) 最省事的用法：把文件/文件夹/zip 拖到 `一条龙.bat`

拖进去就行，它会先侦察再一条龙解密，结果写到 `autocrypt\recovered\`。
等价命令：

```bash
python autocrypt.py auto <文件|文件夹|zip> -o recovered --timeout 60
```

> **启动器踩过的两个 cmd 坑**（都已修掉，写下来免得再犯）：
>
> 1. **批处理里不能出现非 ASCII 字符 + `chcp 65001`**。切换代码页后 cmd 会按
>    字节偏移重读批处理文件，把后面每一行的开头几个字符吃掉——连 `pause` 都会被
>    截没，于是窗口"一闪就退"。现在 `.bat` 保持**纯 ASCII + CRLF**，中文全部由
>    Python 打印（`-X utf8` 配合 `chcp 65001`）。
> 2. **路径里的 `)` 会提前结束 `if ... ( ... )` 块**。`"C:\x (1)"` 这种路径会让
>    整段 `scan`/`solve` 被静默跳过（只剩 pause），看起来像"没反应"。现在脚本里
>    **不用括号块**，全部是 `if ... goto` 单行形式。
>
> 另外还做了：Python 解释器多路查找（`python` → `py -3` → conda 环境 → Anaconda）、
> 尾反斜杠与转义引号导致的"参数被吞"修复（`clean_target()`）、
> 路径不存在时给出明确提示、失败时列出可尝试的参数、任何分支都会 `pause` 住。

### 0.5) 解不出来？留在窗口里继续试（交互菜单）

一次没解出来很正常——逆向题大多还需要一点额外信息。启动器默认带 `--menu`，
跑完不出结果时会**停在同一个窗口等你补充信息**，不用重新拖一次：

```
 1  输入密钥重试（也支持 hex: 前缀，如 hex:637a524037000000）
 2  输入已知明文片段（crib，如 flag{ / XJUSEC{）后重试
 3  加大预算重试（timeout×3 + --deep）
 4  指定密钥派生脚本（.py，定义 keys() 生成器）
 5  密钥确认：用程序内密文反查（输入 程序文件 与 密文偏移）
 6  换个工具试：identify / fragments / carve / crack / xor / basedecode
 7  打开输出目录
 8  换一个目标路径
 q  退出
```

实测：无密钥失败 → 按 `1` 输入密钥 → 自动重试 → 出 flag 并提示"✔ 这次有结果了"，
接着还能继续换参数试，直到按 `q` 退出。手动跑也一样：

```bash
python autocrypt.py auto <目标> --menu            # 强制开菜单
python autocrypt.py auto <目标> --no-menu         # 关掉菜单（脚本里用）
```

> 小提示：窗口停在 `Press any key to continue` 是**正常**的（`pause`），
> 按任意键才会关闭；以前那种"一闪就退"是批处理被 cmd 解析错乱导致的，已修。

### 1) 先自检（确认环境正常）

```bash
python autocrypt.py selftest
```

### 1) 侦察：这堆文件是什么？

```bash
python autocrypt.py scan ./attachment
```

输出每个文件的大小、熵、可打印率、长度是否对齐、疑似格式、字符表猜测、
是否找到"明文/密文"配对。

### 2) 一条龙解密

```bash
# 最基本：给目录，自动解
python autocrypt.py solve ./attachment -o ./recovered

# 密钥藏在程序里、字符串被拆开过 → 深度模式（会生成密钥变体，较慢）
python autocrypt.py solve ./attachment -o ./recovered --deep --timeout 180

# 已经知道密钥（例如密钥由输入经 MD5 派生，程序里搜不到）
python autocrypt.py solve ./attachment -o ./recovered --key "czR@7"

# 密钥派生规则很特别 → 写 5 行脚本
python autocrypt.py solve ./attachment --key-script ./mykeys.py
```

`mykeys.py` 示例（枚举 6 位数字输入并复刻程序的派生逻辑）：

```python
import hashlib
def keys(ctx):
    for i in range(1000000):
        h = hashlib.md5(f"{i:06d}".encode()).hexdigest()
        # ……按题目逻辑算成真实密钥……
        yield derived
```

常用参数：

| 参数 | 说明 |
|---|---|
| `-o/--out` | 输出目录（同时写出 `解密报告.md`） |
| `--depth` | 最多叠加几层（默认 4） |
| `--beam` | 每层保留多少候选（默认 12） |
| `--timeout` | 每个阶段的搜索时间上限（秒） |
| `--deep` | 深度暴力：更多参数组合、更多密钥变体 |
| `--key` | 手动给密钥，可重复 |
| `--keys-file` | 密钥字典（每行一个） |
| `--keys-from` | 从这个文件里抓密钥字符串（默认会自动抓目录里的 ELF/PE） |
| `--key-script` | 自定义密钥派生脚本 |
| `--fmt` | 强制目标格式（jpeg/png/zip/txt…），用于结构约束 |
| `--reference` | 参考文件（默认用 Pillow 生成标准 JPEG 比对 Huffman 表） |
| `--table` | 直接给出 64 字符的字符表 |
| `--crib` / `--crib-regex` | 已知明文（或正则）：设了就**只认命中它的结果**，等价于你直接告诉工具"解对了" |
| `--no-flag-prefix` | 不要假设 `flag{` 前缀 |

### 3) 分析一对明文/密文

```bash
python autocrypt.py pair plain.txt plain.txt.enc
```

输出：长度关系、`明文⊕密文` 的性质（单字节常量 / 短周期重复 / 伪随机密钥流）、
以及能否直接反推出被打乱的字符表。

### 4) 手动指定配方（用于复核、复用、验证）

```bash
python autocrypt.py chain "rev,hex,xor:0x5a" secret.bin          # 配方
python autocrypt.py chain "rc4v:key=@0,mask=1,p1=0x72,p2=0x37" f.enc --key "CCB_M4gic_K3y_2026"
python autocrypt.py chain "classical" garbled.txt                 # 古典密码自动破解这一层
python autocrypt.py chain --list                                  # 列出所有可用变换
```

配方语法：逗号分隔的多步，`名字` 或 `名字:参数=值`；`@i` 引用第 i 个 `--key`。

### 5) 单独还原字符表 / 打分

```bash
python autocrypt.py table logo.jpg.enc --fmt jpeg --pair-plain readme.txt --pair-cipher readme.txt.enc
python autocrypt.py oracle flag.txt.enc
```

### 6) 识别"这是什么"（借鉴 pyWhat / Name-That-Hash）

```bash
python autocrypt.py identify "AKIAIOSFODNN7EXAMPLE"
python autocrypt.py identify suspicious.bin --json
python autocrypt.py identify "5f4dcc3b5aa765d61d8327deb882cf99" --include 哈希
python autocrypt.py identify --tags          # 看有哪些标签
```

会告诉你：哈希类型（含 `hashcat -m` 模式号）、JWT、信用卡（Luhn 校验通过才报）、
云凭证/AK、私钥、加密货币地址、编码层……并且**能校验的都校验**，宁可不报也不误报。

### 7) 多字节 XOR 自动分析（借鉴 xortool）

```bash
python autocrypt.py xor secret.bin                  # 自动猜长度 + 猜密钥
python autocrypt.py xor secret.bin -c 0x00 -m 64    # 二进制文件常用 0x00，最长密钥 64
python autocrypt.py xor secret.bin --hex -o out.bin # 输入是 hex 文本
```

### 8) 递归多层 Base 解码（借鉴 basecrack 的 magic 模式）

```bash
python autocrypt.py basedecode "TUlYWldDWlozTlpTWEc1REY="
python autocrypt.py basedecode nested.txt -d 8 --out plain.txt
python autocrypt.py basedecode x.txt --allow base64,base32,base45
```

支持 base16/32/32hex/z-base-32/crockford/36/45/58(btc,flickr,ripple)/62/64/85/ascii85/z85/91。

### 9) 内嵌文件扫描与雕刻（借鉴 hexforge）

```bash
python autocrypt.py carve suspicious.png --extract
python autocrypt.py carve firmware.bin --depth 2 --json report.json
python autocrypt.py carve --list-sigs
```

会做：格式感知的结尾定位、结构校验器、**压缩区（PNG IDAT / GZIP / ZIP）内的短 magic 自动抑制**、
递归雕刻去重、以及"文件头被单字节 XOR 混淆"的密钥反推。

### 10) 古典密码自动破解（借鉴 quipqiup / dcode 那一类）

```bash
python autocrypt.py crack garbled.txt                 # 自动判断类型
python autocrypt.py crack garbled.txt --type vigenere
python autocrypt.py crack garbled.txt --type sub --deep
```

支持凯撒、仿射、维吉尼亚（重合指数定长 + 逐列卡方 + 逐列微调）、
单表替换（爬山法 + 随机重启）、栅栏、列置换、单字节 XOR。

### 11) 批量处理一列字符串（借鉴 pyWhat 的递归扫描思路）

```bash
python autocrypt.py bulk strings.txt --out decoded.txt
```

对每行做"识别 + 递归解码"，适合"一堆编码串里找 flag"。

### 12) 密钥确认：让**程序里的密文**当标准答案（逆向题专用）

逆向题常见套路：密钥由输入派生，密文直接躺在程序里。这种情况下不需要人眼判断，
也不需要已知明文——用下面三种方式之一，工具能把密钥空间砍到一个点：

```bash
# 方式 B（最常用）：已知密文在程序里的位置，逐个候选密钥解密 + 结构判据自证
python autocrypt.py verify 100w.exe \
    --ciphertext-offset 0x6EE02 --ciphertext-length 48 \
    --keyspace digits --length 6 \
    --key-script examples/keyderive_template.py \
    --cipher --cipher des --key-transform bitrev
# → 命中：输入='732425' 密钥=b'czR@7\x00\x00\x00' 密码=des(bitrev) → CTF{...}

# 方式 A：程序里同时有明文常量和它的密文（crackme 常见）
python autocrypt.py verify crackme.exe --plain 'CTF{' --try-lenprefix --cipher des,aes

# 方式 C：自己写模拟执行脚本（需要 pip install unicorn），工具负责枚举与判定
python autocrypt.py verify app.exe --keyspace digits --length 6 \
    --key-script my_derive.py --emulate-script examples/emulate_template.py
```

三种确认方式的原理：

| 方式 | 前提 | 判据 |
|---|---|---|
| A 加密反查 | 程序里存着明文常量，或你知道明文前缀（一个分组就够） | `encrypt(明文) 出现在程序里` |
| B 解密验证 | 能从逆向里定位到密文（偏移或十六进制） | 解出来满足 `长度前缀+flag` / flag 正则 / 文本 / 文件格式 |
| C 模拟执行 | 需要跑程序自己的密钥构造或解密机器码 | 你脚本返回的字节通过结构判据 |

配套的 `--keyspace`（digits/hex/lower/alnum/range/words）+ `--derive`
（raw/md5/sha1/sha256/md5_hex/…/pad8）能直接枚举"6 位数字"这类输入空间；
派生逻辑如果很怪，用 `--key-script` 照抄成十几行（模板见 `examples/keyderive_template.py`）。

**关于误报**：确认阈值默认 **0.85**，故意把弱判据（"疑似 flag" 0.8、只看 magic 的格式判定）
排除在"确认"之外。原因很实际——百万级枚举下，任何假阳性率高于百万分之一的判据都必然误报；
实测中就抓到过一次：某错误密钥解出的乱码里恰好出现 `xxx{...}`，被宽松 flag 正则判成 0.8 而误确认。
所以"确认"只认强判据：`长度前缀+flag`、严格 flag 正则、文件格式 CRC/段结构、语言模型判定为文本。

**速度参考**：100 万候选 × 1 种密码 × 1 种密钥变换 ≈ 每 10 万候选 3 秒（实测
1,405,115 个候选用了 45.6 秒）。

也可以直接并进一条龙：

```bash
python autocrypt.py solve ./题目目录 --verify-binary ./题目目录/app.exe \
    --ciphertext-offset 0x6EE02 --ciphertext-length 48 \
    --key-script examples/keyderive_template.py --verify-cipher des --verify-key-transform bitrev
# 会先把密钥确认出来，再拿它去解目录里的其它文件
```

### 13) flag 片段收集与拼接（flag 被拆成几段时用）

逆向题常把 flag 拆成几段，分别用明文 / hex / base64 藏在程序里，顺序还可能是乱的：

```bash
python autocrypt.py fragments ./R01_hello                    # 自动找含 { 的锚点并拼接
python autocrypt.py fragments ./app --crib XJUSEC{ --json
```

它做三件事：**收集**（明文片段、hex/base64/base32 解码、反转）→ **拼接**（以含 `{`
的片段为起点，支持重叠拼接，中间状态必须保持"像 flag"）→ **排序**（用语言模型给
拼出来的正文打分，噪声片段拼出的串会排在后面）。

实测（投稿包 R01）：自动拼出
`XJUSEC{the_first_step_is_the_hardest}`，三段分别是明文 `XJUSEC{`、
hex `7468655f66697273`（→`the_firs`）、base64 `dF9zdGVwX2lzX3RoZV9oYXJkZXN0fQ==`
（→`t_step_is_the_hardest}`）——与二进制里那句 "split into THREE parts … plaintext,
hex, and base64" 完全对应。

一条龙里这一步是**默认开启的兜底**（链式搜索和古典破解都没结果时才跑），
也可以用 `--no-fragments` 关掉。

> ⚠ 逆向题经常在附件里埋**诱饵 flag**（看着完整、其实是假的）。投稿包实测中
> R02/R08/R09 的诱饵都被工具捡了出来——所以命中后务必用题目环境验证过再提交。

### 14) 跨版本 `.pyc` / marshal 读取（Python 逆向题专用）

Python 逆向题最烦的一步：题目给的是 3.10 的 `.pyc`，本机是 3.13，`marshal.loads()`
直接抛 `bad marshal data`。本工具自带一个跨版本读取器，**只用标准库**就能把
3.0–3.13 的 code object 读出来（常量、名字、局部变量、字节码长度都准确）：

```bash
python autocrypt.py pyc target.pyc                 # 版本 + 结构 + 常量/名字概览
python autocrypt.py pyc target.pyc --dis           # 附带反汇编（3.10 指令表）
python autocrypt.py pyc target.pyc --json out.json # 机器可读
python autocrypt.py pyc target.pyc --solve         # 只做"从常量推 flag"这一步
```

实现上踩过的坑（都写在 `dkit/pyc.py` 注释里）：

* 版本号必须比**元组**而不是字符串——`"3.10" >= "3.8"` 是 `False`（字典序），
  会导致 3.10 的字节码按 3.8 的布局去解析；
* `w_object` 对**任何**类型都会调 `w_ref`，所以 `FLAG_REF`（0x80）会出现在
  整数/字符串/bytes/浮点上，不只是容器；容器要先占坑再回填；
* 3.11+ 去掉了 `nlocals`，代码对象多出 `localsplusnames` / `localspluskinds`
  和 `qualname`、`exceptiontable`，偏移全变。读取器两种布局都支持
  （已用本机 3.13 编译的字节码逐字段比对验证）。

> 反汇编用的是 **3.10 的指令表**；3.11+ 指令编号变过，所以只有常量/名字/字节码
> 长度可信，指令名仅供参考——CLI 会在版本不是 3.10 时自动提示这一点。

### 15) 逐字节线性公式反推（"每个字节一个公式"的题）

有些题不加密，而是**逐字节做一个线性变换**，形如
`目标[i] = ROL((a*明文[i] + b*i + c) & 0xFF, r) ^ k`（R10 就是这种，两个随机
掩码异或出目标）。

```bash
python autocrypt.py formula secret.bin --crib 'XJUSEC{'
python autocrypt.py formula target.pyc --crib 'flag{' --offset 0
python autocrypt.py formula 3f7a2b9c... --crib 'flag{'      # 直接给十六进制串
```

它做的事情：

1. **不枚举 `a`**：用前 3 个已知字节列出同余方程 `a*K1 ≡ RHS (mod 256)`，
   一次 `gcd` 就解出全部候选 `a`（暴力枚举 128 个奇数会慢上千倍：116 秒 → 1.8 秒）；
2. **分阶段扫 `(r, k)`**：先 `r=0,k=0`（最常见），再"只加循环移位 / 只加异或"的十字，
   最后才做 `8×256` 完整叉积；
3. **目标字节可以不是直接给定的**：`--pyc` 模式下会把 code object 里的十六进制常量
   做**两两异或**、再与里面的小整数常量异或，自动派生候选目标字节串
   （R10 的真目标 `A ^ B ^ 90` 就是这么冒出来的）；
4. 判定用"**crib 前缀 + 闭合花括号**"或 oracles 强判据，避免乱码里凑巧出现 `xxx{...}`；
5. **等价参数去重**：同一个明文常常对应多组参数（旁路的整数异或被"吸收"进公式的 `k`，
   或 `c` 与 `k` 恰好互补），因此只报最简的一条，其余在行尾标注
   `（另有 N 组等价参数）`——R10 原本会刷出 5 条一模一样的结果。

`pyc --solve` 已经把 3、4 两步串起来了：读常量 → 猜 crib（`XJUSEC{` 这种）→ 派生
候选目标 → 解公式 → 打印还原出的 flag。实测 R10：由两份 32 字节随机掩码解出
真 flag `XJUSEC{every_byte_tells_a_story}`。

### 16) 隐写：BMP 位平面 + WAV 音频（"图里藏密文、声音里藏钥匙"）

隐写题和加密题的根本区别：**数据不是"加密"的，而是藏在"分辨率/位序/顺序"里**，
链式搜索那套"试算法"完全无效——你没法用 oracle 给一堆错位提取的字节打分。
所以这个命令换了两条路：**枚举结构组合 + 开头连续可打印判据**，以及
**把看不懂的东西画出来给人看**。

```bash
python autocrypt.py stego art.bmp                       # 自动枚举位平面组合
python autocrypt.py stego art.bmp --dump payload.bin \
    --channel g --bit 0 --order row --stride 1          # 导出指定组合的原始位流
python autocrypt.py stego hint.wav --spectrogram spec.png --ascii-art
python autocrypt.py stego hint.wav --dump samples.raw   # 导出采样
```

它处理了这些真实的坑：

| 坑 | 处理方式 |
|---|---|
| BMP 头部**撒谎**（自制工具把 `biHeight` 写成别的值/写反） | 若"宽×高×每像素字节"与像素数据长度矛盾，就**按数据长度反推**宽高，并在报告里明说纠正前后 |
| 行是**自底向上** + 每行 4 字节对齐 + 通道是 **BGR** | 提位前自动翻正行序，按真实 stride 走，通道名用 b/g/r |
| 位序可能是 MSB-first 也可能 LSB-first | 两种都试 |
| 像素顺序可能是逐行、逐列、或**位平面拼接** | 三种都试；`plane` 模式会把 8 个位平面依次拼成一条流 |
| 可能隔像素藏（stride） | 步长 1–4 都试 |
| 判据：真实载荷是 `[明文][随机噪声]`，整体可打印率必然很低 | 只看**开头连续可打印段的长度**，再乘"这段里字节的多样性"——`333333…`（整片常数）会被压到很低分 |
| 密钥被"**画**"成频谱图（Audacity 看频谱能读字） | `--spectrogram` 导出彩色频谱图 PNG；`--ascii-art` 直接把频谱打成**终端点阵**，没图形界面也能读 |

实测（投稿包 R13）：`art.bmp` 是 512×512 24bpp，密文用"**每像素 3 位（B、G、R 依次取）
+ MSB-first + 蛇形扫描 + 开头跳过 64 个像素**"写进去，再用改过的 RC4 加密（密钥流额外
异或 `(29*i)&0xff`）。工具能**逐字节复现出密文**（用 `--dump` 指定这组参数即可，
已与题解脚本产出的参考密文比对一致）；但"还要再解一层 RC4"这件事工具不会替你做，
所以最终明文由 R13 的题解脚本给出。`hint.wav` 里藏着钥匙：**不是 DTMF/FSK，而是把文字
"画"成频谱**——工具能 `--ascii-art` 打成终端点阵、`--spectrogram` 导出彩色频谱图，
真正"认字"（7 个字形的模板匹配 OCR，读出 `XJU2026`）在题解脚本里完成。

> 这一节有两个我自己踩过、值得记下来的坑：
> 1. **频率轴上限写死会改变读出来的字**。第一次渲染时我把上限设成 8000 Hz，字形被截掉
>    一部分，`XJU2026` 被读成了 `XJUSEC`（数字 `2/0/6` 看成 `S/O/8`）。所以 `stego`
>    提供了 `detect_tone_rows()` **自动探测音高网格**，而不是让人猜上限；
> 2. **别把 BMP 的 `biSize` 当成高度**。`biHeight` 在偏移 22，偏移 14 是 `biSize`（固定 40）。
>    我第一次探测时读错偏移，得出了"头部在撒谎（写 512×40）"的错误结论——实际上
>    R13 的头部完全正确。"头部撒谎"这个**能力**仍然保留（`bmp_pixels` 会按像素数据长度
>    反推宽高，自检里有对应用例），但不能拿这道题当例子。

### 17) 模拟执行取证：把"跑一遍才知道的常量"挖出来（`emu`）

有一大类逆向题，答案**不在文件里，而在程序跑起来之后**：

* 解密用的表是运行时用 LCG + Fisher-Yates 生成的（二进制里根本没有这张表）；
* 密码算法的常量被改过（标准 `0x9E3779B9` 之类的 delta 搜不到）；
* 先自修改代码解密出真代码，再执行（不解密就反汇编不到东西）。

`emu` 命令就是为它们准备的。它自己做 ELF 解析（**不依赖 pyelftools**），
再用 Unicorn 把指定函数跑起来，然后告诉你**它改写了哪块内存**：

```bash
python autocrypt.py emu ./R03_xor --call 0x401930          # 跑函数 + 内存改写差分
python autocrypt.py emu ./R03_xor --anchor "[+] Correct!"  # 锚点字符串 → 引用它的代码地址
python autocrypt.py emu ./R03_xor --imm 0x401a60:24        # 该函数里的立即数常量
python autocrypt.py emu ./R03_xor --call 0x401930 --dump 0x4c8320:36 --dump-to out/
```

它做了这些事：

| 能力 | 说明 |
|---|---|
| ELF 自解析 | 程序头/节表/入口/架构；给出 `.bss` 位置提示（运行时生成的表通常在那儿） |
| 锚点 xref | 给一段字符串（`"[+] Correct!"`），找出代码里引用它的地址（64 位 RIP 相对与 32 位绝对地址都支持）——**脚本因此不必硬编码地址**，题目改一版也不会废 |
| 立即数提取 | 用 capstone 按真实指令边界取 `mov/lea/add/cmp` 的立即数，改过常量的密码算法就是靠这个暴露的 |
| 模拟执行 | 按 `PT_LOAD` 铺内存、铺栈、SysV 传参（rdi…r9）、压哨兵返回地址；命中 `syscall`/未映射内存/指令上限**一律停下并说明原因**，绝不静默继续（静默继续会给你一个看似合理实则错误的值） |
| **内存改写差分** | 跑之前快照、跑之后比较，直接报出"这个函数往 0x… 写了 48 字节"。改写的区间里只要存在一段长度 n 且恰好是 `0..n-1` 排列的窗口，就自动标成 **★ 运行时生成的置换表**——洗牌表/S 盒/字符表都是这个特征，不用猜它在哪 |

实测（投稿包 R03，运行时生成的置换表）：

```text
[模拟执行] 0x401930()：
  指令数=785  返回 rax=0x6(6)
  停止原因：函数返回
  [改写内存] 0x4c8320 len=48：14 06 0b 23 1a 1c 08 1b 17 21 1e 12 0f 02 01 16 …
  ★ 运行时生成的置换表 @0x4c8320 n=36：14 06 0b 23 1a 1c 08 1b 17 21 1e 12 0f 02 01 16
    09 1f 15 19 10 05 0a 13 22 00 03 18 11 1d 04 0c 0e 07 20 0d
```

整张表 0.05 秒刨出来，与人工逆向的结论（种子 `0x880b44e71c9a3352`、LCG = MSVC
`state*0x41C64E6D+0x3039`、降序 Fisher-Yates、N=36）逐字节一致；同一命令在 R05 上
一眼就暴露出被改过的轮常量 `0xd5321538`（标准值 `0x9E3779B9` 在二进制里出现 0 次）。

踩过的坑（都写在 `dkit/emu.py` 注释里）：

* **Unicorn 的 `timeout=` 参数会让它在每条指令上读一次时钟**：`timeout=2000000` 比
  `timeout=0` 慢 **60 倍**（实测 15.3 ms/次 vs 0.24 ms/次）。所以本模块用
  `emu_start(..., timeout=0, count=N)` 自己数指令，不要用 timeout；
* 64 位和 32 位的程序头字段顺序**不一样**（64 位是 `type, flags, offset, vaddr…`，
  32 位是 `type, offset, vaddr, …, flags`），照 64 位写去解 32 位会把 flags 当成偏移；
* 节表里 `sh_addr` 是第 4 个字段，别拿 `sh_offset` 当地址；
* Unicorn 在 `PC == until` 时**执行前**就停，钩子不一定触发 → 返回值要靠
  "RIP 是否落在哨兵上 / RSP 是否已回弹"补判断。

### 18) 让 Windows 逆向题"自己判对错"：PE 解析 + 导入表打桩（`emu --run`）

吾爱破解/看雪上的 CrackMe **绝大多数是 Windows PE**，所以 17 节那套 ELF 取证不够用。
现在 `emu` 同时吃 PE 与 ELF，PE 侧做的事情是：

| 环节 | 做法 |
|---|---|
| PE 解析 | 自研（不依赖 pefile）：节表、**COFF 符号表**（MinGW 常保留，白送函数名）、**`.pdata` 异常目录**（x64 每个函数的起止地址，哪怕 strip 了也能回溯函数边界）、导入表、导出表、`.NET`(CLR 头) 识别、长节名 `/N` 还原 |
| 铺内存 | `.text/.data/.rdata…` + **PE 头部**（很多程序会读自己的 MZ/PE 头）+ 栈 + **TEB/PEB** |
| 反调试 | `IsDebuggerPresent` → 0，`CheckRemoteDebuggerPresent` → FALSE，`PEB.BeingDebugged` = 0，时间类 API 返回**固定值**（顺手废掉时间差反调试） |
| 导入表打桩 | 每个 API 的 IAT 槽改写成一段桩地址，命中桩就由宿主实现语义：`strcmp/memcmp/strncmp/strlen/strcpy/memcpy/memset/sprintf/printf/puts/scanf/gets/fgets/ReadFile/WriteFile/malloc/HeapAlloc/VirtualAlloc/GetCommandLineA/GetModuleFileNameA/…`（实测补到 **200+** 个，含临界区、TLS、MFC/Qt 启动链） |
| 找校验函数 | `find_check_functions()`：符号名（`main/check/verify`）→ 字符串引用回溯（x64 靠 `.pdata`）→ 退回 CRT 入口 |
| **抓比较参数** | 每次 `strcmp/memcmp/strncmp` 的**实参都记下来**。CrackMe 的期望值通常就摆在比较参数上——这就是"hook strcmp 拿序列号"的自动化版本 |
| 输出解码 | 程序输出按 `utf-8 → gbk → big5 → latin-1` 依次尝试（**国产 CrackMe 大量输出 GBK 中文**，不解对连"成功/失败"都匹配不上，成败判定会直接失效） |
| 结论判定 | 输出里出现 Correct/Success/恭喜/正确… → `result=True`；Wrong/失败/Nope… → `False`；看不到明确字样 → `None`（让你自己看输出） |

```bash
python autocrypt.py emu 题目.exe --run --stdin "候选flag"     # 让程序自己判对错
python autocrypt.py emu 题目.exe --list-candidates           # 只列校验函数候选
python autocrypt.py emu 题目.exe --call 0x401930             # 直接跑某个函数 + 内存改写差分
```

实测（看雪 CTF 2019q2 第六题《消失的岛屿》，32 位控制台 PE）：

```text
[校验函数候选]  0x401622  符号名 _main
[运行程序] 入口 0x401622（符号名 _main）  停止：函数返回
  ── 程序输出 ──   please enter Serial:Please Try Again
  ── 程序内部比较了什么（CrackMe 的期望值通常就在这儿）──
  | strcmp: 'kanxue{test_flag}'  vs  '!NGV%,$h1f4S3%2P(hkQ94=='
```

看到这条比较，题目就只剩"这是个自定义 base64"一层窗户纸了（题解见
`_论坛题目/题解/看雪2019q2_第六题_LostIslands_solve.py`，最终序列号 `KanXue2019ctf_st`，
脚本回代让程序自己打印 `Success`）。

**32 位 PE 的两个大坑**（都写在代码注释里）：
* **Unicorn 2.x 在 32 位模式下静默忽略 `FS_BASE/GS_BASE` 写入**（id 250/251 是 deprecated
  no-op），而 PE 一开局就 `mov eax, fs:[0]` 读 SEH 链 → 直接 `UC_ERR_MAP`。解法是
  反着利用"FS 基址=0"这个事实：**把 TEB 铺在地址 0**；
* **stdcall 由被调用方清栈，参数个数猜错就会让 ESP 差 4 的倍数**，调用几次后 `ret` 飞进栈里
  （表现为"UC_ERR_MAP 在 0x2f7c"这种莫名其妙的地方）。所以除了维护参数表，还加了
  **从调用点反推参数个数**：扫 `call` 前面连续的 `push`，个数基本就是参数个数；
  一条 `push` 都没有时再认 MSVC 的 `mov [esp+k], val` 传参形式（实测栽在 `SetConsoleTitleA`）。

**执行轨迹驱动的控制流重建**（花指令的克星，`coverage=True`）：

```python
res = emu.run_function(img, entry, coverage=True)
for addr, mnem, ops in emu.trace_disasm(img, res["coverage"]):
    ...
```

线性反汇编从函数头一路顺着解，**永远碰不到"半路跳进来"的字节**——出题人正是靠这点挡住
反汇编器。轨迹反汇编按"真实执行过的地址"分块、从每块的真实首地址解码，于是指令流是对的。
实测在看雪那道自写壳上，线性反汇编从函数头顺扫 149 条都到不了崩溃点 `0x4ced37`，
而轨迹反汇编把那段循环清清楚楚解了出来；再配合**崩溃时的寄存器现场**（`fault_regs`），
一眼就看出"壳读过假 DLL 的末尾了"（`edx=0x71010005`）。

### 19) CrackMe 静态辅助（`crackme`）

GUI 程序（Qt/MFC/Delphi）的校验发生在"点按钮"之后，把窗口消息循环也模拟出来不现实
（Speakeasy 那类专业框架也做不好），所以这类题必须走静态。`crackme` 命令给的就是静态那一条路：

```bash
python autocrypt.py crackme 题目.exe              # 静态：输入点/比较点/成败串/可疑字符串
python autocrypt.py crackme 题目.exe --run --stdin 候选   # 顺手把控制台题跑一遍
```

* **读取输入的调用点**（`GetWindowTextA`/`scanf`/`ReadFile`…）——GUI 题的校验函数就在这些点的调用者附近；
* **比较点**：定位 `strcmp/memcmp/lstrcmp/CompareString` 的调用地址，并**还原实参**，
  能读成字符串的直接显示；
* **成败提示字符串**：扫"Correct/Wrong/成功/失败/恭喜"这类词，快速判断程序会说哪几句话；
* **多编码字符串**：ASCII + **GBK 中文** + **UTF-16LE** 三种都扫（国产题的中文提示是重要线索），
  并且**跳过可执行节**——代码段里的"可打印字节"几乎全是指令编码的巧合
  （实测能刷出满屏 `'VQPV'`、`'t.;t$$t('` 这种噪声），不跳过会把真线索淹掉；
* **运行库噪声过滤**：`runtime error`/`TLOSS`/`GetLastError`/`combobox`/`ime` 这类
  CRT/MFC 内部字符串一律过滤（否则"比较点"列表里全是 MFC 自己的逻辑）。

### 20) 加密常量指纹（含"被改过的常量"）+ 打包器识别（`sig`）

逆向题最常见的套路是**标准算法 + 改常量**：TEA 的 delta 换成别的数、AES 的 S 盒动几个字节、
MD5 的初值被改。人眼很难发现，机器可以——这就是 findcrypt / Detect It Easy 那一类工具的核心。

```bash
python autocrypt.py sig 题目.exe
```

* **常量指纹库**：AES/逆 S 盒、SM4 S 盒、TEA delta、MD5/SHA1/SHA256 初值、CRC32 表、
  Blowfish P 数组、DES 表、标准/URL-safe base64 表、zlib/gzip/zip 头…
* **near-miss 检测**（比 findcrypt 多的一步）：不要求逐字节相等，而是算相似度，
  于是"**被改过几个字节的 AES S 盒**""**被改过一位的 TEA delta**"都能报出来，
  并给出差异位置：

  ```text
  ≈相似度 99%  AES S 盒  @0x1000（差异位置 [10, 100]）
  ≈相似度 97%  TEA delta  @0x1000（差异位置 [0]）
  ```

  短指纹（< 8 字节）**按位**算相似度：TEA delta 改一位后按字节只有 75%（会被 90% 阈值筛掉），
  按位是 97%，正好落在"同一常量被动过"的区间；
* **打包器识别**：节名（UPX0/UPX1、.themida、.vmp0、.aspack、MPRESS1…）+ 入口点字节签名
  （UPX `60 BE`、ASPack `60 E8`、MPRESS `60 E9`…）+ 启发式证据（RWX 节、入口在末节、
  代码段熵 > 7.0、导入表为空、大块 overlay），并按"证据条数"给出高/中/低置信度；
* **熵分析**：逐节算香农熵，> 7.0 基本就是被压缩/加密过的数据。

> 踩过的坑：我一开始把 `55 8b ec 6a ff 68`（`push ebp; mov ebp,esp; push -1; push imm32`）
> 当成"Themida/VMProtect 入口"签名，结果拿一个正常程序一试就误报——那只是**最普通的
> MSVC 函数序言**。教训：**签名要么足够独特，要么就别放**，宁可少报也不能把正常程序吓一跳。
> 自检里专门有一条"普通程序不会被误判成加壳"。

它同时会**自动解密被异或加密的字符串**（FLOSS 那条路子的静态近似版）——国产 CrackMe
几乎都会把提示语异或一遍，在 `.rdata` 里只能看到乱码。这里做两条路，**可靠优先**：

| 路径 | 默认 | 判据 | 实测 |
|---|---|---|---|
| 单字节 XOR 全扫（numpy 向量化） | ✅ 开 | 无控制字符 + 字符多样性（≥6 种）+ 非周期重复 + 首尾重复填充剪掉 + 含常见提示语词（error/success/成功/注册…） | **零假阳性**，合成用例准确解出 |
| 多字节 XOR + 已知词 crib | ❌ 需 `--crib` | 同样判据，但从"字符串起点"用常见词反推密钥 | 能解出，但**假阳性明显更多**，所以做成显式选项并在输出里标注"需人工确认" |

调这几道闸门的过程本身就是教训，写进代码注释了：拆掉任何一道都会立刻刷屏——
异或 `0x20` 只是**翻转 ASCII 大小写**，于是每段普通字符串都会"被解出来"一次；
UTF-16 串异或后会变成"每隔一个字符是空格"的锯齿；常量填充会变成 `AAAA…` 刷屏；
而错误密钥凑出来的"可打印垃圾"（`'suc;es+uc;es…'`）连词表都能蒙过。
**宁可少报也不要让人在噪声里捞针。**

### 21) 证据门控：把"找到 flag"和"确认 flag"分开（借鉴看雪 r0re）

这条是纯"工程约束"，但可能是这一轮最有价值的一条。看雪那篇《r0re 自动逆向分析工具实战记录》
（<https://bbs.kanxue.com/thread-292470.htm>）里最值得抄的不是某个算法，而是**完成门控**：
候选答案先进"待验证"，必须有独立验证证据才能 finalize；死路（`dead_end`）也要留下来，
免得重复走。为什么我特别需要它——投稿包 12 题里有 3 题会主动喂你**诱饵 flag**，
而我自己也抓到过一次真·假阳性（PNG 二进制里凑出 `jc_{8_&vfo9?_uL_}` 还给了 0.95 分）。

所以现在每条结果都带**证据等级**，只有 `oracle` 及以上才算"确认"：

| 等级 | 含义 |
|---|---|
| `binary` | 与程序内密文/已知明文对上（`verify` 的三种模式） |
| `emulate` | **程序自己的校验被模拟执行跑通**（`emu --run --stdin`） |
| `oracle` | 结构判据强通过：CRC 全对、段结构完整、确实是完整文件 |
| `roundtrip` | 解出来的结果重新加密回去 == 原密文（自洽性） |
| `shape` | 只有形状：拼出 `xxx{...}`、命中 crib 前缀——**诱饵和噪声都长这样** |
| `text` | 语言模型觉得像（最弱，只用来排序） |

命令行里直接标出来，报告开头也有一段"哪些能信、哪些只是线索"：

```text
找到的 flag（附证据等级：只有 oracle 及以上才算「确认」）：
  [⚠待验证 shape] XJUSEC{the_first_step_is_the_hardest}   （来自 R01_hello；flag 片段拼接（形状判据，可能是诱饵））
  ⚠ 上面这些**都没有强证据**：逆向题常在附件里埋诱饵 flag（投稿包 3/12 就埋了）。
    提交前请用 `verify`（程序内密文反查）或 `emu --run --stdin 候选`（让程序自己判对错）确认一次。
```

还能**自动升级证据**：`solve --verify-emulate` 会把候选 flag 挨个喂回程序自己跑一遍，
程序说对就升级成 `emulate`（强证据），说错就明确标成"多半是诱饵/假阳性"。

---

## 五、实测结果

### 真实题 `distorted`（被打乱的 Base64 表 + 改造 RC4）

**完全自动，连密钥都不用给**（`--timeout 150`，实测 34.3 秒）：

```bash
python autocrypt.py solve ./_realcase -o ./_realcase_out --timeout 150
```

工具输出（节选）：

```
密钥候选：734 个（按“像密钥”程度排序）
发现 1 组明文/密文配对
  配对 readme.txt ↔ readme.txt.enc：未知
    · 长度不同（150 vs 200），可能含编码层
  尝试识别流加密家族（字符集约束 + 常量枚举，限时枚举密钥候选）…
  RC4 家族：密钥=b'CCB_M4gic_K3y_2026' 掩码公式#1 p1=0x72 p2=0x37（约束：base64 字符集）
已知明文直接推出 64 个字符映射
密码表还原成功（置信度 1.00）
  · logo.jpg.enc: 参考比对通过（段结构与标准 JPEG 一致）
  · flag.txt.enc: FLAG 1.00 (flag{1jn9bdpcemcinm4sob2bmmmjfls2qjdt})
流水线解出 3 个文件
```

要点：
* 密钥**不是**完整存在于二进制里的——程序只把 `CCB_M4gic_K3y_20` 放在只读数据，
  末两位 `26` 由指令临时拼上。工具的密钥变体生成把这段补回来了；
* `p1=0x72`、`p2=0x37`、掩码公式编号、KSA 变种全是**枚举出来的**，没有写死；
* 还原出的字符表 `mBVfrIouxs947KW1YbLS/CM8tUGARHQ+0TEgzp6kNFyDea3j5lPZqdXh2nOciJvw`
  与官方题解逐字节一致；
* 三个还原文件与官方 `recovered/` 的 **SHA256 完全一致**，且都通过"重新加密复核"。

复现日志见 `实测日志/distorted-一条龙-默认模式.log` 与
`实测日志/distorted-一条龙-解密报告.md`。

### 真实题 `100w`（易语言 + MD5 派生密钥 + DES 位选取表反转）

这道题第一次跑是**半自动**（需要人给密钥）；补上"密钥确认"之后变成**全自动**——
工具拿程序里存着的密文当标准答案，反查 6 位输入空间：

```bash
python autocrypt.py solve ./_100w_case --verify-binary ./_100w_case/100w.exe \
    --ciphertext-offset 0x6EE02 --ciphertext-length 48 \
    --key-script examples/keyderive_template.py \
    --verify-cipher des --verify-key-transform bitrev --timeout 150
```

实测输出（45.6 秒，1,405,115 个候选）：

```
  命中：[B 解密验证] 输入='732425' 密钥=b'czR@7\x00\x00\x00' 密码=des(bitrev)
        程序内偏移 0x6ee02 → %   CTF{4ef7836c744a0aaa0ac00dbc885849d3}
  ✅ 密钥确认成功：输入='732425'
  CTF{4ef7836c744a0aaa0ac00dbc885849d3}   （来自 100w.exe）
```

要点：
* 唯一需要人提供的，是**程序里那段派生逻辑**（`examples/keyderive_template.py`，15 行）；
* 判断"哪个输入对"完全由程序内的密文完成——**不需要已知明文，也不需要假设 flag 格式**；
* 同一次确认顺手证明了 DES 位反转变体方向是对的：按密钥缓冲区 `637a524037000000`
  加密已知明文块后，密文**在原始 exe 偏移 454146 处精确命中**，而 `raw` /
  `reverse` / `bitrev_all` 等其它变体都找不到。

### 内置自检

```bash
python autocrypt.py selftest     # 37/37
```

自检覆盖：oracle 判定、密码表还原（有/无明文对照）、三层叠加、AES/DES 变体、
线索识别、多字节 XOR、递归 Base 解码、内嵌雕刻与压缩区抑制、古典密码破解、
密钥确认（加密反查 + 解密验证 + 候选空间枚举）、跨版本 pyc 读取、线性公式反推、
BMP LSB 隐写（含头部撒谎纠正）、WAV DTMF 解码、ELF 解析 + 模拟执行 + 置换表识别
（自检用的 ELF 是脚本现场手写的机器码，不依赖任何外部附件）。

### `02_题目投稿包` 12 套逆向题实测

测试方式：把附件目录直接丢给 `python autocrypt.py auto <目录>`，**不看题目工程文件里的 writeup**，
每文件预算 20–30 秒，判分只看是否出现 `描述.txt` 里的真 flag。完整报告见
`..\_投稿测试\_测试报告.md`。

| 题目 | 结果 | 说明 |
|---|---|---|
| R01_hello | ✅ 真解 | 片段拼接：明文 `XJUSEC{` + hex + base64 三段自动拼出 |
| R10_pyc | ✅ 真解 | 3.10 字节码常量 + 线性公式反推（第 14/15 条） |
| R02_password | ⚠ 诱饵 | 稳定捞出 `XJUSEC{strcmp_1s_n0t_3n0ugh}`（假）；真解要动态调试变形比较 |
| R08_obfuscated | ⚠ 诱饵 | 稳定捞出 `XJUSEC{junk_c0d3_3v3rywh3r3}`（假）；真解要静态还原 SMC |
| R09_vm | ⚠ 诱饵 | 稳定捞出 `XJUSEC{z3_1s_ch34t1ng_r1ght_}`（假）；真解要读自定义 VM |
| R13_stegano | ◐ 半自动 | 工具能**逐字节复现出 BMP 里的密文**（3 位/像素 + MSB-first + 跳前 64 像素，参数已实现并验证），也能把音频频谱打成终端点阵/导出频谱图；剩下"认字（读出钥匙 `XJU2026`）+ 再解一层改过的 RC4"由题解脚本完成 |
| R03/R04/R05/R06/R07/R12 | ❌ | 需要模拟执行（运行时生成表、改过的 TEA 常量、SMC）、解包（PyInstaller）、
时序侧信道、Go 并发流水线 —— 见第六节局限与报告第三节的能力缺口 |

**这批评测的结论**：本工具强在"编码/压缩/换表/参数未知的对称加密/多段拼接"这一类
**数据层面**的关卡；一旦答案要靠**执行程序**才能得到（运行时生成的表、自修改代码、
改过常量的算法、侧信道），就必须上模拟执行。诱饵能被稳定捞出也算有用信息——
至少能立刻判断"这题在 bait 你"。

---

## 五、常见问题

**Q：GUI 题的输入喂不进去（程序从编辑框读输入）怎么办？**
走 `gui` 命令那条路——它的核心不是"模拟窗口消息"，而是**直接把校验函数调起来**：

```bash
python autocrypt.py gui 题目.exe --discover
```

要做成需要三件事（`dkit/gui.py` 都封装了）：① 靠"引用了成功/失败文案"和
"调用了 `GetWindowText*`"两条线索**回溯函数起点**；② 用 `pre_write` 摆好全局输入缓冲、
用 `api_setup` 把 `GetWindowTextA` 换成"返回我们想试的输入"，并把 `GetWindowRect`/
`GetCursorPos` 伪造成"鼠标点在按钮上"（校验前面常有这种命中测试）；
③ 给所有把字符串交给 UI 的 API 插探针，**窄字符与宽字符都读**
（Windows 文案大量是 UTF-16，只读 C 字符串会什么都抓不到）。

**判定的黄金标准**：同一个入口下，**两个不同输入给出不同结论**才算找到真校验。
**已知边界**：成功/失败文案若是运行时从资源加载或拼装的，探针读不到；
校验若在定时器/特定消息里、或进校验前有 `strlen`/控件状态等前置条件，也会失败。
这时退回手工：`--break` / `--trace-cfg` 找到成功与失败分支的地址，再用 `coverage` 看走了哪条。

**Q：提示"未能确定算法"怎么办？**
按顺序试：① `--keys-from 程序文件`（默认已自动抓 ELF/PE 里的字符串）；
② `--key 具体密钥`；③ `--deep`（会生成 `密钥+后缀` 变体，适用于"密钥在代码里
被拼接出来、二进制里只有前半段"的情况）；④ `--key-script` 复刻派生逻辑。

**Q：跑得很慢？**
`--timeout` 控制每个阶段的秒数；`--depth/--beam` 控制搜索规模。
字符集常量枚举是大头（每个密钥约 0.25 秒 × 密钥数），`--deep` 会更慢。

**Q：解出来一堆候选，怎么知道哪个对？**
看评分和报告里的校验行：`CRC 全通过`、`段结构完整`、`重新加密复核通过`
都是强证据；只有 `xxx magic` 的是弱证据（分数被故意压在成功线以下）。

**Q：想加一个自己的算法/编码？**
在 `dkit/transforms.py` 里加一个 `@register("名字", detect=..., params=...)` 函数即可，
搜索引擎会自动带上它。

**Q：图片不是标准 Huffman 表怎么办？**
用 `--reference 自己的.jpg` 提供参考；或者严格比对失败时工具会自动退回纯结构校验
（此时表可能不唯一，报告里会提示置信度）。

---

## 六、已知局限（说清楚比吹牛有用）

1. **密钥必须能"猜到或给到"**。工具会从二进制里抓字符串并生成常见后缀变体，
   像 `distorted` 那样"二进制里只有前半段、末两位由代码拼上"的情况能自动补出来；
   但**派生逻辑本身**（比如"MD5(输入) 再按五行公式算"）工具不会替你逆向，
   要么用 `--key` 直接给，要么写 `--key-script`，要么交给"密钥确认"去验证。
2. **密钥确认需要三者之一**：一个已知明文分组（方式 A）、密文在程序里的位置（方式 B，
   从逆向里拿到偏移即可）、或你自己写的模拟执行脚本（方式 C）。三者都没有时，
   只能退回常规搜索。
3. **非置换型自定义表**（字符重复/缺失）目前按"标准字符通过程"处理，
   极端情况下需要人工指定 `--table`。
4. **JPEG 严格比对依赖"标准 Huffman 表"这一假设**。图换过自定义 Huffman 表时
   严格比对会失败，工具会退回结构校验（更弱的约束），此时建议同时提供
   `--pair-plain` 或让目录里带上一个已知明文文件。
5. **搜索是启发式的**（beam search），不保证全局最优；层数很深（≥5）或
   参数空间很大时需要 `--deep` 与更大 `--timeout`。
6. **语言模型默认没有 quadgram**：只用 Google 10k 词表的前 3000 词训练了
   字母/二元/三元统计，够用来排古典密码的候选，但比真正的 quadgram 统计弱。
   想要更强的打分，把 `english_quadgrams.txt` 放到 `dkit/data/` 就会自动启用。
7. **单表替换的爬山法是随机算法**：短文（<200 字母）可能只解出 80%~95%，
   多跑几次或加 `--deep` 会更好；返回的是"最优候选"而不是保证唯一解。
8. **雕刻会给出"未通过结构校验"的候选**（报告里标 `?`），这些可能是误报；
   短 magic（<6 字节）落在已知压缩区里的一律不报，但压缩区之外的短 magic
   仍需要人看一眼。
9. **多字节 XOR 存在"密钥长度是 n 的倍数"的固有歧义**（xortool 也会提示这点），
   工具按"分数接近时优先短密钥"处理，并把候选按语言分数排序；
   真正的判据还是解出来的明文像不像人话/像不像文件。
10. **识别（identify）是正则 + 校验器**，不是语义理解：它只会告诉你"这东西符合
    MD5 的形状"这类事实，不会替你判断哪个是真 flag。
11. **`.pyc` 反汇编只内置了 3.10 的指令表**：3.11+ 的指令编号不同，反汇编结果
    仅供参照（常量/名字/字节码长度仍然准确），CLI 会主动提示。
12. **公式反推只覆盖"线性 + 索引项 + 循环移位 + 异或"这一族**：非线性项
    （乘法混入字节高位、查表、S 盒）不在模型内；`--pyc` 的候选派生依赖
    "十六进制常量两两异或 + 小整数异或"这一常见形态。
13. **模拟执行只覆盖 x86-64 ELF，且要人工给入口**：`emu` 能跑函数、做内存改写差分、
    自动认出运行时置换表，但"该跑哪个函数、要传什么参数"仍需人（或脚本）判断；
    PE（Windows）与别的架构目前会明确报"不支持"，不会瞎猜。仍未覆盖：解包
    （PyInstaller/UPX）、SMC 脱壳的**自动化**（`emu` 只是提供了工具，脱壳流程要自己串）、
    侧信道、以及自定义打包格式（出题人自己写的 `pack` 工具）。
14. 本工具面向 CTF / 逆向 / 数据恢复等**你有权处理的数据**。
