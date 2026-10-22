改名 plainseek，重写中英文 README（A/B 分档 + 基准线 + 边界），新增 triage 与 CI

## 改名：autocrypt → plainseek

原名暗示"自动的 crypt"，把"全自动"和"半自动"混在一起说，用户第一次用就会撞在失败率上。
新名字 plainseek（寻明文）只承诺"找"，不承诺"一定找到"。

- 入口：plainseek.py / plainseek.bat
- 兼容壳：autocrypt.py、一条龙.bat（转发 + 提示改名）
- Python 包：pseek；dkit/__init__.py 保留三行别名，老脚本 from dkit import x 仍可用
- GitHub 仓库已改名为 sanyin/plainseek（旧地址自动跳转）

## 文档：把承诺和边界写清楚

- README.md / README.en.md 重写：开头就是 A 档（全自动）/ B 档（半自动）分档表，
  然后是三个主指标的基准线、擅长/不做两张表、证据分级、三条原则、改名说明、局限；
- 原 976 行详细用法移到 docs/commands.md（逐命令手册），首页只留能让人 3 分钟判断
  "这工具值不值得用"的内容；
- 新增 BENCHMARK.md：M1 投稿包 2/12、M2 2012 批量 18/33（明确标注是"定位率"不是"解出率"）、
  M3 2026 春节 2 解出/1 脱壳/1 跑起来，并写清每个数字的出处与可信度。

## 新命令 triage：工具原来会干活但不会指路

实测中我手工做过五遍同一套判断（先 sig 还是先 crackme、要不要先脱壳、这题能不能碰）。
triage 把它固化：

- 身份（PE/ELF、位数、子系统）、外壳（UPX 能自脱 / 其它只报证据）、
  运行时（MSVC C++/Go/Rust/.NET/Delphi/AutoIt/Electron/PyInstaller/易语言/Qt…）、
  输入通道（stdin/argv/GUI/文件）、成败文案、加密常量、可疑魔数；
- 输出 结论：A 档还是 B 档，以及按优先级排好的下一步命令（路径自动加引号，可直接复制执行）；
- 只给线索和路线，不造候选明文——造答案是 auto/emu/gui 的事。

## 自检从 52 增到 61（补上一轮留下的测试债）

新增 9 条，都是负样本或关键分支：

- _initterm 必须真的调用静态构造器表里的两个函数（按顺序），且回调后栈已恢复、入口正常返回；
- getc 必须真的从 stdin 读到字节；
- triage 的 A/B 判定在五种关键输入上都正确（含"低置信度可能加壳不该降档"这条——自检里
  那个合成 PE 就曾被误判成 B 档）；
- triage 报告包含档位与下一步、带空格路径必须被引号包住、普通路径不多包。

## CI

.github/workflows/selftest.yml：Windows（3.10/3.13）为门槛，Linux（3.10/3.12）先标"探索性"
（continue-on-error，绿几次再转正式），另有"入口兼容"任务验证 plainseek.py 与 autocrypt.py
两个入口都还能 --help。

## 顺带修的真 bug

- triage._tier 把"低置信度可能加壳"当成真壳，导致正常样本被降成 B 档；
- 自检里合成 PE 的节内偏移被重复减了 0x1000（负索引写到数组尾部）；
- keystone 不接受汇编串里带括号的 ; 注释，会在 _initterm 自检里报 Invalid operand。

验证：自检 61/61；看雪 2019q2 第六题、吾爱 2021 之四、吾爱 2012CM keygen、2026 春节之二
（banner 必须打印出来）四道回归全过。
