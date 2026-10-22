# plainseek

[![selftest](https://github.com/sanyin/plainseek/actions/workflows/selftest.yml/badge.svg)](https://github.com/sanyin/plainseek/actions/workflows/selftest.yml)

**Seek the plaintext.** A decryption pipeline plus an evidence-first reverse-engineering workbench.

> It does **not** promise you a plaintext. It does two things:
> automates what can be automated; turns what cannot into a **ranked, evidence-backed list of leads**.

[中文](README.md) · [Command reference](docs/commands.md) · [Measured baseline](BENCHMARK.md) · [MIT](LICENSE)

---

## Two tiers — stated up front

| Tier | Scope | What to expect |
|---|---|---|
| **A — fully automatic** | stacked encodings, scrambled alphabets, classical ciphers, structurally verifiable crypto (AES/DES/RC4…), flag-fragment stitching, `.pyc` constant recovery | one command, a plaintext plus an evidence level; **it usually delivers** |
| **B — semi-automatic** | native RE: packers, custom VMs, GUI targets, C++ console, anti-debug | the tool gives **leads** (packer, runtime, crypto constants, verdict strings, input channel) and **the next command to run**; you make the call |

The split is not a disclaimer — it is the tool's real boundary. The previous release lumped both tiers
together under "one-stop"; **that was overselling, and it has been removed**.

## Measured baseline

Progress is judged on these three numbers (provenance in [BENCHMARK.md](BENCHMARK.md)):

| Corpus | Result | Note |
|---|---|---|
| Self-made submission pack (12 layered/table challenges) | **2/12 truly solved** | another 3/12 reliably surface the author's *decoy* flags — reported as unverified |
| 52pojie 2012 CrackMe batch (33 exes) | **18/33** candidate check routines located | that is *location*, not *solution* |
| 52pojie 2026 Spring Festival (9 challenges) | **2 solved / 1 unpacked / 1 running** | solved: LÖVE game, MCP server; UPX+AES cracked open; a C++ console target now runs |

Forum challenges **fully solved and self-verified**: KanXue 2019q2 #6, 52pojie Spring Festival 2021 #4,
52pojie 2012CM (ying5567890). Every answer was confirmed by *the program accepting it* or by
*recomputing the original algorithm*.

## What it is good at

* **Layers** — hex → reverse → zlib, base64 → AES-ECB, rot13 → XOR → gzip: the chain search discovers the depth itself.
* **Scrambled alphabets** — recovered from structural constraints (padding position, trailing bits, decoded-length divisibility), not by enumeration.
* **Modified algorithms** — an AES S-box with a few bytes changed, reversed DES selection tables, a replaced TEA delta: the signature scanner reports **near misses** and which bytes differ.
* **Keys living inside a binary** — `--verify-binary` tries candidate keys against the ciphertext embedded in the program and answers "which key is right", not "which key looks right".
* **Packing** — `unpack` runs the packer stub in the emulator and dumps the image, so modified UPX works too; samples locked by antivirus can be streamed through `-`.
* **Letting the program judge itself** — `emu --run` / `gui --discover` use Unicorn with 300+ Win32 stubs and fake system DLLs plus a PEB→Ldr chain, then quote the program's own verdict strings.

## What it does not do

| Not supported | Why / what to use instead |
|---|---|
| .NET (IL) | IL is not parsed; the tool says so and points at dnSpy / ILSpy |
| Android APK / web / pwn | Out of scope; points at jadx / a browser / pwndbg |
| Non-UPX packers | Reports evidence (name, confidence) but does not force an unpack; suggests x64dbg + Scylla |
| GUI message loops | Buttons are not simulated; the route is "call the check routine directly", limited to statically reachable verdicts |
| Self-written packers needing a faithful loader environment | More API stubs do not help; the tool reports the wall instead of pretending to advance |

## Install

```bash
pip install -r requirements.txt
```

Pure stdlib still runs the encoding/classical half. `unicorn`/`capstone` gate dynamic analysis;
`numpy`/`Pillow` gate scanning and stego. Python 3.8+ (tested on 3.13).

## Five minutes in

**Start by asking for directions** (this is what tells you whether the challenge is worth your time):

```bash
python plainseek.py triage ./challenge.exe
```

Output: identity (PE32 console) → packer (none / UPX / ?) → runtime (MSVC C++ / .NET / Go…) → input channel
(stdin / GUI) → verdict strings → crypto constants → **tier verdict** → **ranked next commands**.

**Tier A: just run it**

```bash
python plainseek.py auto ./challenge_dir     # recon + chain search + judging
python plainseek.py xor ./blob.bin           # blind XOR
python plainseek.py basedecode ./str.txt     # recursive base decoding
```

**Tier B: follow triage's plan**

```bash
python plainseek.py unpack cm.exe                      # unpack UPX first
python plainseek.py sig cm.unpacked.bin                # which algorithm shows up
python plainseek.py emu cm.exe --run --stdin "candidate"   # let the program judge
python plainseek.py emu cm.exe --anchor "Correct" --break 0x401234
```

## Commands

| Group | Commands |
|---|---|
| Pipeline | `scan` `auto` `solve` `chain` `triage` |
| Encoding / classical | `basedecode` `xor` `crack` `identify` `transforms` |
| Structure / crypto | `table` `pair` `verify` `formula` `oracle` |
| Files / stego | `carve` `stego` `fragments` `pyc` `bulk` |
| Binary | `sig` `unpack` `crackme` `emu` `gui` |
| Self-check | `selftest` (61 items, negative cases included) |

Full reference: [docs/commands.md](docs/commands.md) (Chinese).

## Evidence levels — the part worth reading

| Level | Meaning |
|---|---|
| 0 | text guess ("looks like text") |
| 1 | shape/format valid (parses as JSON/PNG…) |
| 2 | heuristic (statistically flag-like) |
| 3 | round-trip (re-encrypting reproduces the ciphertext) |
| 4 | oracle (a format validator accepts it) |
| 5 | emulation (the program's own code accepted it) |
| 6 | binary self-proof (embedded ciphertext confirmed the key) |

**Anything stuck at 0–2 is reported as unverified and never presented as the answer.** Decoy flags that look
complete but are never compared are far too common in RE challenges.

## Three principles (each one learned the hard way)

1. **Evidence gating** — a candidate must pass an independent verifier; dead ends stay dead ends.
2. **Under-report rather than fish in noise** — multi-byte XOR string decryption is opt-in, packer signatures are conservative; a false hit is worse than a miss.
3. **Write the trap into the comment** — the TEB page at address 0, stdcall arities, instruction lengths, junk bytes inside instructions, `enter` reporting a strange error inside a translation block: every non-obvious workaround here carries the failure that produced it.

## Renamed

Formerly `autocrypt`. It is not an "automatic crypt" — the old name oversold and set users up to hit the
failure rate on their first try. It is now `plainseek` (seek the plaintext), with the A/B split on the front page
and the measured baseline published.

* New entry points: `python plainseek.py ...`, `plainseek.bat`
* Old ones still work: `python autocrypt.py ...`, `一条龙.bat` (both forward and print a rename notice)

## Status and limitations

* **61/61** self-checks pass, negative cases included (a wrong input must be judged wrong).
  CI runs on every push on **Windows 3.10/3.13 and Linux 3.10/3.12**, both required (first run fully green).
* Windows is the main battlefield; on Linux the ELF/pure-algorithm half runs.
* Emulation is stronger than static guessing and weaker than a real machine — the evidence level in the output says which one you are looking at.
* C++ console targets need CRT initialisation (`_initterm`, `__p__acmdln`, `realloc`, `getc` are implemented), but targets that spawn real threads or depend on timing may still bail out early; the tool reports where.

## Layout

```
plainseek.py        entry point (autocrypt.py is a compatibility shim)
plainseek.bat       Windows launcher (一条龙.bat is a compatibility shim)
pseek/              implementation
  triage.py         routing: recon + ranked next steps
  unpack.py         in-memory UPX unpacking
  emu.py winapi.py fakedll.py   Unicorn emulation + Win32 stubs + fake system DLLs
  oracles.py alphabets.py ciphers.py transforms.py recover.py   tier-A core
  board.py          evidence-gated blackboard
  sigscan.py crackme.py gui.py stego.py pyc.py formula.py fragments.py verify.py
tests/              developer tests (private samples via AUTOCRYPT_DATA; clean skip when missing)
docs/commands.md    per-command reference
.github/workflows/  CI: Windows + Linux gates + entry-point compatibility
```

## License

MIT.
