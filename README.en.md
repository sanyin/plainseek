# autocrypt — an all-in-one CTF decryption toolkit

> **Give it a directory, get plaintext back.** No hard-coded "per-challenge" keys: the tool
> works out the alphabet itself, tries the cipher parameters itself, stacks layers itself, and
> judges whether the result is actually right.

[中文说明（完整版）](README.md) · [License: MIT](LICENSE)

This is the English overview. The Chinese `README.md` is much longer and contains the full
per-command walkthrough and the experiment log; everything essential is mirrored here.

---

## 1. What it is good at

* **Layered encryption** — hex → reverse → zlib, base64 → AES-ECB, rot13 → XOR → gzip … the
  chain search discovers the layers instead of you telling it.
* **Shuffled alphabets** — a base64/custom-base table whose character order is randomised is
  recovered from structural constraints (padding position, trailing bits, decoded-length
  divisibility), not by brute force.
* **Modified ciphers** — RC4 with a tweaked PRGA, DES with reversed bit-selection tables,
  AES with one byte of the S-box changed: the signature scanner matches *near misses* and
  reports what was altered.
* **Key confirmation** — when the key is derived inside a program (MD5 of a 6-digit input and
  so on), `--verify-binary` takes the ciphertext that lives in the binary, tries candidate keys
  against it and keeps the one that produces structured output. It answers "what key is right",
  not "what key looks plausible".
* **Windows crackmes without running them** — a Unicorn-based emulator with ~300 Win32 API
  stubs, fake system DLLs plus a PEB→Ldr chain, an execution trace disassembler, breakpoints
  and an API stack ledger. The program is asked to judge its own input; the tool only reports
  what the program itself printed.
* **Packed samples** — `unpack` runs the UPX stub in the emulator and dumps the decompressed
  image, so a packed crackme becomes a normal one. Works even when the sample is modified and
  `upx -d` refuses it, and even when the file is locked by an antivirus (read it through a pipe).

---

## 2. Install

```bash
pip install -r requirements.txt
```

| package | used for | if missing |
|---|---|---|
| `pycryptodome` | AES / DES / 3DES / RC4 / ChaCha20 / Salsa20 | standard-cipher path unavailable |
| `numpy` | vectorised scanning (entropy, XOR-string decryption, bit planes) | related commands warn |
| `Pillow` | image stego (BMP bit planes, spectrum plots), Huffman table comparison | image features degrade gracefully |
| `unicorn` | CPU emulation (`emu`, `gui`, `crackme`, `unpack`) | dynamic analysis commands unavailable |
| `capstone` | disassembly (trace decoding, instruction lengths) | dynamic analysis commands unavailable |
| `keystone-engine` | assembling tiny test samples inside `selftest` | that selftest item is skipped |

Pure-stdlib `python autocrypt.py` still runs the classical-crypto and encoding half.
Tests that need a private sample read `AUTOCRYPT_DATA`; without it they print one line and
exit cleanly instead of dumping a stack trace.

Python 3.8+ (tested on 3.13).

---

## 3. Quick start

```bash
# 1) look around first
python autocrypt.py scan ./challenge

# 2) the whole pipeline: detect → chain-search → verify → report
python autocrypt.py auto ./challenge

# 3) when the key lives inside a binary
python autocrypt.py verify-binary app.exe --cipher-offset 0x3020

# 4) a Windows crackme: let the program judge its own input
python autocrypt.py emu crackme.exe --run --stdin "candidate-password"

# 5) packed crackme: unpack in memory, then analyse
python autocrypt.py unpack crackme.exe
python autocrypt.py sig crackme.unpacked.bin

# 6) sample is locked by an antivirus? stream it through stdin
unrar p -p<password> pack.rar target.exe | python autocrypt.py unpack - --out target.bin
```

Every command accepts `--json` for machine-readable output.

---

## 4. Commands

| command | what it does |
|---|---|
| `scan` | reconnaissance: file type, entropy, encoding guesses, whether a plaintext/ciphertext pair exists |
| `solve` | the one-shot pipeline over a directory |
| `chain` | replay an explicit recipe (handy for verification and reuse) |
| `pair` | analyse a plaintext/ciphertext pair → keystream or alphabet conclusions |
| `table` | recover a shuffled character table |
| `oracle` | score a file for "does this look like the real thing" |
| `transforms` | list every available transform |
| `identify` | what is this string: hash / token / credential / encoding … |
| `xor` | multi-byte XOR: guess the key length, then the key |
| `basedecode` | recursive base decoding (hex/base32/base64/base85/base91 …) |
| `carve` | scan and carve embedded files (magic numbers, structural validation, archive suppression) |
| `crack` | classical ciphers: Caesar, affine, Vigenère, monoalphabetic, rail fence |
| `verify` | key confirmation against a known ciphertext |
| `fragments` | collect and stitch flag fragments stored separately |
| `pyc` | read Python bytecode: version, constants, disassembly, `--solve` |
| `sig` | crypto-constant fingerprints (including modified constants), packer detection, entropy |
| `gui` | GUI/CrackMe auto-judge: find candidate check routines and let the program decide |
| `crackme` | static help: locate input and comparison sites, optional emulation |
| `emu` | emulation forensics: run a function, see what memory it rewrites |
| `unpack` | **UPX unpacking by emulation** (dumps a flat, analysable image) |
| `stego` | BMP bit planes, WAV spectrum/audio decoding |
| `formula` | derive a per-byte linear formula from a target byte and a known prefix |
| `bulk` | batch: one candidate per line, auto-detected and decoded |
| `auto` | file / folder / archive pipeline (recon, then solve) |
| `selftest` | 52 synthetic checks over the whole pipeline |

---

## 5. How it decides (and why you can trust the output)

Every conclusion carries an **evidence level**:

| level | meaning |
|---|---|
| 0 | text-level guess (something looks like text) |
| 1 | shape/format valid (parses as JSON/PNG/…) |
| 2 | heuristic (statistical, "looks like" a flag) |
| 3 | round-trip (re-encrypting gives the original bytes back) |
| 4 | oracle (a format validator accepts it) |
| 5 | emulation (the program's own code accepted it) |
| 6 | binary (the binary's own embedded ciphertext confirmed the key) |

Decoys are common in reverse-engineering challenges: strings that look like a complete flag
but are never compared. A candidate that only reached level 0–2 is reported as *unverified* and
never presented as the answer. `--json` exposes the level on every candidate.

Two habits that came out of real failures and are now enforced in the code:

* **Negative tests matter more than positive ones.** If a check routine is mis-identified, the
  program prints "Correct!" for every input — a silently wrong answer. The selftest therefore
  feeds a deliberately wrong input and requires the program to reject it.
* **"Runs further" is the only real evidence.** Two early conclusions ("the TEB page is fine",
  "dynamic API arity cannot be counted") were wrong; both were only caught by measuring
  instruction counts instead of reasoning about the code.

---

## 6. Design principles

1. **Evidence gating.** Candidate answers must pass an independent verifier before being
   finalised; dead ends stay dead ends.
2. **Rather under-report than fish in noise.** Multi-byte XOR string decryption is opt-in and
   flagged as "needs human confirmation"; packer signatures are conservative.
3. **Write the trap into the comment.** Every non-obvious workaround in this codebase carries
   the failure that produced it (TEB page at address 0, stdcall argument counts, instruction
   lengths, junk bytes inside instructions, `enter` inside a translation block …).
4. **Say what it cannot do.** .NET, APK and pwn are out of scope and the tool says so instead of
   producing a plausible-looking wrong answer.

---

## 7. Limitations

* **GUI message loops are not emulated.** The working route is "call the check routine directly
  with a prepared buffer"; it covers the class where the verdict text is statically reachable.
* **.NET / Android / pwn** are out of scope — the tool tells you to use dnSpy, jadx or pwndbg.
* **Self-written packers** that depend on a faithful loader environment (module layout, their own
  integrity data) are not solved by adding more API stubs; the tool reports the wall instead.
* **Emulation is stronger than static guessing but weaker than real execution** — the evidence
  level in the output always says which one you are looking at.
* C++ console targets need CRT initialisation (`_initterm`, `__p__acmdln`, `realloc`,
  `getc`/`ungetc`). These are implemented; targets that start extra threads or rely on real
  timing may still bail out early, and the tool reports where.

---

## 8. Layout

```
autocrypt.py          entry point
一条龙.bat            double-click launcher for Windows
dkit/
  oracles.py          format validators (is this decrypt right?)
  alphabets.py        alphabet recovery
  ciphers.py          cipher implementations, including modified variants
  transforms.py       transform registry
  recover.py          chain search
  board.py            evidence-gated blackboard
  emu.py              Unicorn emulation (PE/ELF), trace disassembly
  winapi.py           ~300 Win32 API stubs
  fakedll.py          fake system DLLs + PEB→Ldr chain
  pe.py               PE parsing, function discovery, xrefs
  unpack.py           UPX unpacking by emulation
  sigscan.py          crypto constant fingerprints, packers, XOR strings
  crackme.py          static crackme help
  gui.py              GUI/CrackMe auto-judge
  stego.py            BMP/WAV steganography
  pyc.py              Python bytecode
  formula.py          per-byte formula recovery
  fragments.py        flag fragment stitching
  verify.py           key confirmation
  selftest.py         52 self-checks
tests/                developer tests (private samples via AUTOCRYPT_DATA)
examples/             template scripts for key derivation / emulation
```

---

## 9. Real-world results

Details and dead ends are documented in the Chinese `README.md` (section 五) and in
`_卡点与已解出.md` in the parent working directory. Short version:

* a base64 alphabet scrambled by a fake-UPX challenge: **recovered automatically**, three files
  decrypted byte-for-byte;
* an EasyLanguage binary with an MD5-derived key and reversed DES tables: key
  **`732425` found automatically in ~46 s** by `--verify-binary`;
* a KanXue 2019 CTF challenge (scrambled base64 + `strcmp`): solved, answer re-verified by
  re-running the program itself;
* a 52pojie Spring Festival challenge (`~ord(x)^prime`): solved, recomputed forward and compared
  against the embedded `check[]`;
* a 2012 crackme whose typed text is itself a tiny VM program: keygen written from the recovered
  rule, verified in the emulator.

2026 Spring Festival pack (in progress at the time of writing): UPX-packed crackme unpacked and
identified as UPX + AES-128; a C++ console crackme went from *"aborts after 3312 instructions
with no output"* to *"prints its banner, reads stdin, and returns a length hint"* after the CRT
initialisation and stdio fixes.

---

## 10. License

MIT. See [LICENSE](LICENSE).
