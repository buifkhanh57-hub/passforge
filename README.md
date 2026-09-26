# passforge

> Professional password generator and auditor toolkit — pure Lua, zero dependencies, fully offline.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Lua](https://img.shields.io/badge/Lua-5.1%20%E2%80%93%205.4-blue.svg)](https://www.lua.org/)
[![LuaJIT](https://img.shields.io/badge/LuaJIT-2.0%2B-blue.svg)](https://luajit.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)]()
[![Crypto](https://img.shields.io/badge/SHA--256-FIPS%20180--4-informational.svg)]()
[![Tests](https://img.shields.io/badge/tests-spec%20suite%20%2B%20NIST%20vectors-success.svg)]()
[![Version](https://img.shields.io/badge/version-1.0.0%20(anvil)-orange.svg)]()

---

## Overview

**passforge** is a command-line password toolkit that generates random passwords and
diceware-style passphrases, analyzes the strength of existing ones, audits whole batches,
computes honest entropy math, and verifies files with a from-scratch SHA-256 — all in
pure Lua with **no external rocks, no C bindings, and no network access**.

Every number it prints comes from one shared entropy engine (`passforge/entropy.lua`),
so the verdict shown by `gen`, `pass`, `strength`, `audit`, `tips` and `entropy` can
never disagree. The whole toolkit runs unchanged on Lua 5.1, 5.2, 5.3, 5.4 and LuaJIT
thanks to a bit-exact bitwise compatibility layer that falls back from `bit32` to `bit`
to a pure-Lua implementation.

- **Everything is local.** Generation, analysis, hashing and auditing never touch the
  network and never write files (except temp files for one streaming test).
- **Everything is inspectable.** ~6,600 lines of dependency-free Lua you can read in an
  afternoon, pinned by known-answer tests.
- **Everything is honest.** The security notes below state the real limits of a
  pure-Lua RNG instead of pretending otherwise.

## Features

| Area | What you get |
| --- | --- |
| **Password generation** | Character-set driven (`luds`), 4–256 chars, ambiguity filtering (`Il1O0o|`), no-repeats mode, per-set inclusion guarantees |
| **Passphrase generation** | Embedded 1024-word list (exactly 10.00 bits/word), custom separators, capitalization, optional digit suffix |
| **Strength analysis** | Verdict scale 0–5, three entropy views (pool / distinct-alphabet / Shannon), pattern deductions, ~500-entry leaked-password corpus |
| **Batch auditing** | One password per line from files or stdin, masked output by default, batch statistics, `--min-score` CI gate |
| **Entropy math** | A dedicated command that shows pool sizes, bits, keyspace and crack times *without generating anything* |
| **Contextual tips** | Ranked recommendations with `why`/`how` for a concrete password or for planned generation settings |
| **SHA-256 hashing** | From-scratch FIPS 180-4 implementation, string/file/stdin input, 64 KiB streaming for files |
| **Charset reference** | Exact set contents, sizes with and without ambiguous characters, alias letters |
| **Self-test** | Embedded spec suite runnable as `passforge selftest` — no external test framework |
| **JSON output** | Every command supports `--json` / `--pretty` for machine-readable pipelines |

## Requirements

| Requirement | Notes |
| --- | --- |
| Lua 5.1 / 5.2 / 5.3 / 5.4 or LuaJIT 2.0+ | Any one of them; the compatibility layer picks the best bitwise backend (`bit32`, `bit`, or `pure`) automatically |
| POSIX-ish shell (optional) | `/dev/urandom` is used for seeding **when available**; without it passforge still runs, with weaker seeding (see Security notes) |
| Nothing else | No LuaRocks, no OpenSSL, no shared libraries, no network |

## Installation

passforge is a single repository — clone it and run it:

```sh
git clone https://github.com/buifkhanh57-hub/passforge.git
cd passforge
./bin/passforge version
```

Or install the shim on your `PATH`:

```sh
ln -s "$PWD/bin/passforge" /usr/local/bin/passforge   # adjust to taste
passforge help
```

The `bin/passforge` shim rewrites `package.path` relative to its own location, so
symlinked installs work from any working directory. As a library, just make the repo
root reachable from `package.path` and:

```lua
local pf = require("passforge")
print(pf.sha256.hex("abc"))
-- ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

## Quick Start

```console
$ passforge gen --length 20 --sets luds --no-ambiguous --count 3
rT7#mQz2pXw4!tN8hR3yE
uV6kF9dJ2cB5nH8sW3qM
yA4pG7tZ1xC6mK2vD9fL

$ passforge pass --words 5
copper-harbor-meadow-raven-ladder

$ passforge hash abc
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

$ passforge strength 'Summer2023!' | head -5
verdict:   fair (score 2/5)
entropy:   45.54 bits  (base 59.54 - deductions 14.00)
length:    10   classes: lower+upper+digits   pool: 62
views:     pool 59.54 | distinct 46.51 | shannon 43.89 bits
findings:  2
```

> The command layouts above are exactly what the CLI prints. Passwords and the
> numeric analysis values are illustrative examples (generation output is random by
> design); the `hash` digests are the real NIST/canonical vectors.

## Usage

### Commands

| Command | Aliases | Purpose |
| --- | --- | --- |
| `passforge gen` | `generate`, `rand` | Generate random passwords from character sets (`-l`, `-c`, `-s`, `--no-ambiguous`, `--no-repeats`, `--no-require-each`) |
| `passforge pass` | `passphrase` | Generate passphrases from the embedded 1024-word list (`-w`, `--sep`, `--cap`, `--digit`) |
| `passforge strength` | `check` | Analyze one password (argument or `-` for stdin): verdict, entropy decomposition, findings, crack times |
| `passforge audit` | — | Audit many passwords from FILE(s)/stdin with batch stats and an optional `--min-score` exit gate |
| `passforge entropy` | `est` | Show the entropy math for a mode without generating anything (`-m gen\|pass`) |
| `passforge tips` | `advise` | Contextual recommendations for a password or for planned generation settings |
| `passforge hash` | `sha256` | SHA-256 of a string, `--file PATH` (streamed in 64 KiB chunks), or stdin |
| `passforge charset` | `charsets` | Print character-set tables, ambiguity counts and reference pool sizes |
| `passforge selftest` | `test` | Run the embedded spec suite from the repository |
| `passforge version` | — | Print identity, interpreter (`_VERSION`) and active bitwise backend |
| `passforge help` | — | Global usage or per-command help |

### Global flags and exit codes

| Flag | Effect |
| --- | --- |
| `--json` | Compact machine-readable output |
| `--pretty` | Indented JSON (implies `--json`) |
| `--version` | Identity banner |

| Exit code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Audit threshold failed (`--min-score`) |
| `2` | Usage error (bad flags, missing arguments) |
| `3` | Runtime error (broken install, unreadable file) |

### `passforge gen` — character-set passwords

```console
$ passforge gen --length 16 --sets lud
kR3mf8wQp2vXh7Zd

$ passforge gen --count 5 --no-ambiguous --json
{
  "command": "gen",
  "passwords": [ "rT7#mQz2pXw4!tN8hR3yE", "..." ],
  "count": 5,
  "parameters": { "length": 20, "sets": "luds", "ambiguous": false, ... },
  "entropy_bits": 124.54,
  "verdict": "excellent",
  "score": 5
}
```

Selected sets map from `-s luds` (`l`=lower, `u`=upper, `d`=digits, `s`=symbols);
`--no-ambiguous` strips `Il1O0o|` from every set (lower loses `l`/`o` → 24 chars, digits
lose `0`/`1` → 8 chars). By default one character per selected set is forced so a
declared `luds` password can never come out all-lowercase; `--no-require-each` relaxes
that. `--no-repeats` samples without replacement.

### `passforge pass` — memorable passphrases

```console
$ passforge pass --words 6 --sep . --cap
Copper.Harbor.Meadow.Raven.Ladder.Moss
```

Every word carries exactly `log2(1024) = 10.00` bits, so the math is trivially
verifiable: 4 words = 40.00 bits, 6 words = 60.00 bits. `--digit` appends one random
digit (~3.32 extra bits). The wordlist is curated: 3–9 letters, common English, no
profanity, no two entries differing only by a trailing `s`/`d`, and uniqueness enforced
at load time.

### `passforge strength` — one password, fully decomposed

```console
$ passforge strength 'Tr0ub4dor&3'
verdict:   strong (score 3/5)
entropy:   63.10 bits  (base 72.10 - deductions 9.00)
length:    11   classes: lower+upper+digits+symbols   pool: 94
views:     pool 72.10 | distinct 63.55 | shannon 55.76 bits
findings:  2
  [warn] leetified spelling adds no real entropy (-3.00 bits)
          substitutions like 0->o and 4->a are tried by every cracker
  [info] dictionary word "troubador" (-6.00 bits)
          matches the embedded wordlist
crack time (average case, half the keyspace):
  online, rate-limited (100/s)         10.0 million years
  online, unthrottled (10^4/s)         100.0 thousand years
  offline, slow hash (10^5/s)          10.0 thousand years
  offline, fast hash (10^11/s)         2.4 days
  offline, GPU farm (10^15/s)          21.0 minutes
```

The three "views" are deliberately shown together: the optimistic pool view (what the
generator *would* have used), the distinct-alphabet bound and the Shannon content of
the actual string. Pattern penalties (sequences, repeats, keyboard walks, years, dates,
dictionary words, leet, single class, short length) are subtracted from the base and
every deduction is printed. If the password appears in the embedded ~500-entry leaked
corpus, an `ALERT` line with its rank appears — those die in seconds regardless of length.

### `passforge audit` — batches with a CI gate

```console
$ printf 'hunter2\nTr0ub4dor&3\nfountainpen\n' | passforge audit - --min-score 3
  1. h******2      30.68 bits  score 1/5  weak            2 findings
  2. T*********3   63.10 bits  score 3/5  strong          2 findings
  3. f*********n   45.70 bits  score 2/5  fair            1 finding

THRESHOLD: FAIL - at least one password scores below 3/5
$ echo $?
1
```

Input is one password per line; blank lines and `#` comments are ignored. Secrets are
masked (first + last character, `f*********n`) unless `--reveal` is passed, so JSON
dumps and CI logs are safe to share by default. Use `--min-score N` in CI to fail the
build when any password scores below N.

### `passforge hash` — SHA-256 where you need it

```console
$ passforge hash abc
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

$ echo 'The quick brown fox jumps over the lazy dog' | passforge hash -
d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592

$ passforge hash --file /etc/hostname --json
{ "command": "hash", "algorithm": "sha256", "input": "file:/etc/hostname",
  "bytes": 32, "hex": "..." }
```

stdin has exactly one trailing CR/LF run stripped, so `echo abc |` matches the
canonical `"abc"` vector; string arguments are used byte-exact. Files are streamed in
64 KiB chunks, so arbitrarily large files hash in constant memory.

## Security notes — the honest version

- **The RNG is xorshift128, not a CSPRNG.** Pure Lua has no OS-grade random API, so
  `random.lua` seeds a 32-bit xorshift128 (Marsaglia 2003, period 2¹²⁸−1) from the best
  available source. When `/dev/urandom` can be read, its bytes are hashed into the seed
  — decent seeding. When it cannot (restricted sandbox, Windows, `io.popen` disabled),
  the seed falls back to `os.time` + `os.clock` + GC counters + fresh table addresses,
  which is **weak**: an attacker who knows roughly *when* a password was generated can
  enumerate that small seed space. Treat passforge's output accordingly and prefer
  dedicated OS tooling for high-value secrets.
- **Deterministic mode is for tests only.** `--seed TEXT` derives the whole state from
  `sha256("passforge-seed" .. seed)`. Identical seeds emit identical streams — great for
  reproducible bug reports, catastrophic for real passwords. The CLI help says so at
  the point of use.
- **Offline by design.** Nothing phones home, nothing is logged, no config is written.
  What you generate stays in your terminal (and your scrollback — use `--json` into a
  file if that matters).
- **Entropy is a property of the generation process, not of one string.** For a
  password you did not generate yourself, the printed bits are an *upper bound*;
  pattern detectors subtract from them, never add.
- **Crack times are models, not physics.** They are average-case (half the keyspace),
  assume the attacker knows your generation scheme, and ignore server-side rate
  limiting, hash cost and password reuse. They exist to compare options, not to
  promise survival times.
- **SHA-256 here is standard, verified SHA-256.** The implementation is pinned to the
  official NIST vectors (see Testing below), so digests match every other correct
  implementation. It is a hash, not a password KDF — do not store passwords hashed
  with it; use bcrypt/argon2 on the server side.
- **Batch audits are read-only.** `audit` never writes reports to disk; it prints to
  stdout/stderr and masks secrets unless you explicitly `--reveal`.

## Entropy methodology

All estimates live in one module (`passforge/entropy.lua`) and are shared verbatim by
every command:

- **Pool arithmetic (mode `gen`):** `bits = length × log2(pool_size)` — the classic
  independent-draws model. Pools: lower 26, upper 26, digits 10, symbols 32; combined
  pools are sums (e.g. `luds` = 94, `lud` = 62). `--no-ambiguous` re-counts the pools
  after removing `Il1O0o|`.
- **Wordlist arithmetic (mode `pass`):** `bits = words × log2(1024)` = exactly
  `10.00 × words`; `--digit` adds `log2(10) ≈ 3.32` bits.
- **String-side views (mode `strength`):** three independent estimates are printed —
  the pool view, a distinct-alphabet bound and the Shannon content of the actual
  characters — followed by explicit pattern deductions (bits are subtracted, never
  added).
- **Shared verdict scale:** one table maps bits → score 0–5 → label
  (`<28` very weak, `28+` weak, `36+` fair, `60+` strong, `80+` very strong, `100+`
  excellent). Negative bits (deduction overshoot) clamp to score 0.
- **Crack-time model:** five documented attacker rates — online rate-limited (10²/s),
  online unthrottled (10⁴/s), offline slow hash (10⁵/s), offline fast hash (10¹¹/s),
  offline GPU farm (10¹⁵/s) — each converted as `2^bits / rate` seconds, average case.
- **Keyspaces** beyond ~300 bits are still printed as finite IEEE-754 doubles; they are
  astronomically large either way, and the exact mantissa does not change any decision.

## Project Structure

```
passforge/
├── bin/
│   └── passforge              46   executable shim: package.path bootstrap + exit-code translation
├── passforge/                      the library (one module per concern)
│   ├── init.lua               31   library facade: require("passforge") returns every module
│   ├── version.lua            46   single source of truth for name/version/codename/license
│   ├── compat.lua            270   Lua 5.1–5.4/LuaJIT bitwise layer (bit32 → bit → pure fallback)
│   ├── charsets.lua          222   the four canonical sets, ambiguity filtering, per-class sizes
│   ├── json.lua              132   minimal JSON encoder for --json/--pretty output
│   ├── sha256.lua            257   pure-Lua SHA-256 (FIPS 180-4), incremental + file streaming
│   ├── random.lua            318   seeding (urandom → fallbacks), xorshift128, unbiased sampling
│   ├── wordlist.lua         1178   embedded 1024-word list + uniqueness guard at load time
│   ├── generator.lua         229   character-set password engine (pools, per-set inclusion)
│   ├── passphrase.lua        168   word-based passphrase engine (separator/cap/digit options)
│   ├── entropy.lua           384   shared math: pools, SCALE, keyspace, crack-time model
│   ├── strength.lua          864   single-password analysis + ~500-entry leaked corpus + penalties
│   ├── tips.lua              392   contextual recommendations with why/how
│   ├── audit.lua             261   batch orchestration, masking, batch statistics
│   └── cli.lua              1073   command parsing, help text, JSON emission, dispatch, USAGE
└── spec/                           embedded test suite (no external framework)
    ├── run.lua                51   entry point: registers suites, run_all() → exit code
    ├── harness.lua           213   tiny spec harness (suites, assertions, summary, exit code)
    ├── compat_spec.lua       132   bitwise backend contract tests
    ├── json_spec.lua         148   encoder round-trips and escaping
    └── sha256_spec.lua       178   FIPS 180-4 known-answer vectors + incremental/file tests
```

Line counts are the real on-disk sizes. Dependency direction is flat and one-way:
`compat` → `charsets`/`sha256` → `random`/`wordlist` → `generator`/`passphrase` →
`entropy` → `strength` → `tips` → `audit`/`cli`.

## Testing

The suite is embedded — no Busted, no LuaRocks:

```sh
lua spec/run.lua        # from the repository root
passforge selftest      # or through the shim
```

The SHA-256 module is pinned to the **official FIPS 180-4 test vectors** in
`spec/sha256_spec.lua`; if any of these fail, the toolkit's security statements are
void:

| Message | Expected digest |
| --- | --- |
| `""` (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `"abc"` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| 448-bit message (`abcdbcde…nopnopq`) | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` |
| 896-bit two-block message | `cf5b16a778af8380036ce59e7b0492375b2495fdb8d4a65a543f14bd6da5e72` |
| one million `"a"` characters | `cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0` |

Beyond the vectors, the suite covers: K-table geometry (512-bit blocks, 256-bit
digest, 64 round constants), the incremental `new()/update()/finish()` API against
one-shot hashing across every padding boundary from 0–66 bytes, binary content
stability, file streaming via a temp file, and the error protocol (missing files,
foreign states). The `compat` suite pins the bitwise backend contract (including the
pure-Lua fallback, which is what makes all interpreters behave identically), and the
`json` suite covers round-trips and escaping.

Library modules additionally carry load-time invariant checks inside `passforge/`
itself — e.g. the wordlist raises immediately on a duplicate word, and the entropy
SCALE table must stay ordered by `min_bits`.

## FAQ

**Is passforge safe for generating my real bank password?**
Use it with eyes open: on a normal POSIX system with `/dev/urandom` reachable the
seeding is decent and the output is fine for everyday accounts. It is still not a
CSPRNG-based tool — for high-value secrets prefer `openssl rand` / your password
manager's generator. See Security notes.

**Why not use a "real" CSPRNG?**
Pure Lua exposes no byte-level OS randomness and no crypto primitives. The design
goal was zero dependencies across Lua 5.1–5.4 and LuaJIT, so `random.lua` collects
the best seed it can reach and is honest about the fallbacks.

**Why only 1024 words instead of EFF's 7776?**
So every word is exactly 10.00 bits and the math is verifiable in your head.
Security is equivalent per-bit; you just need one more word (`6 × 10 = 60` bits)
than with a 7776-word list (`6 × 12.9 = 77.5` bits).

**Why does `strength` show *three* entropy numbers?**
They answer different questions: the pool view is what the generator would have
used, the distinct-alphabet and Shannon views measure the actual string. Real
security is capped by the smallest honest view minus deductions.

**Is `passforge hash` suitable for storing passwords?**
No. SHA-256 is a fast hash; password storage needs a slow KDF (bcrypt, scrypt,
argon2). Use `hash` for integrity checks, deduplication and file verification.

**Does anything leave my machine?**
No. No network calls exist in the codebase — you can grep for `io.popen` and find
only the `/dev/urandom` read.

**Why is the audit output masked by default?**
Because audit output is the kind of thing that ends up in tickets, CI logs and
screenshots. Pass `--reveal` explicitly when you truly need plaintext.

**Which Lua should I run it with?**
Any of them. 5.4 or LuaJIT is fastest; 5.2 uses the `bit32` backend; everything else
uses the verified pure-Lua bitwise fallback, which is bit-exact but slower.

## Roadmap

- [ ] Additional wordlists (EFF large list, non-English) selectable via `--list`
- [ ] Optional Have I Been Pwned-style offline corpus expansion for `audit`
- [ ] `bench` command: measure generator throughput and backend speed on your interpreter
- [ ] Export/import audit reports as CSV
- [ ] Optional Argon2-style slow KDF study for pure Lua (documentation-first)
- [ ] Man page and shell completions (bash/zsh/fish)
- [ ] Per-command `--pretty` fixtures in the spec suite
- [ ] Packaging: LuaRocks rockspec and Homebrew formula

## License

MIT License — see `LICENSE` in the repository root. Copyright (c) 2026 Bui Bao Khanh.
You may use, copy, modify and distribute this software with attribution; it is provided
"as is", without warranty of any kind.

---
**by Bui Bao Khanh**
