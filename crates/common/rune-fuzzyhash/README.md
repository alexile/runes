# rune-fuzzyhash

> TLSH and ssdeep (CTPH) fuzzy hashes with distance scoring for near-identical files and payloads

[![crates.io](https://img.shields.io/crates/v/rune-fuzzyhash)](https://crates.io/crates/rune-fuzzyhash)
[![docs.rs](https://img.shields.io/docsrs/rune-fuzzyhash)](https://docs.rs/rune-fuzzyhash)
[![license](https://img.shields.io/crates/l/rune-fuzzyhash)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Fuzzy hashes for grouping near-identical content: favicon variants, JS
bundle versions, copied code, malware families. Sans-I/O: bytes in, digest
out. Output is bit-for-bit identical to the reference implementations, so
digests interoperate with existing databases and tools.

| Algorithm | Digest | Similarity | Recommended cut-off |
| --- | --- | --- | --- |
| [TLSH](https://github.com/trendmicro/tlsh) (preferred) | `T1` + 70 hex | `Tlsh::distance`: 0 = identical, unbounded | ≤ 50 similar (`tlsh::RECOMMENDED_MAX_DISTANCE`), ≤ 30 strict (`tlsh::STRICT_MAX_DISTANCE`) |
| [ssdeep](https://ssdeep-project.github.io/ssdeep/) (CTPH) | `blocksize:d1:d2` | `Ssdeep::compare`: 0–100, 100 = identical | ≥ 50 similar (`ssdeep::RECOMMENDED_MIN_SCORE`); > 0 shares content |

**Which one?** Prefer TLSH: any two digests are comparable, the distance
degrades gracefully under spread-out edits and reordering, and it needs only
50 bytes (with some variety). ssdeep is better at spotting one file embedded
in another, but only compares digests whose block sizes are within a factor
of two and says little about inputs under a few hundred bytes.

## Installation

```toml
[dependencies]
rune-fuzzyhash = "0.1"
```

Enable the `serde` feature to serialize digests as strings. The
command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-fuzzyhash --features cli
```

## Usage

### Library

```rust
use rune_fuzzyhash::{Ssdeep, Tlsh, TlshBuilder, ssdeep, tlsh};

fn main() -> Result<(), rune_fuzzyhash::Error> {
    let v1: String = (0..300).map(|i| format!("function f{i}(x) {{ return x * {i}; }}\n")).collect();
    let v2 = v1.replace("return x * 150;", "return x - 1;");

    // TLSH: lower distance = more similar.
    let (a, b) = (Tlsh::hash(v1.as_bytes())?, Tlsh::hash(v2.as_bytes())?);
    assert!(a.distance(&b) <= tlsh::STRICT_MAX_DISTANCE);
    println!("{a}"); // T1…

    // Streaming input.
    let mut builder = TlshBuilder::new();
    for chunk in v1.as_bytes().chunks(4096) {
        builder.update(chunk);
    }
    assert_eq!(builder.finish()?, a);

    // ssdeep: higher score = more similar.
    let (x, y) = (Ssdeep::hash(v1.as_bytes())?, Ssdeep::hash(v2.as_bytes())?);
    assert!(x.compare(&y) >= ssdeep::RECOMMENDED_MIN_SCORE);

    // Digests from elsewhere (feeds, databases) parse and compare too.
    let known: Tlsh = "T109F05A198CC69A5A4F0F9380A9EE93F2B927CF42089EA74276DC5F0BB2D34E68114448".parse()?;
    println!("distance to known sample: {}", a.distance(&known));
    Ok(())
}
```

### CLI

```bash
rune-fuzzyhash hash app.v1.js app.v2.js
# T1…<TAB>96:…<TAB>app.v1.js
# T1…<TAB>96:…<TAB>app.v2.js

rune-fuzzyhash compare T109F05A19…114448 T1301124198C…11444C   # TLSH distance
# 121
rune-fuzzyhash compare 96:koJ37jhe…:koJ3RiFZ… 192:koJ3RiFZ…:T4FZ4CYP…  # ssdeep score
# 97
```

## Conformance

The tests check, without network access:

- TLSH's published unit test (`simple_unittest`): both digests and both
  distances (121 with length, 97 without).
- 34 generated inputs (0 B to 1 MiB, binary and text, with and without
  edits) against digests from the reference TLSH library (`py-tlsh` 4.x)
  and ssdeep 2.14.1, plus pairwise TLSH distances and ssdeep scores,
  including signatures one block size apart.

During development the implementation also matched, with zero
differences: all 80 digests and 3 160 pairwise distances (with and without
length) of TLSH's published `example_data` corpus, ssdeep 2.14.1 digests of
the same corpus, and 1 080 further inputs with 240 edited pairs differential-
tested against both reference implementations.

## License

MIT, except `src/tlsh/tables.rs`, which contains TLSH's Pearson and length
tables, copyright 2010-2014 Trend Micro, used under the BSD-3-Clause
licence (TLSH is offered under Apache-2.0 OR BSD-3-Clause). The full notice
is in that file. The SPDX expression is `MIT AND BSD-3-Clause`.

The ssdeep implementation is written from the published algorithm
(Kornblum 2006, Tridgell's spamsum) and contains no ssdeep code.
