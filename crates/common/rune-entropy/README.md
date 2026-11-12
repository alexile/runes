# rune-entropy

> Shannon entropy calculator for files and byte streams.

[![crates.io](https://img.shields.io/crates/v/rune-entropy)](https://crates.io/crates/rune-entropy)
[![docs.rs](https://img.shields.io/docsrs/rune-entropy)](https://docs.rs/rune-entropy)
[![license](https://img.shields.io/crates/l/rune-entropy)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Entropy measures how random a sequence of bytes is, on a scale from `0.0`
(perfectly uniform, e.g. a file of all-zero bytes) to `8.0` (maximum
randomness, e.g. encrypted or compressed data). It is a fast, dependency-free
way to triage files during malware analysis, CTF challenges, or forensics work.

| Entropy range | Meaning             |
|---------------|---------------------|
| 0.0 – 2.9     | Plaintext           |
| 3.0 – 4.9     | Structured data     |
| 5.0 – 6.9     | Compressed / code   |
| 7.0 – 8.0     | Encrypted / random  |

## Installation

```toml
[dependencies]
rune-entropy = "0.3"
```

The `rune-entropy` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-entropy --features cli
```

## Usage

### Library

```rust
use rune_entropy::{entropy, classify, file_entropy, block_entropy};
use std::path::Path;

// From a byte slice
let score = entropy(b"hello world");
println!("{score:.4} — {}", classify(score));

// From a file
let score = file_entropy(Path::new("suspicious.bin"))?;
println!("{score:.4} — {}", classify(score));

// Per-block analysis — detect partially-encrypted regions
let data = std::fs::read("firmware.bin")?;
for (i, score) in block_entropy(&data, 512).iter().enumerate() {
    println!("block {i:>4} @ +{:#08x}  {score:.4}  {}", i * 512, classify(*score));
}
```

### CLI

```bash
# Single file — detailed output
rune-entropy suspicious.bin

# Multiple files — tabular output
rune-entropy *.bin

# Per-block analysis
rune-entropy --block-size 512 firmware.bin

# From stdin
cat data.bin | rune-entropy -
```

## Output

```
file:     suspicious.bin
entropy:  7.9518 / 8.0  [####################]  encrypted/random
```

```
7.9518  [####################]   encrypted/random  suspicious.bin
4.7382  [############........]       structured  config.toml
3.0221  [########............]       structured  notes.txt
```

Per-block (`--block-size 512`):

```
firmware.bin
       0  7.9128  [####################]  encrypted/random
     512  7.8941  [####################]  encrypted/random
    1024  3.1044  [########............]  structured
    1536  0.0000  [....................]  plaintext
```

> [!TIP]
> Scores above `7.0` on a non-media file are a strong signal of encryption,
> packing, or compression — worth investigating further.

## License

MIT
