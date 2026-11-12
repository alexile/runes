# rune-fnv

> FNV-1 and FNV-1a non-cryptographic hash functions (32 and 64-bit).

[![crates.io](https://img.shields.io/crates/v/rune-fnv)](https://crates.io/crates/rune-fnv)
[![docs.rs](https://img.shields.io/docsrs/rune-fnv)](https://docs.rs/rune-fnv)
[![license](https://img.shields.io/crates/l/rune-fnv)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Fowler–Noll–Vo hash functions used in hash tables, bloom filters, and data
deduplication. Provides both FNV-1 and FNV-1a in 32-bit and 64-bit variants.
Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-fnv = "0.1"
```

The `rune-fnv` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-fnv --features cli
```

## Usage

```rust
use rune_fnv::{fnv1a_32, fnv1a_64};

let h32 = fnv1a_32(b"hello");
let h64 = fnv1a_64(b"hello");
println!("{h32:08x}  {h64:016x}");
```

## CLI

Outputs the FNV-1a 64-bit hash.

```bash
rune-fnv data.bin
cat data.bin | rune-fnv -
```

## Output

```
a430d84680aabd0b  data.bin
```

## License

MIT
