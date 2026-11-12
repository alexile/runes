# rune-murmur

> MurmurHash3 — pure-Rust, zero-dependency implementation of the 32-bit and 128-bit variants.

[![crates.io](https://img.shields.io/crates/v/rune-murmur)](https://crates.io/crates/rune-murmur)
[![docs.rs](https://img.shields.io/docsrs/rune-murmur)](https://docs.rs/rune-murmur)
[![license](https://img.shields.io/crates/l/rune-murmur)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

MurmurHash3 by Austin Appleby — fast, non-cryptographic hash for hash tables and
checksums. This crate provides both the 32-bit and 128-bit variants, fully
seed-parameterised.

## Installation

```toml
[dependencies]
rune-murmur = "0.2"
```

The `rune-murmur` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-murmur --features cli
```

## Usage

```rust
use rune_murmur::{murmurhash3_x86_32, murmurhash3_x64_128};

let h32 = murmurhash3_x86_32(b"hello world", 0);
println!("{h32:#010x}");

let h128 = murmurhash3_x64_128(b"hello world", 0);
println!("{h128:#034x}");
```

## CLI

```bash
rune-murmur file.bin           # 32-bit hash
rune-murmur --x128 file.bin    # 128-bit hash
echo -n "hello" | rune-murmur -
rune-murmur --seed 42 file.bin
```

## Output

```
248bfa47  hello.txt
```

## License

MIT
