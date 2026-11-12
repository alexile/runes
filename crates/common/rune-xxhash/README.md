# rune-xxhash

> xxHash (xxh32 / xxh64) — extremely fast non-cryptographic hash, pure Rust.

[![crates.io](https://img.shields.io/crates/v/rune-xxhash)](https://crates.io/crates/rune-xxhash)
[![docs.rs](https://img.shields.io/docsrs/rune-xxhash)](https://docs.rs/rune-xxhash)
[![license](https://img.shields.io/crates/l/rune-xxhash)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

xxHash by Yann Collet — the hash function powering LZ4, RocksDB bloom filters, and
ClickHouse checksums. This crate provides xxh32 and xxh64, fully seed-parameterised,
with zero dependencies.

## Installation

```toml
[dependencies]
rune-xxhash = "0.2"
```

The `rune-xxhash` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-xxhash --features cli
```

## Usage

```rust
use rune_xxhash::{xxh32, xxh64};

let h32 = xxh32(b"hello world", 0);
println!("{h32:#010x}");

let h64 = xxh64(b"hello world", 0);
println!("{h64:#018x}");
```

## CLI

```bash
rune-xxhash file.bin           # xxh64 (default)
rune-xxhash --x32 file.bin     # xxh32
echo -n "hello" | rune-xxhash -
rune-xxhash --seed 42 file.bin
```

## Output

```
ef46db3751d8e999  hello.txt
```

## License

MIT
