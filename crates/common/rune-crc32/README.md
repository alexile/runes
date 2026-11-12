# rune-crc32

> CRC-32 checksum for byte slices and files (IEEE 802.3 polynomial).

[![crates.io](https://img.shields.io/crates/v/rune-crc32)](https://crates.io/crates/rune-crc32)
[![docs.rs](https://img.shields.io/docsrs/rune-crc32)](https://docs.rs/rune-crc32)
[![license](https://img.shields.io/crates/l/rune-crc32)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Computes CRC-32 checksums using the IEEE 802.3 polynomial (0xEDB88320) — the
variant used by Ethernet frames, ZIP archives, PNG images, and gzip streams.
Pure Rust, no dependencies, zero unsafe code.

## Installation

```toml
[dependencies]
rune-crc32 = "0.1"
```

The `rune-crc32` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-crc32 --features cli
```

## Usage

```rust
use rune_crc32::{checksum, checksum_hex, checksum_file};

// Byte slice → u32
let crc: u32 = checksum(b"123456789");
assert_eq!(crc, 0xCBF43926);

// Byte slice → hex string
let hex = checksum_hex(b"hello world");
assert_eq!(hex, "0d4a1185");

// File → u32
let file_crc = checksum_file("archive.zip").unwrap();
println!("{file_crc:08x}");
```

## CLI

```bash
rune-crc32 archive.zip          # compute checksum of a file
cat data.bin | rune-crc32 -    # read from stdin
```

## Output

```
cbf43926  test.txt
0d4a1185  hello.txt
```

## License

MIT
