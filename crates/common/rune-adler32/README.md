# rune-adler32

> Adler-32 checksum for byte slices and files (RFC 1950 / zlib).

[![crates.io](https://img.shields.io/crates/v/rune-adler32)](https://crates.io/crates/rune-adler32)
[![docs.rs](https://img.shields.io/docsrs/rune-adler32)](https://docs.rs/rune-adler32)
[![license](https://img.shields.io/crates/l/rune-adler32)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Computes Adler-32 checksums per RFC 1950. Used internally by zlib, PNG, and
other compression formats. Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-adler32 = "0.1"
```

The `rune-adler32` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-adler32 --features cli
```

## Usage

```rust
use rune_adler32::{checksum, checksum_hex, checksum_file};

let adler = checksum(b"Wikipedia");
assert_eq!(adler, 0x11E60398);

let hex = checksum_hex(b"Wikipedia");
assert_eq!(hex, "11e60398");
```

## CLI

```bash
rune-adler32 archive.zlib
cat data.bin | rune-adler32 -
```

## Output

```
11e60398  data.bin
```

## License

MIT
