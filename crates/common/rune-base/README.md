# rune-base

> Encode and decode bytes in any base using a caller-supplied alphabet.

[![crates.io](https://img.shields.io/crates/v/rune-base)](https://crates.io/crates/rune-base)
[![docs.rs](https://img.shields.io/docsrs/rune-base)](https://docs.rs/rune-base)
[![license](https://img.shields.io/crates/l/rune-base)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-base` converts bytes to and from a positional numeral string in any base from 2 to 256.
The base is determined entirely by the length of the alphabet you provide — no configuration
enum, no hardcoded radix. Pass `b"01"` for binary, `b"0123456789abcdef"` for hex, or any
custom symbol set you need.

## Installation

```toml
[dependencies]
rune-base = "0.3"
```

The `rune-base` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-base --features cli
```

## Usage

```rust
use rune_base::{encode, decode};

// Base 16 with a lowercase hex alphabet
let encoded = encode(b"hi", b"0123456789abcdef").unwrap();
assert_eq!(encoded, "6869");

let decoded = decode(&encoded, b"0123456789abcdef").unwrap();
assert_eq!(decoded, b"hi");
```

## CLI

```bash
# Encode a file or stdin
rune-base encode --alphabet "0123456789abcdef" myfile.bin
cat file.bin | rune-base encode --alphabet "01" -

# Decode from a file or stdin
rune-base decode --alphabet "0123456789abcdef" encoded.txt
echo -n "6869" | rune-base decode --alphabet "0123456789abcdef" -
```

## Output

```
$ echo -n "hi" | rune-base encode --alphabet "0123456789abcdef" -
6869
$ echo -n "6869" | rune-base decode --alphabet "0123456789abcdef" -
hi
```

## License

MIT
