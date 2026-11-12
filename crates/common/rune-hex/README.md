# rune-hex

> Hex encoding and decoding for byte slices and files.

[![crates.io](https://img.shields.io/crates/v/rune-hex)](https://crates.io/crates/rune-hex)
[![docs.rs](https://img.shields.io/docsrs/rune-hex)](https://docs.rs/rune-hex)
[![license](https://img.shields.io/crates/l/rune-hex)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Converts between raw bytes and hexadecimal strings. Decoding accepts lowercase,
uppercase, mixed-case, and optional `0x` prefix. The library has zero dependencies.

## Installation

```toml
[dependencies]
rune-hex = "0.2"
```

The `rune-hex` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-hex --features cli
```

## Usage

### Library

```rust
use rune_hex::{encode, encode_upper, decode};

assert_eq!(encode(b"\xde\xad\xbe\xef"),       "deadbeef");
assert_eq!(encode_upper(b"\xde\xad\xbe\xef"), "DEADBEEF");

assert_eq!(decode("deadbeef").unwrap(), b"\xde\xad\xbe\xef");
assert_eq!(decode("DEADBEEF").unwrap(), b"\xde\xad\xbe\xef");
assert_eq!(decode("0xDeAdBeEf").unwrap(), b"\xde\xad\xbe\xef");
```

### CLI

```bash
# Encode a file
rune-hex encode firmware.bin

# Encode stdin
echo -n "hello" | rune-hex encode
# 68656c6c6f

# Uppercase output
echo -n "hello" | rune-hex encode --upper
# 68656C6C6F

# Decode hex to raw bytes
rune-hex decode deadbeef > out.bin

# Decode from stdin
echo "68656c6c6f" | rune-hex decode
# hello

# Decode with 0x prefix
rune-hex decode 0xdeadbeef > out.bin
```

## License

MIT
