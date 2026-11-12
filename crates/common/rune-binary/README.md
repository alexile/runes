# rune-binary

> Binary (01010101) representation encoder and decoder.

[![crates.io](https://img.shields.io/crates/v/rune-binary)](https://crates.io/crates/rune-binary)
[![docs.rs](https://img.shields.io/docsrs/rune-binary)](https://docs.rs/rune-binary)
[![license](https://img.shields.io/crates/l/rune-binary)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Converts raw bytes to their 8-bit binary string representation and back.
Security researchers and CTF players use it to inspect data at the bit level,
analyze binary protocols, and verify bit manipulation results.

## Installation

```toml
[dependencies]
rune-binary = "0.2"
```

The `rune-binary` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-binary --features cli
```

## Usage

```rust
use rune_binary::{encode, encode_compact, decode};

// Space-separated: one group of 8 bits per byte
assert_eq!(encode(b"AB"), "01000001 01000010");

// Compact: all bits joined together
assert_eq!(encode_compact(b"AB"), "0100000101000010");

// Both forms decode identically
assert_eq!(decode("01000001 01000010").unwrap(), b"AB");
assert_eq!(decode("0100000101000010").unwrap(), b"AB");
```

## CLI

```bash
rune-binary encode myfile.bin        # encode a file
echo -n "AB" | rune-binary encode -  # encode from stdin
rune-binary decode "01000001"        # decode a literal string
rune-binary decode encoded.txt       # decode from file
cat bits.txt | rune-binary decode -  # decode from stdin
```

## Output

```
$ echo -n "Hi" | rune-binary encode -
01001000 01101001
```

## License

MIT
