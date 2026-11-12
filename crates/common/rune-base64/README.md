# rune-base64

> Base64 encoder and decoder — standard (RFC 4648) and URL-safe variants.

[![crates.io](https://img.shields.io/crates/v/rune-base64)](https://crates.io/crates/rune-base64)
[![docs.rs](https://img.shields.io/docsrs/rune-base64)](https://docs.rs/rune-base64)
[![license](https://img.shields.io/crates/l/rune-base64)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Encodes and decodes Base64 with no external dependencies, implementing RFC 4648
from scratch. Supports the standard alphabet (`+` `/`) and the URL-safe variant
(`-` `_`), with or without `=` padding. Useful for CTF challenges, JWT
inspection, protocol debugging, and anywhere raw bytes need to pass through
text-only channels.

## Installation

```toml
[dependencies]
rune-base64 = "0.2"
```

The `rune-base64` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-base64 --features cli
```

## Usage

```rust
use rune_base64::{encode, encode_url, encode_no_pad, encode_url_no_pad, decode};

// Standard Base64 with padding
assert_eq!(encode(b"foo"), "Zm9v");
assert_eq!(encode(b"fo"),  "Zm8=");
assert_eq!(encode(b"f"),   "Zg==");

// URL-safe variant
let url_encoded = encode_url(b"hello world");
assert!(!url_encoded.contains('+'));
assert!(!url_encoded.contains('/'));

// No padding
assert_eq!(encode_no_pad(b"f"), "Zg");

// Decode auto-detects standard vs URL-safe alphabet
assert_eq!(decode("Zm9v").unwrap(), b"foo");
```

## CLI

```bash
rune-base64 encode myfile.bin          # standard Base64
rune-base64 encode --url myfile.bin    # URL-safe Base64
rune-base64 encode --no-pad myfile.bin # no = padding
rune-base64 encode --url --no-pad -    # URL-safe, no pad, from stdin
rune-base64 decode encoded.txt         # decode from file
cat data.b64 | rune-base64 decode -    # decode from stdin
```

## Output

```
$ echo -n "hello" | rune-base64 encode -
aGVsbG8=

$ echo -n "aGVsbG8=" | rune-base64 decode -
hello
```

## License

MIT
