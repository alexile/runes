# rune-url-encode

> URL percent-encoding and decoding for byte slices and strings.

[![crates.io](https://img.shields.io/crates/v/rune-url-encode)](https://crates.io/crates/rune-url-encode)
[![docs.rs](https://img.shields.io/docsrs/rune-url-encode)](https://docs.rs/rune-url-encode)
[![license](https://img.shields.io/crates/l/rune-url-encode)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Encodes strings as percent-encoded (`%XX`) sequences and decodes them back.
Uses the RFC 3986 unreserved character set — all other bytes are escaped.
Decoding also accepts `+` as a space (application/x-www-form-urlencoded).

## Installation

```toml
[dependencies]
rune-url-encode = "0.2"
```

The `rune-url-encode` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-url-encode --features cli
```

## Usage

```rust
use rune_url_encode::{encode, decode};

let encoded = encode("hello world/path?q=1");
assert_eq!(encoded, "hello%20world%2Fpath%3Fq%3D1");

let decoded = decode(&encoded).unwrap();
assert_eq!(decoded, "hello world/path?q=1");
```

## CLI

```bash
rune-url-encode "hello world"       # encode
rune-url-encode -d "hello%20world"  # decode
echo "hello world" | rune-url-encode -  # stdin
```

## Output

```
hello%20world
```

## License

MIT
