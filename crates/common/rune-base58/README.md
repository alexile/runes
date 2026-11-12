# rune-base58

> Base58 encode and decode — Bitcoin and Flickr alphabets.

[![crates.io](https://img.shields.io/crates/v/rune-base58)](https://crates.io/crates/rune-base58)
[![docs.rs](https://img.shields.io/docsrs/rune-base58)](https://docs.rs/rune-base58)
[![license](https://img.shields.io/crates/l/rune-base58)](LICENSE)

Base58 is the encoding used by Bitcoin addresses, IPFS CIDv0 hashes, and
various other protocols that need short, human-readable, URL-safe
identifiers without visually ambiguous characters (`0`, `O`, `I`, `l`).

| Alphabet | Characters | Used by |
|---|---|---|
| Bitcoin (default) | `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` | Bitcoin, IPFS, Monero |
| Flickr | `123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ` | Flickr short URLs |

- `encode` / `decode` — Bitcoin alphabet
- `encode_flickr` / `decode_flickr` — Flickr alphabet
- `is_base58` — heuristic check for Base58-looking strings

## Installation

```toml
[dependencies]
rune-base58 = "0.1"
```

The `rune-base58` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-base58 --features cli
```

## Usage

```rust
use rune_base58::{encode, decode};

let encoded = encode(b"Hello World");
let decoded = decode(&encoded).unwrap();
assert_eq!(decoded, b"Hello World");
```

## CLI

```bash
rune-base58 encode "hello"
rune-base58 decode "Cn8eVZg"
echo -n "hello" | rune-base58 encode -
```

## License

MIT
