# rune-base32

> Base32 encode and decode — RFC 4648 standard and extended hex alphabets.

[![crates.io](https://img.shields.io/crates/v/rune-base32)](https://crates.io/crates/rune-base32)
[![docs.rs](https://img.shields.io/docsrs/rune-base32)](https://docs.rs/rune-base32)
[![license](https://img.shields.io/crates/l/rune-base32)](LICENSE)

Encodes arbitrary bytes to Base32 ASCII and decodes back, with optional
padding. Supports both the standard `A–Z 2–7` alphabet and the extended
hex `0–9 A–V` alphabet used in DNS security (NSEC3) and other protocols.

- `encode` / `decode` — standard alphabet with padding
- `encode_hex` / `decode_hex` — extended hex alphabet
- `encode_no_pad` — standard alphabet without `=` padding
- `is_base32` — heuristic check for Base32-looking strings

## Installation

```toml
[dependencies]
rune-base32 = "0.1"
```

The `rune-base32` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-base32 --features cli
```

## Usage

```rust
use rune_base32::{encode, decode};

let encoded = encode(b"Hello, World!");
assert_eq!(encoded, "JBSWY3DPFQQFO33SNRSCC===");

let decoded = decode(&encoded).unwrap();
assert_eq!(decoded, b"Hello, World!");
```

## CLI

```bash
rune-base32 encode "hello"
echo -n "hello" | rune-base32 encode -
```

## License

MIT
