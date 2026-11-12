# rune-sha1

> Compute SHA-1 hashes of byte slices and files.

[![crates.io](https://img.shields.io/crates/v/rune-sha1)](https://crates.io/crates/rune-sha1)
[![docs.rs](https://img.shields.io/docsrs/rune-sha1)](https://docs.rs/rune-sha1)
[![license](https://img.shields.io/crates/l/rune-sha1)](LICENSE)

> **Warning**: SHA-1 is cryptographically broken. Use only for legacy interoperability or CTF work — never for security-sensitive applications.

## Installation

```toml
[dependencies]
rune-sha1 = "0.1"
```

The `rune-sha1` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-sha1 --features cli
```

## Usage

```rust
use rune_sha1::{hash_bytes, hash_file};

let digest = hash_bytes(b"hello world");
assert_eq!(digest, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
```

## CLI

```bash
rune-sha1 file.bin
cat file | rune-sha1 -
```

## License

MIT
