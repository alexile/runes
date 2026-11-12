# rune-blake3

> Compute BLAKE3 hashes of byte slices and files — faster than SHA-256 and cryptographically secure.

[![crates.io](https://img.shields.io/crates/v/rune-blake3)](https://crates.io/crates/rune-blake3)
[![docs.rs](https://img.shields.io/docsrs/rune-blake3)](https://docs.rs/rune-blake3)
[![license](https://img.shields.io/crates/l/rune-blake3)](LICENSE)

## Installation

```toml
[dependencies]
rune-blake3 = "0.1"
```

The `rune-blake3` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-blake3 --features cli
```

## Usage

```rust
use rune_blake3::{hash_bytes, hash_file};

let digest = hash_bytes(b"hello world");
assert_eq!(digest, "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");

let digest = hash_file("Cargo.toml").unwrap();
println!("{digest}  Cargo.toml");
```

## CLI

```bash
rune-blake3 file.bin
cat file | rune-blake3 -
```

## License

MIT
