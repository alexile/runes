# rune-sha512

> Compute SHA-512 hashes of byte slices and files.

[![crates.io](https://img.shields.io/crates/v/rune-sha512)](https://crates.io/crates/rune-sha512)
[![docs.rs](https://img.shields.io/docsrs/rune-sha512)](https://docs.rs/rune-sha512)
[![license](https://img.shields.io/crates/l/rune-sha512)](LICENSE)

## Installation

```toml
[dependencies]
rune-sha512 = "0.1"
```

The `rune-sha512` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-sha512 --features cli
```

## Usage

```rust
use rune_sha512::{hash_bytes, hash_file};

let digest = hash_bytes(b"hello world");
assert_eq!(digest.len(), 128);

let digest = hash_file("Cargo.toml").unwrap();
println!("{digest}  Cargo.toml");
```

## CLI

```bash
rune-sha512 file.bin
cat file | rune-sha512 -
```

## License

MIT
