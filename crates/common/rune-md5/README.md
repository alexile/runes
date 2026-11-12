# rune-md5

> Compute MD5 checksums of byte slices and files.

[![crates.io](https://img.shields.io/crates/v/rune-md5)](https://crates.io/crates/rune-md5)
[![docs.rs](https://img.shields.io/docsrs/rune-md5)](https://docs.rs/rune-md5)
[![license](https://img.shields.io/crates/l/rune-md5)](LICENSE)

> **Warning**: MD5 is cryptographically broken and collision-prone. Use only for non-security checksums, legacy interoperability, or CTF work.

## Installation

```toml
[dependencies]
rune-md5 = "0.1"
```

The `rune-md5` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-md5 --features cli
```

## Usage

```rust
use rune_md5::{hash_bytes, hash_file};

let digest = hash_bytes(b"hello world");
assert_eq!(digest, "5eb63bbbe01eeed093cb22bb8f5acdc3");
```

## CLI

```bash
rune-md5 file.bin
cat file | rune-md5 -
```

## License

MIT
