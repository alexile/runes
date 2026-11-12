# rune-sha256

> Compute SHA-256 hashes of files and strings.

[![crates.io](https://img.shields.io/crates/v/rune-sha256)](https://crates.io/crates/rune-sha256)
[![docs.rs](https://img.shields.io/docsrs/rune-sha256)](https://docs.rs/rune-sha256)
[![license](https://img.shields.io/crates/l/rune-sha256)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-sha256` computes SHA-256 digests of byte slices and files, returning lowercase hex strings. Ships as both a library and a `rune-sha256` CLI that mimics the output format of `sha256sum`.

## Installation

```toml
[dependencies]
rune-sha256 = "0.1"
```

The `rune-sha256` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-sha256 --features cli
```

## Usage

### Library

```rust
use rune_sha256::{hash_bytes, hash_file};

let digest = hash_bytes(b"hello");
assert_eq!(digest, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

let digest = hash_file("Cargo.toml").unwrap();
println!("{digest}  Cargo.toml");
```

### CLI

```bash
rune-sha256 file.bin
rune-sha256 file1.bin file2.bin
cat file | rune-sha256 -
```

## Output

```
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  hello.txt
```

Two-space separator matches the output of `sha256sum` for easy scripting.

## License

MIT
