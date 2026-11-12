# rune-atbash

> Atbash cipher — reverse-alphabet substitution for Latin letters.

[![crates.io](https://img.shields.io/crates/v/rune-atbash)](https://crates.io/crates/rune-atbash)
[![docs.rs](https://img.shields.io/docsrs/rune-atbash)](https://docs.rs/rune-atbash)
[![license](https://img.shields.io/crates/l/rune-atbash)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-atbash` encodes and decodes text using the Atbash substitution cipher, mapping each Latin letter to its mirror in the alphabet: A↔Z, B↔Y, C↔X, and so on. Case is preserved; non-letter bytes pass through unchanged. Originally a Hebrew cipher, Atbash appears frequently in CTF challenges, historical texts, and cryptography exercises. Because the mapping is symmetric, the same operation encodes and decodes.

## Installation

```toml
[dependencies]
rune-atbash = "0.2"
```

The `rune-atbash` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-atbash --features cli
```

## Usage

```rust
use rune_atbash::atbash;

let encoded = atbash("Hello, World!");
assert_eq!(encoded, "Svool, Dliow!");

let decoded = atbash(&encoded);
assert_eq!(decoded, "Hello, World!");
```

## CLI

```bash
rune-atbash "Hello, World!"          # encode a string
echo "Svool, Dliow!" | rune-atbash  # decode via stdin
rune-atbash -f message.txt           # encode a file
```

## Output

```
Svool, Dliow!
```

## License

MIT
