# rune-rot13

> ROT13 cipher — rotate ASCII letters by 13 positions.

[![crates.io](https://img.shields.io/crates/v/rune-rot13)](https://crates.io/crates/rune-rot13)
[![docs.rs](https://img.shields.io/docsrs/rune-rot13)](https://docs.rs/rune-rot13)
[![license](https://img.shields.io/crates/l/rune-rot13)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-rot13` encodes and decodes text using the ROT13 substitution cipher, shifting each ASCII letter 13 positions in the alphabet. Non-letter characters — digits, punctuation, whitespace, binary bytes — pass through unchanged. Because 26 ÷ 2 = 13, the same operation encodes and decodes, making it a staple in CTF puzzles and obfuscation tasks.

## Installation

```toml
[dependencies]
rune-rot13 = "0.2"
```

The `rune-rot13` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-rot13 --features cli
```

## Usage

```rust
use rune_rot13::rot13;

let encoded = rot13("Hello, World!");
assert_eq!(encoded, "Uryyb, Jbeyq!");

let decoded = rot13(&encoded);
assert_eq!(decoded, "Hello, World!");
```

## CLI

```bash
rune-rot13 "Hello, World!"          # encode a string
echo "Uryyb, Jbeyq!" | rune-rot13  # decode via stdin
rune-rot13 -f message.txt           # encode a file
```

## Output

```
Uryyb, Jbeyq!
```

## License

MIT
