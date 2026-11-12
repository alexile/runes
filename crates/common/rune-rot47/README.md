# rune-rot47

> ROT47 cipher — rotate printable ASCII characters by 47 positions.

[![crates.io](https://img.shields.io/crates/v/rune-rot47)](https://crates.io/crates/rune-rot47)
[![docs.rs](https://img.shields.io/docsrs/rune-rot47)](https://docs.rs/rune-rot47)
[![license](https://img.shields.io/crates/l/rune-rot47)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-rot47` encodes and decodes text using the ROT47 substitution cipher, rotating every printable ASCII character (bytes 33–126) by 47 positions within that 94-character window. Unlike ROT13, ROT47 scrambles digits and punctuation as well as letters, making it more thorough for obfuscation tasks and CTF challenges. Bytes outside the printable range pass through unchanged. Applying the cipher twice returns the original input.

## Installation

```toml
[dependencies]
rune-rot47 = "0.2"
```

The `rune-rot47` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-rot47 --features cli
```

## Usage

```rust
use rune_rot47::rot47;

let encoded = rot47("Hello, World!");
assert_eq!(encoded, "w6==@[ (@C=5P");

let decoded = rot47(&encoded);
assert_eq!(decoded, "Hello, World!");
```

## CLI

```bash
rune-rot47 "Hello, World!"          # encode a string
echo "w6==@[ (@C=5P" | rune-rot47  # decode via stdin
rune-rot47 -f message.txt           # encode a file
```

## Output

```
w6==@[ (@C=5P
```

## License

MIT
