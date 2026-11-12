# rune-morse

> Morse code encoder and decoder — ASCII text to dots and dashes and back.

[![crates.io](https://img.shields.io/crates/v/rune-morse)](https://crates.io/crates/rune-morse)
[![docs.rs](https://img.shields.io/docsrs/rune-morse)](https://docs.rs/rune-morse)
[![license](https://img.shields.io/crates/l/rune-morse)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Converts between ASCII text and International Morse Code. Letters are separated by
a single space; words are separated by ` / `. Both uppercase and lowercase input are
accepted during encoding. Useful for CTF challenges, amateur radio utilities, and
educational tools.

## Installation

```toml
[dependencies]
rune-morse = "0.2"
```

The `rune-morse` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-morse --features cli
```

## Usage

### Library

```rust
use rune_morse::{encode, decode};

let morse = encode("SOS").unwrap();
assert_eq!(morse, "... --- ...");

let text = decode("... --- ...").unwrap();
assert_eq!(text, "SOS");
```

### CLI

```bash
# Encode text to Morse code
rune-morse encode "Hello World"
# .... . .-.. .-.. --- / .-- --- .-. .-.. -..

# Decode Morse code to text
rune-morse decode ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."
# HELLO WORLD
```

## Output

```
$ rune-morse encode "SOS"
... --- ...

$ rune-morse decode "... --- ..."
SOS
```

## License

MIT
