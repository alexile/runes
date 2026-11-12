# rune-ascii

> ASCII table lookup and character conversion — decimal, hex, octal, binary, and char.

[![crates.io](https://img.shields.io/crates/v/rune-ascii)](https://crates.io/crates/rune-ascii)
[![docs.rs](https://img.shields.io/docsrs/rune-ascii)](https://docs.rs/rune-ascii)
[![license](https://img.shields.io/crates/l/rune-ascii)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-ascii` provides a complete reference for all 128 ASCII code points, including control
character names (NUL, SOH, STX…) and printable character descriptions. Look up any code point
by decimal, hex, octal, binary, or the character itself. Zero dependencies.

## Installation

```toml
[dependencies]
rune-ascii = "0.2"
```

The `rune-ascii` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-ascii --features cli
```

## Usage

```rust
use rune_ascii::{lookup, parse_input};

let entry = lookup(65).unwrap();
assert_eq!(entry.character, 'A');
assert_eq!(entry.hex, "0x41");

let entry = parse_input("0x41").unwrap();
assert_eq!(entry.code, 65);
```

## CLI

```bash
rune-ascii 65          # look up by decimal
rune-ascii 0x41        # look up by hex
rune-ascii 0o101       # look up by octal
rune-ascii 0b01000001  # look up by binary
rune-ascii A           # look up by character
rune-ascii --table     # print the full ASCII table
```

## Output

```
code: 65  hex: 0x41  oct: 0o101  bin: 0b01000001  char: A
```

## License

MIT
