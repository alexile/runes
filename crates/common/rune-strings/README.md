# rune-strings

> Extract printable strings from binary files — configurable minimum length and encoding.

[![crates.io](https://img.shields.io/crates/v/rune-strings)](https://crates.io/crates/rune-strings)
[![docs.rs](https://img.shields.io/docsrs/rune-strings)](https://docs.rs/rune-strings)
[![license](https://img.shields.io/crates/l/rune-strings)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Scans byte slices or files for contiguous runs of printable ASCII characters and
returns each run that meets a configurable minimum length. Security researchers
and CTF players use it to quickly triage firmware images, captured network
traffic, and unknown binary blobs without reaching for external tools.

## Installation

```toml
[dependencies]
rune-strings = "0.2"
```

The `rune-strings` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-strings --features cli
```

## Usage

### Library

```rust
use rune_strings::{extract, extract_default, StringsConfig};

// Zero-config: find all runs of 4+ printable characters
let strings = extract_default(b"\x00\x01hello\x00world\x02\x03hi\x00");
assert_eq!(strings, vec!["hello", "world"]);

// Custom minimum length with byte offsets
let config = StringsConfig { min_length: 8, include_offset: true };
let found = extract(b"\x00short\x00longstring\x00", &config);
assert_eq!(found[0].text, "longstring");
assert_eq!(found[0].offset, 7);
```

### CLI

```bash
rune-strings firmware.bin          # default: minimum length 4
rune-strings firmware.bin -n 8     # minimum length 8
rune-strings firmware.bin -o       # show offsets
cat firmware.bin | rune-strings -  # read from stdin
```

## Output

```
$ rune-strings firmware.bin -o
0x00000010: Copyright (C) 2024 Acme Corp
0x00000040: /lib/ld-linux.so.2
0x00000060: libc.so.6
0x00000070: main
```

## License

MIT
