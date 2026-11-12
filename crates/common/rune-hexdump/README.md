# rune-hexdump

> Hex dump with ASCII sidebar — inspect binary files like xxd.

[![crates.io](https://img.shields.io/crates/v/rune-hexdump)](https://crates.io/crates/rune-hexdump)
[![docs.rs](https://img.shields.io/docsrs/rune-hexdump)](https://docs.rs/rune-hexdump)
[![license](https://img.shields.io/crates/l/rune-hexdump)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-hexdump` formats arbitrary byte slices as a human-readable hex dump compatible with the
familiar `xxd` layout: byte offset, hex values in blocks of eight, and an ASCII sidebar where
printable bytes are shown as-is and non-printable bytes appear as `.`. Zero dependencies.

## Installation

```toml
[dependencies]
rune-hexdump = "0.2"
```

The `rune-hexdump` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-hexdump --features cli
```

## Usage

```rust
use rune_hexdump::hexdump_default;

let output = hexdump_default(b"hello, world!\n");
assert!(output.starts_with("00000000"));
assert!(output.contains("|hello, world!.|"));
```

Configure the output with `HexdumpConfig`:

```rust
use rune_hexdump::{hexdump, HexdumpConfig};

let config = HexdumpConfig { cols: 8, upper: true, ..Default::default() };
let output = hexdump(b"hello", &config);
println!("{output}");
```

## CLI

```bash
rune-hexdump myfile.bin              # dump a file
cat myfile.bin | rune-hexdump -      # read from stdin
rune-hexdump myfile.bin --cols 8     # 8 bytes per row
rune-hexdump myfile.bin --upper      # uppercase hex
```

## Output

```
00000000  68 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 0a      |hello, world!.|
```

## License

MIT
