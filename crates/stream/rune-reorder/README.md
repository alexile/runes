# rune-reorder

> Windowed reordering buffer for out-of-sequence timestamped/sequenced items.

[![crates.io](https://img.shields.io/crates/v/rune-reorder)](https://crates.io/crates/rune-reorder)
[![docs.rs](https://img.shields.io/docsrs/rune-reorder)](https://docs.rs/rune-reorder)
[![license](https://img.shields.io/crates/l/rune-reorder)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Buffers sequence-numbered items and releases them once the run starting at
the next expected sequence number is contiguous. If a gap never fills — a
genuinely lost item — the buffer force-advances past it once it holds more
than `window` entries, rather than stalling forever. Pure Rust, no
dependencies beyond the CLI's argument parser.

## Installation

```toml
[dependencies]
rune-reorder = "0.1"
```

The `rune-reorder` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-reorder --features cli
```

## Usage

```rust
use rune_reorder::Reorder;

let mut reorder = Reorder::new(4);
assert_eq!(reorder.push(1, "b"), Vec::<&str>::new());
assert_eq!(reorder.push(0, "a"), vec!["a", "b"]);
```

## CLI

Reads `"<seq> <text>"` lines from stdin and prints items in sequence order:

```bash
printf '1 b\n0 a\n2 c\n' | rune-reorder --window 8
```

## Output

```
a
b
c
```

## License

MIT
