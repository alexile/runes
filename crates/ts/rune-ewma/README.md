# rune-ewma

> Exponentially weighted moving average over a numeric stream.

[![crates.io](https://img.shields.io/crates/v/rune-ewma)](https://crates.io/crates/rune-ewma)
[![docs.rs](https://img.shields.io/docsrs/rune-ewma)](https://docs.rs/rune-ewma)
[![license](https://img.shields.io/crates/l/rune-ewma)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

An incremental, O(1)-per-update exponentially weighted moving average. Gives
more weight to recent observations without keeping a window of past values
around. Includes a `span`-to-`alpha` conversion matching the pandas
`.ewm(span=...)` convention. Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-ewma = "0.1"
```

The `rune-ewma` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-ewma --features cli
```

## Usage

```rust
use rune_ewma::Ewma;

let mut ewma = Ewma::new(0.5);
assert_eq!(ewma.update(10.0), 10.0);
assert_eq!(ewma.update(20.0), 15.0);
```

## CLI

```bash
rune-ewma 0.3 10 12 11 15 20
```

## Output

```
10.000000
10.600000
10.720000
12.204000
14.542800
```

## License

MIT
