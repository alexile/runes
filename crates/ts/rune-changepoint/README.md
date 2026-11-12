# rune-changepoint

> CUSUM-style changepoint detection over a numeric series.

[![crates.io](https://img.shields.io/crates/v/rune-changepoint)](https://crates.io/crates/rune-changepoint)
[![docs.rs](https://img.shields.io/docsrs/rune-changepoint)](https://docs.rs/rune-changepoint)
[![license](https://img.shields.io/crates/l/rune-changepoint)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A classic two-sided CUSUM (cumulative sum) control chart: two running
accumulators track sustained drift above or below a target value, with a
drift allowance to keep ordinary noise from triggering false signals. Both
an incremental `Cusum` accumulator and a batch `detect` function are
provided. Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-changepoint = "0.1"
```

The `rune-changepoint` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-changepoint --features cli
```

## Usage

```rust
use rune_changepoint::{detect, ChangeDirection};

let data = [0.0, 0.0, 0.0, 3.0, 3.0, 3.0, 3.0];
let changes = detect(&data, 0.0, 5.0, 0.5);
assert_eq!(changes[0].1, ChangeDirection::Up);
```

## CLI

```bash
rune-changepoint --target 0 --threshold 5 --drift 0.5 0 0 0 3 3 3 3
```

## Output

```
5: Up
```

## License

MIT
