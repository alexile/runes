# rune-correlate

> Cross-correlation and lag detection between two numeric series.

[![crates.io](https://img.shields.io/crates/v/rune-correlate)](https://crates.io/crates/rune-correlate)
[![docs.rs](https://img.shields.io/docsrs/rune-correlate)](https://docs.rs/rune-correlate)
[![license](https://img.shields.io/crates/l/rune-correlate)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Computes the Pearson correlation between two numeric series at every integer
lag within a window, and finds the lag with the strongest correlation —
useful for detecting a delay between two related signals. Pure Rust, no
dependencies beyond the optional CLI parser.

## Installation

```toml
[dependencies]
rune-correlate = "0.1"
```

The `rune-correlate` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-correlate --features cli
```

## Usage

```rust
use rune_correlate::best_lag;

let a = vec![1.0, 4.0, 2.0, 8.0, 5.0, 7.0, 3.0];
let b = vec![-1.0, -1.0, 1.0, 4.0, 2.0, 8.0, 5.0]; // a, delayed by 2 steps
let (lag, corr) = best_lag(&a, &b, 4);
assert_eq!(lag, 2);
```

## CLI

```bash
rune-correlate --max-lag 4 --a 1,4,2,8,5,7,3 --b 0,0,1,4,2,8,5
```

## Output

```
best lag: 2 (correlation: 1.0000)
```

## License

MIT
