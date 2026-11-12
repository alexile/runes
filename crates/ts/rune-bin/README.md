# rune-bin

> Fixed and adaptive histogram binning for numeric distributions.

[![crates.io](https://img.shields.io/crates/v/rune-bin)](https://crates.io/crates/rune-bin)
[![docs.rs](https://img.shields.io/docsrs/rune-bin)](https://docs.rs/rune-bin)
[![license](https://img.shields.io/crates/l/rune-bin)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Builds histograms two ways: `fixed_bins` (equal-width buckets, the usual
histogram) and `adaptive_bins` (equal-frequency/quantile buckets, so skewed
distributions don't collapse into one overloaded bucket and a row of empty ones).
Pure Rust, no dependencies beyond the optional CLI parser.

## Installation

```toml
[dependencies]
rune-bin = "0.1"
```

The `rune-bin` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-bin --features cli
```

## Usage

```rust
use rune_bin::{fixed_bins, adaptive_bins};

let data = vec![0.0, 1.0, 2.0, 3.0, 100.0];

let fixed = fixed_bins(&data, 5);
let adaptive = adaptive_bins(&data, 5);

assert_eq!(fixed.counts.iter().sum::<usize>(), data.len());
assert_eq!(adaptive.counts.iter().sum::<usize>(), data.len());
```

## CLI

```bash
rune-bin data.txt --bins 10
rune-bin data.txt --bins 10 --adaptive
```

## Output

```
[0.0000, 20.0000): 4
[20.0000, 40.0000): 0
[40.0000, 60.0000): 0
[60.0000, 80.0000): 0
[80.0000, 100.0000): 1
```

## License

MIT
