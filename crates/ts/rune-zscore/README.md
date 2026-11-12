# rune-zscore

> Z-score and IQR-based outlier/anomaly detector.

[![crates.io](https://img.shields.io/crates/v/rune-zscore)](https://crates.io/crates/rune-zscore)
[![docs.rs](https://img.shields.io/docsrs/rune-zscore)](https://docs.rs/rune-zscore)
[![license](https://img.shields.io/crates/l/rune-zscore)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Two independent outlier detectors over a batch of numbers: z-score (points
far from the mean in units of standard deviation) and IQR/Tukey fences
(points outside `[Q1 - 1.5*IQR, Q3 + 1.5*IQR]`, more robust to extreme
values). Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-zscore = "0.1"
```

The `rune-zscore` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-zscore --features cli
```

## Usage

```rust
use rune_zscore::{zscore_outliers, iqr_outliers};

let data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
assert_eq!(zscore_outliers(&data, 1.4), vec![7]);
```

## CLI

```bash
rune-zscore --threshold 1.4 2 4 4 4 5 5 7 9
```

## Output

```
zscore outliers (threshold=1.4): [7]
iqr outliers: []
```

## License

MIT
