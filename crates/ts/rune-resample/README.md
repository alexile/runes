# rune-resample

> Resample an irregular timestamped series to a fixed interval.

[![crates.io](https://img.shields.io/crates/v/rune-resample)](https://crates.io/crates/rune-resample)
[![docs.rs](https://img.shields.io/docsrs/rune-resample)](https://docs.rs/rune-resample)
[![license](https://img.shields.io/crates/l/rune-resample)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Converts an irregularly-sampled `(timestamp_ms, value)` series into an evenly
spaced grid, filling each grid point via linear interpolation, previous-value
step-hold, or next-value step-hold. Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-resample = "0.1"
```

The `rune-resample` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-resample --features cli
```

## Usage

```rust
use rune_resample::{resample, resample_with, FillMethod};

let points = [(0, 0.0), (3000, 30.0)];
assert_eq!(resample(&points, 1000), vec![(0, 0.0), (1000, 10.0), (2000, 20.0), (3000, 30.0)]);

let stepped = resample_with(&points, 1000, FillMethod::PreviousValue);
```

## CLI

```bash
rune-resample --points "0,0;1000,10;3000,30" --interval-ms 1000
```

## Output

```
0,0
1000,10
2000,20
3000,30
```

## License

MIT
