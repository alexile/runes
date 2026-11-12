# rune-lttb

> Largest-Triangle-Three-Buckets downsampling for chart-ready series.

[![crates.io](https://img.shields.io/crates/v/rune-lttb)](https://crates.io/crates/rune-lttb)
[![docs.rs](https://img.shields.io/docsrs/rune-lttb)](https://docs.rs/rune-lttb)
[![license](https://img.shields.io/crates/l/rune-lttb)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Downsamples a large `(x, y)` series to a target point count for charting,
using the LTTB algorithm: within each bucket, keeps the point that forms the
largest triangle area against the previously-kept point and the average of
the next bucket. Preserves visually significant features like spikes far
better than naive decimation. Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-lttb = "0.1"
```

The `rune-lttb` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-lttb --features cli
```

## Usage

```rust
use rune_lttb::{downsample, Point};

let points: Vec<Point> = (0..1000)
    .map(|i| Point { x: i as f64, y: (i as f64).sin() })
    .collect();

let reduced = downsample(&points, 100);
assert_eq!(reduced.len(), 100);
```

## CLI

Reads "x,y" lines from a CSV file (or stdin) and prints the downsampled
series:

```bash
rune-lttb 100 data.csv
cat data.csv | rune-lttb 100 -
```

## Output

```
0,0
12,0.4321
27,0.9998
...
999,0.8268
```

## License

MIT
