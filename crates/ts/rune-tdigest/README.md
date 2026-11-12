# rune-tdigest

> Streaming quantile/percentile estimator (t-digest-style) for large or unbounded series.

[![crates.io](https://img.shields.io/crates/v/rune-tdigest)](https://crates.io/crates/rune-tdigest)
[![docs.rs](https://img.shields.io/docsrs/rune-tdigest)](https://docs.rs/rune-tdigest)
[![license](https://img.shields.io/crates/l/rune-tdigest)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A simplified t-digest-style quantile estimator: feed values in one at a time,
query any quantile back out, with internal centroid count bounded by a
`compression` parameter rather than growing with the number of values seen.
Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-tdigest = "0.1"
```

The `rune-tdigest` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-tdigest --features cli
```

## Usage

```rust
use rune_tdigest::TDigest;

let mut digest = TDigest::new(100.0);
for i in 0..=1000 {
    digest.add(i as f64);
}
let median = digest.quantile(0.5);
assert!((median - 500.0).abs() < 20.0);
```

## CLI

```bash
rune-tdigest --values "1,2,3,4,5,6,7,8,9,10" --quantile 0.5
```

## Output

```
5.5
```

## License

MIT
