# rune-derivative

> Rate-of-change (derivative) and cumulative (integral) calculation over a series.

[![crates.io](https://img.shields.io/crates/v/rune-derivative)](https://crates.io/crates/rune-derivative)
[![docs.rs](https://img.shields.io/docsrs/rune-derivative)](https://docs.rs/rune-derivative)
[![license](https://img.shields.io/crates/l/rune-derivative)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Computes the rate of change and the trapezoidal-rule integral of a timestamped
`(ts_ms, value)` numeric series. Useful for turning a raw reading stream into a
rate (e.g. speed from odometer readings, power from energy readings) or an
accumulated total (e.g. distance from speed, energy from power). Pure Rust, no
dependencies beyond the optional CLI parser.

## Installation

```toml
[dependencies]
rune-derivative = "0.1"
```

The `rune-derivative` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-derivative --features cli
```

## Usage

```rust
use rune_derivative::{derivative, integral, cumulative_integral};

let points = vec![(0, 0.0), (1000, 1.0), (2000, 2.0)];

let rates = derivative(&points);
assert_eq!(rates.len(), 2);

let total = integral(&points);
let running = cumulative_integral(&points);
assert!((running.last().unwrap().1 - total).abs() < 1e-9);
```

## CLI

```bash
rune-derivative series.csv
```

## Output

```
integral: 2
derivative points: 2
cumulative integral points: 3
```

## License

MIT
