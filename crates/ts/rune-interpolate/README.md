# rune-interpolate

> Linear and spline interpolation for gap-filling irregular series.

[![crates.io](https://img.shields.io/crates/v/rune-interpolate)](https://crates.io/crates/rune-interpolate)
[![docs.rs](https://img.shields.io/docsrs/rune-interpolate)](https://docs.rs/rune-interpolate)
[![license](https://img.shields.io/crates/l/rune-interpolate)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Interpolates a value at an arbitrary `x` from a set of `(x, y)` points: piecewise
linear, or a natural cubic spline that passes exactly through every input point.
Both are extrapolation-free — querying outside the input range returns `None`.
Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-interpolate = "0.1"
```

The `rune-interpolate` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-interpolate --features cli
```

## Usage

```rust
use rune_interpolate::{linear, cubic_spline};

let points = [(0.0, 0.0), (10.0, 100.0)];
assert_eq!(linear(&points, 5.0), Some(50.0));

let curve = [(0.0, 0.0), (1.0, 2.0), (2.0, 1.0)];
let y = cubic_spline(&curve, 0.5).unwrap();
```

## CLI

```bash
rune-interpolate --points "0,0;5,25;10,100" --at 7 --method linear
```

## Output

```
70
```

## License

MIT
