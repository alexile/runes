# rune-simplify

> Douglas-Peucker line simplification for coordinate paths.

[![crates.io](https://img.shields.io/crates/v/rune-simplify)](https://crates.io/crates/rune-simplify)
[![docs.rs](https://img.shields.io/docsrs/rune-simplify)](https://docs.rs/rune-simplify)
[![license](https://img.shields.io/crates/l/rune-simplify)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Reduces the number of points in a polyline while preserving its overall
shape, via the standard Douglas-Peucker algorithm: recursively keeps the
point with the maximum perpendicular distance from the line segment between
the current endpoints, as long as that distance exceeds a tolerance
(`epsilon`), discarding everything in between otherwise. Pure Rust, no
dependencies beyond the optional CLI parser and JSON I/O.

## Installation

```toml
[dependencies]
rune-simplify = "0.1"
```

The `rune-simplify` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-simplify --features cli
```

## Usage

```rust
use rune_simplify::simplify;

let path = [(0.0, 0.0), (5.0, 0.01), (10.0, 0.0)];
let simplified = simplify(&path, 1.0);
assert_eq!(simplified, vec![(0.0, 0.0), (10.0, 0.0)]);
```

## CLI

```bash
rune-simplify --epsilon 0.5 points.json
```

Where `points.json` is a JSON array of `[x, y]` pairs:

```json
[[0.0, 0.0], [5.0, 0.01], [10.0, 0.0]]
```

## Output

```
[[0.0,0.0],[10.0,0.0]]
```

## License

MIT
