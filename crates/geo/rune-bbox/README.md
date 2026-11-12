# rune-bbox

> Bounding-box math: union, intersection, containment, clustering/merge of overlapping boxes.

[![crates.io](https://img.shields.io/crates/v/rune-bbox)](https://crates.io/crates/rune-bbox)
[![docs.rs](https://img.shields.io/docsrs/rune-bbox)](https://docs.rs/rune-bbox)
[![license](https://img.shields.io/crates/l/rune-bbox)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Bounding-box math over `(lat, lon)` boxes: union, intersection, containment
queries, and a fixed-point `merge_overlapping` that collapses chains of
overlapping boxes into their connected-component unions. Boundaries are
inclusive throughout. Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-bbox = "0.1"
```

The `rune-bbox` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-bbox --features cli
```

## Usage

```rust
use rune_bbox::{BBox, union, contains_point};

let a = BBox { min_lat: 0.0, min_lon: 0.0, max_lat: 1.0, max_lon: 1.0 };
let b = BBox { min_lat: 0.5, min_lon: 0.5, max_lat: 1.5, max_lon: 1.5 };

let u = union(&a, &b);
assert!(contains_point(&u, 0.75, 0.75));
```

## CLI

```bash
rune-bbox union 0,0,1,1 0.5,0.5,1.5,1.5
rune-bbox merge 0,0,1,1 0.9,0.9,2,2 1.9,1.9,3,3
```

## Output

```
0,0,1.5,1.5
```

## License

MIT
