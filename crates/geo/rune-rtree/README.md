# rune-rtree

> R-tree spatial index for fast nearest-neighbor and range queries over points.

[![crates.io](https://img.shields.io/crates/v/rune-rtree)](https://crates.io/crates/rune-rtree)
[![docs.rs](https://img.shields.io/docsrs/rune-rtree)](https://docs.rs/rune-rtree)
[![license](https://img.shields.io/crates/l/rune-rtree)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A from-scratch, dependency-free 2D R-tree. Stores `(f64, f64)` points with
an associated generic payload, and supports incremental insertion, bounding
box range queries, and exact k-nearest-neighbor search via branch-and-bound
pruning. Deletion is out of scope by design — this index is built and grown,
then queried.

## Installation

```toml
[dependencies]
rune-rtree = "0.1"
```

The `rune-rtree` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-rtree --features cli
```

## Usage

```rust
use rune_rtree::{RTree, BBox};

let mut tree = RTree::new();
tree.insert((0.0, 0.0), "origin");
tree.insert((1.0, 1.0), "near");
tree.insert((10.0, 10.0), "far");

let in_range = tree.range(BBox::new(-0.5, -0.5, 2.0, 2.0));
let nearest = tree.nearest((0.1, 0.1), 1);
```

## CLI

```bash
rune-rtree points.csv --range 0.0 0.0 5.0 5.0
rune-rtree points.csv --nearest 1.0 1.0 --k 3
```

## Output

```
{"x":0.0,"y":0.0,"id":0,"distance":1.4142135623730951}
{"x":1.0,"y":1.0,"id":1,"distance":0.0}
```

## License

MIT
