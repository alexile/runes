# rune-geo-cluster

> Spatial clustering of point sets (thin geo-domain wrapper over the existing `ml` clustering crates).

[![crates.io](https://img.shields.io/crates/v/rune-geo-cluster)](https://crates.io/crates/rune-geo-cluster)
[![docs.rs](https://img.shields.io/docsrs/rune-geo-cluster)](https://docs.rs/rune-geo-cluster)
[![license](https://img.shields.io/crates/l/rune-geo-cluster)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A geo-domain-flavored wrapper around the general-purpose `rune-kmeans` and
`rune-hdbscan` clustering crates. Instead of building a raw `Vec<Vec<f64>>`
row per point, pass `&[(f64, f64)]` lat/lon pairs directly and get back a
label per point. All clustering math is delegated to the wrapped crates —
this crate is deliberately thin.

## Installation

```toml
[dependencies]
rune-geo-cluster = "0.1"
```

The `rune-geo-cluster` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-geo-cluster --features cli
```

## Usage

```rust
use rune_geo_cluster::{cluster_kmeans, cluster_hdbscan};

let points = [
    (60.170, 24.938), (60.171, 24.939), (60.169, 24.937),
    (60.451, 22.267), (60.452, 22.266), (60.450, 22.268),
];

let labels = cluster_kmeans(&points, 2);
let hdb_labels = cluster_hdbscan(&points, 3);
```

## CLI

```bash
rune-geo-cluster points.csv --method kmeans --k 3
rune-geo-cluster points.csv --method hdbscan --min-cluster-size 5
```

## Output

```
{"lat":60.170,"lon":24.938,"label":0}
{"lat":60.171,"lon":24.939,"label":0}
{"lat":60.451,"lon":22.267,"label":1}
```

## License

MIT
