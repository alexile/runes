# rune-map-match

> Snap a noisy position stream onto the nearest edges of a supplied road/path graph.

[![crates.io](https://img.shields.io/crates/v/rune-map-match)](https://crates.io/crates/rune-map-match)
[![docs.rs](https://img.shields.io/docsrs/rune-map-match)](https://docs.rs/rune-map-match)
[![license](https://img.shields.io/crates/l/rune-map-match)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Snaps noisy positions onto the nearest edge of a small planar graph: perpendicular
projection onto each candidate segment (clamped to the segment, never
extrapolated), brute-force nearest-edge search per point, and a trace-level
convenience that applies it across a whole recorded path. Pure Rust, no
dependencies beyond `serde`/`clap` for the optional CLI.

## Installation

```toml
[dependencies]
rune-map-match = "0.1"
```

The `rune-map-match` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-map-match --features cli
```

## Usage

```rust
use rune_map_match::{Edge, match_point};

let edges = vec![
    Edge { id: 0, from: (0.0, 0.0), to: (10.0, 0.0) },
    Edge { id: 1, from: (0.0, 5.0), to: (10.0, 5.0) },
];

let (edge_id, snapped) = match_point((3.0, 1.0), &edges).unwrap();
assert_eq!(edge_id, 0);
assert_eq!(snapped, (3.0, 0.0));
```

## CLI

```bash
rune-map-match edges.json trace.json
```

`edges.json`: `[{"id":0,"from":[0.0,0.0],"to":[10.0,0.0]}, ...]`
`trace.json`: `[[1.0,1.0], [5.0,-1.0], ...]`

## Output

```
0: edge 0 -> (3.0000, 0.0000)
1: edge 0 -> (5.0000, 0.0000)
```

## License

MIT
