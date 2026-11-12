# rune-mvt

> Encode and decode Mapbox Vector Tile protobuf.

[![crates.io](https://img.shields.io/crates/v/rune-mvt)](https://crates.io/crates/rune-mvt)
[![docs.rs](https://img.shields.io/docsrs/rune-mvt)](https://docs.rs/rune-mvt)
[![license](https://img.shields.io/crates/l/rune-mvt)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A self-contained Mapbox Vector Tile (MVT v2) encoder: a hand-rolled protobuf
wire-format layer (varints, zigzag deltas, length-delimited fields — no
general-purpose protobuf dependency), MVT's command/parameter geometry
encoding for points, lines, and polygons, and a per-layer key/value tag
dictionary that feature properties are interned into. Pure Rust; the only
dependencies are `thiserror` and the optional CLI parser.

- **Spec-valid output** ([MVT 2.1]): consecutive duplicate vertices are
  dropped, and degenerate features (a line with fewer than two distinct
  vertices, a polygon without a ring of non-zero area) are not added — the
  `add_*_feature` methods return `false` for them. Ring winding and unique
  layer names remain the caller's responsibility.
- **Validating decoder** for untrusted tiles: `decode` checks every length,
  index and geometry command sequence, never panics, and keeps feature
  properties as indices so memory stays linear in the input.
- Tested with the spec's §4.3.5 geometry examples, and encode/decode round-trip
  property tests.

[MVT 2.1]: https://github.com/mapbox/vector-tile-spec/tree/master/2.1

## Installation

```toml
[dependencies]
rune-mvt = "0.1"
```

The `rune-mvt` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-mvt --features cli
```

## Usage

```rust
use rune_mvt::{Layer, Tile, Value};

let mut layer = Layer::new("poi");
layer.add_point_feature(100, 200, &[("name", Value::String("cafe".into()))]);
layer.add_line_feature(&[(0, 0), (100, 0), (100, 100)], &[]);
layer.add_polygon_feature(
    &[vec![(0, 0), (100, 0), (100, 100), (0, 100)]],
    &[("kind", Value::String("building".into()))],
);

let mut tile = Tile::new();
tile.add_layer(layer);
let bytes = tile.encode();

// Decoding (e.g. an untrusted tile) validates the bytes.
let decoded = rune_mvt::decode(&bytes).expect("valid tile");
let layer = &decoded.layers[0];
for feature in &layer.features {
    let props: Vec<_> = layer.properties(feature).collect();
    println!("{:?} {:?} {props:?}", feature.geometry_type, feature.geometry);
}
```

Coordinates are tile-local integers in `0..extent`, per the MVT contract —
projecting real-world coordinates into that grid is the caller's job.

## CLI

```bash
rune-mvt --layer poi --extent 4096 --output tile.mvt 100,200 300,400
```

## Output

```
wrote 27 bytes to tile.mvt
```

## License

MIT
