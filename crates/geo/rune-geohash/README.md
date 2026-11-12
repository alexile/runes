# rune-geohash

> Geohash encode/decode.

[![crates.io](https://img.shields.io/crates/v/rune-geohash)](https://crates.io/crates/rune-geohash)
[![docs.rs](https://img.shields.io/docsrs/rune-geohash)](https://docs.rs/rune-geohash)
[![license](https://img.shields.io/crates/l/rune-geohash)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Encodes and decodes standard base32 geohashes: interleaved-bit latitude/longitude
cell encoding. Pure Rust, no dependencies beyond the optional CLI parser.

## Installation

```toml
[dependencies]
rune-geohash = "0.1"
```

The `rune-geohash` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-geohash --features cli
```

## Usage

```rust
use rune_geohash::{encode, decode, decode_bounds};

let hash = encode(57.64911, 10.40744, 9);
let (lat, lon) = decode(&hash)?;
let (min_lat, min_lon, max_lat, max_lon) = decode_bounds(&hash)?;
```

## CLI

```bash
rune-geohash encode 57.64911 10.40744 6
rune-geohash decode u4pruydqq
```

## Output

```
u4pruy
57.649109 10.407438
```

## License

MIT
