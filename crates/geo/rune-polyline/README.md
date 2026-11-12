# rune-polyline

> Google polyline algorithm encode/decode.

[![crates.io](https://img.shields.io/crates/v/rune-polyline)](https://crates.io/crates/rune-polyline)
[![docs.rs](https://img.shields.io/docsrs/rune-polyline)](https://docs.rs/rune-polyline)
[![license](https://img.shields.io/crates/l/rune-polyline)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Encodes and decodes the Google Encoded Polyline Algorithm Format — the compact
ASCII representation used by Google Maps' static/directions APIs and widely
supported elsewhere. Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-polyline = "0.1"
```

The `rune-polyline` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-polyline --features cli
```

## Usage

```rust
use rune_polyline::{decode, encode};

let points = vec![(38.5, -120.2), (40.7, -120.95), (43.252, -126.453)];
let encoded = encode(&points);
assert_eq!(encoded, "_p~iF~ps|U_ulLnnqC_mqNvxq`@");

let decoded = decode(&encoded);
assert_eq!(decoded.len(), 3);
```

`decode` is lenient: it stops at the first malformed or truncated value and
returns the points before it. `try_decode` rejects malformed input with a
`PolylineError` instead; the CLI uses it.

## CLI

```bash
rune-polyline encode 38.5,-120.2 40.7,-120.95
rune-polyline decode '_p~iF~ps|U_ulLnnqC_mqNvxq`@'
```

## Output

```
_p~iF~ps|U_ulLnnqC
```

## License

MIT
