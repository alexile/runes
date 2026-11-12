# rune-static-map

> Build static-map image request parameters/URLs from a set of features.

[![crates.io](https://img.shields.io/crates/v/rune-static-map)](https://crates.io/crates/rune-static-map)
[![docs.rs](https://img.shields.io/docsrs/rune-static-map)](https://docs.rs/rune-static-map)
[![license](https://img.shields.io/crates/l/rune-static-map)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A fluent builder that assembles the URL-encoded query-parameter string for a
generic static-map-image request: center, zoom, image size, markers, and an
optional polyline overlay. This is a params/URL builder only — no network
call is made, and the parameter names (`center`, `zoom`, `size`, `markers`,
`path`) are generic rather than tied to any one specific map provider's exact
API. Reuse-friendly: it accepts an already-encoded polyline string rather
than depending on a polyline encoder itself. Pure Rust, no dependencies
beyond the optional CLI parser.

## Installation

```toml
[dependencies]
rune-static-map = "0.1"
```

The `rune-static-map` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-static-map --features cli
```

## Usage

```rust
use rune_static_map::StaticMapRequest;

let query = StaticMapRequest::new((60.1699, 24.9384), 12, (600, 400))
    .add_marker(60.1699, 24.9384, "red")
    .with_polyline("_p~iF~ps|U_ulLnnqC")
    .build_query_string();
```

## CLI

```bash
rune-static-map --center 60.1699,24.9384 --zoom 12 --size 600x400 --marker 60.1699,24.9384,red
```

## Output

```
center=60.1699%2C24.9384&zoom=12&size=600x400&markers=60.1699%2C24.9384%2Cred
```

## License

MIT
