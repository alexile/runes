# rune-geofence

> Point-in-polygon / point-in-circle containment, plus enter/exit event detection over a position stream.

[![crates.io](https://img.shields.io/crates/v/rune-geofence)](https://crates.io/crates/rune-geofence)
[![docs.rs](https://img.shields.io/docsrs/rune-geofence)](https://docs.rs/rune-geofence)
[![license](https://img.shields.io/crates/l/rune-geofence)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Point-in-circle (great-circle distance) and point-in-polygon (ray casting)
containment checks, plus a `GeofenceTracker` that turns a stream of position
updates into `Enter`/`Exit` events by tracking prior containment state. Pure
Rust, no dependencies beyond the optional CLI parser.

## Installation

```toml
[dependencies]
rune-geofence = "0.1"
```

The `rune-geofence` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-geofence --features cli
```

## Usage

```rust
use rune_geofence::{Fence, GeofenceTracker, FenceEvent};

let mut tracker = GeofenceTracker::new(Fence::Circle {
    center_lat: 60.0,
    center_lon: 24.0,
    radius_m: 1000.0,
});

assert_eq!(tracker.update(60.0, 24.0), Some(FenceEvent::Enter));
```

## CLI

```bash
rune-geofence circle 60.0 24.0 1000 60.001 24.001
```

## Output

```
true
```

## License

MIT
