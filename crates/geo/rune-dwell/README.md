# rune-dwell

> Stop/dwell-time detection from a position stream.

[![crates.io](https://img.shields.io/crates/v/rune-dwell)](https://crates.io/crates/rune-dwell)
[![docs.rs](https://img.shields.io/docsrs/rune-dwell)](https://docs.rs/rune-dwell)
[![license](https://img.shields.io/crates/l/rune-dwell)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Tracks whether recent positions stay within a radius of an anchor point long
enough to count as a genuine stop, as opposed to noise (briefly leaving the
radius before any meaningful time has passed) or continuous movement. Feed it
one timestamped `(lat, lon)` sample at a time; it emits a completed dwell
event whenever a qualifying stop just ended.

## Installation

```toml
[dependencies]
rune-dwell = "0.1"
```

The `rune-dwell` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-dwell --features cli
```

## Usage

```rust
use rune_dwell::DwellDetector;

let mut d = DwellDetector::new(50.0, 60_000); // 50m radius, 60s minimum dwell
assert!(d.update(0, 60.17, 24.94).is_none());
assert!(d.update(90_000, 60.17, 24.94).is_none()); // still within radius
let event = d.update(91_000, 61.0, 24.94).unwrap(); // jumped far away
assert_eq!(event.duration_ms, 90_000);
```

## CLI

```bash
rune-dwell 50 60000 trace.csv
```

## Output

```
{"start_ms":0,"end_ms":90000,"lat":60.17,"lon":24.94,"duration_ms":90000}
```

## License

MIT
