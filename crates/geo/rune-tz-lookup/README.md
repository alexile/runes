# rune-tz-lookup

> Offline timezone-from-coordinates lookup.

[![crates.io](https://img.shields.io/crates/v/rune-tz-lookup)](https://crates.io/crates/rune-tz-lookup)
[![docs.rs](https://img.shields.io/docsrs/rune-tz-lookup)](https://docs.rs/rune-tz-lookup)
[![license](https://img.shields.io/crates/l/rune-tz-lookup)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Estimates the UTC offset for a `(lat, lon)` coordinate using the equal-width
longitude model (15° per hour of offset — the same model used for nautical
time), with a small set of named bounding-box exceptions for real
half-hour/45-minute-offset regions (India, Nepal, Newfoundland, central
Australia). No data files, no network calls, no dependency on a real tzdb —
this is a documented approximation, not a replacement for one. Political
timezone borders don't follow meridians, so accuracy degrades the further a
point is from a region this crate models explicitly.

## Installation

```toml
[dependencies]
rune-tz-lookup = "0.1"
```

The `rune-tz-lookup` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-tz-lookup --features cli
```

## Usage

```rust
use rune_tz_lookup::estimate_utc_offset_hours;

let offset = estimate_utc_offset_hours(60.1699, 24.9384);
```

## CLI

```bash
rune-tz-lookup 60.1699 24.9384
```

## Output

```
{"lat":60.1699,"lon":24.9384,"utc_offset_hours":2.0}
```

## License

MIT
