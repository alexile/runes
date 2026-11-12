# rune-watermark

> Late-arrival/watermark tracking for out-of-order event streams.

[![crates.io](https://img.shields.io/crates/v/rune-watermark)](https://crates.io/crates/rune-watermark)
[![docs.rs](https://img.shields.io/docsrs/rune-watermark)](https://docs.rs/rune-watermark)
[![license](https://img.shields.io/crates/l/rune-watermark)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Maintains a watermark — `max_ts_seen - allowed_lateness` — over a stream of
millisecond timestamps arriving in any order, and classifies each new
timestamp as on-time or late relative to the watermark at the moment it
arrives. The watermark only ever moves forward. Pure Rust, no dependencies.

## Installation

```toml
[dependencies]
rune-watermark = "0.1"
```

The `rune-watermark` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-watermark --features cli
```

## Usage

```rust
use rune_watermark::{WatermarkTracker, Lateness};

let mut tracker = WatermarkTracker::new(1_000);

assert_eq!(tracker.observe(5_000), Lateness::OnTime);
assert_eq!(tracker.observe(6_000), Lateness::OnTime);
assert_eq!(tracker.observe(4_000), Lateness::Late { by_ms: 1_000 });
```

## CLI

```bash
rune-watermark --allowed-lateness 1000 timestamps.txt
cat timestamps.txt | rune-watermark --allowed-lateness 1000 -
```

## Output

```
5000	on-time
6000	on-time
4000	late	1000ms
1/3 events late
```

## License

MIT
