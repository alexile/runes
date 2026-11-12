# rune-trace-replay

> Replay a recorded position trace at a configurable speed multiplier through any sink.

[![crates.io](https://img.shields.io/crates/v/rune-trace-replay)](https://crates.io/crates/rune-trace-replay)
[![docs.rs](https://img.shields.io/docsrs/rune-trace-replay)](https://docs.rs/rune-trace-replay)
[![license](https://img.shields.io/crates/l/rune-trace-replay)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Wraps any iterator of timestamped position points and replays them with the
original pacing preserved, at a configurable speed multiplier — so a recorded
GPS trace can be replayed as if a device were moving live, at any speed. Pure
Rust, no async runtime required.

## Installation

```toml
[dependencies]
rune-trace-replay = "0.1"
```

The `rune-trace-replay` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-trace-replay --features cli
```

## Usage

```rust
use rune_trace_replay::{TracePoint, TraceReplay};

let points = vec![
    TracePoint { ts_ms: 0, lat: 60.17, lon: 24.94 },
    TracePoint { ts_ms: 1000, lat: 60.18, lon: 24.95 },
];

for point in TraceReplay::new(points.into_iter(), 10.0) {
    println!("{}, {}", point.lat, point.lon);
}
```

## CLI

Reads a headerless CSV of `ts_ms,lat,lon` rows and replays them to stdout:

```bash
rune-trace-replay --speed 10 trace.csv
cat trace.csv | rune-trace-replay --speed 10 -
```

## Output

```
0,60.17,24.94
1000,60.18,24.95
```

## License

MIT
