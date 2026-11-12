# rune-heartbeat

> Missing-heartbeat/liveness detector over a keyed stream of pings.

[![crates.io](https://img.shields.io/crates/v/rune-heartbeat)](https://crates.io/crates/rune-heartbeat)
[![docs.rs](https://img.shields.io/docsrs/rune-heartbeat)](https://docs.rs/rune-heartbeat)
[![license](https://img.shields.io/crates/l/rune-heartbeat)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Tracks the last-seen time per key and reports which keys have gone silent
for longer than a configured timeout. Time is passed in explicitly rather
than read from the system clock, so results stay fully deterministic. Pure
Rust, no dependencies beyond the CLI's argument parser.

## Installation

```toml
[dependencies]
rune-heartbeat = "0.1"
```

The `rune-heartbeat` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-heartbeat --features cli
```

## Usage

```rust
use rune_heartbeat::HeartbeatMonitor;
use std::time::{Duration, Instant};

let start = Instant::now();
let mut monitor = HeartbeatMonitor::new(Duration::from_secs(5));
monitor.ping("device-1", start);

assert!(monitor.missing(start + Duration::from_secs(1)).is_empty());
assert_eq!(monitor.missing(start + Duration::from_secs(6)), vec!["device-1"]);
```

## CLI

Reads `"<key> <offset_ms>"` ping lines from stdin and prints keys missing at
a given evaluation time:

```bash
printf 'device-1 0\ndevice-2 100\n' | rune-heartbeat --timeout-ms 500 --now-ms 700
```

## Output

```
device-1
```

## License

MIT
