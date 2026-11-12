# rune-window-agg

> Tumbling/sliding/session window aggregator over a timestamped stream.

[![crates.io](https://img.shields.io/crates/v/rune-window-agg)](https://crates.io/crates/rune-window-agg)
[![docs.rs](https://img.shields.io/docsrs/rune-window-agg)](https://docs.rs/rune-window-agg)
[![license](https://img.shields.io/crates/l/rune-window-agg)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Aggregates a `(timestamp, value)` stream into tumbling (fixed, non-overlapping),
sliding (overlapping, stepped), or session (gap-based) windows. Windows close
automatically as the timestamp watermark advances past their end; `flush`
collects whatever is still open at stream end. Pure Rust, no dependencies
beyond the CLI arg parser.

## Installation

```toml
[dependencies]
rune-window-agg = "0.1"
```

The `rune-window-agg` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-window-agg --features cli
```

## Usage

```rust
use rune_window_agg::{WindowAggregator, WindowKind};

let mut agg = WindowAggregator::new(WindowKind::Tumbling { size_ms: 10 });
agg.push(0, 1.0);
agg.push(5, 2.0);
let closed = agg.push(12, 3.0); // crossing into the next bucket closes the first
assert_eq!(closed[0].sum, 3.0);
assert_eq!(closed[0].count, 2);
```

## CLI

Aggregates a `ts_ms,value` CSV stream into fixed-size tumbling windows:

```bash
rune-window-agg --size-ms 60000 readings.csv
cat readings.csv | rune-window-agg --size-ms 60000 -
```

## Output

```
[0, 10) count=2 sum=3 min=1 max=2
[10, 20) count=1 sum=3 min=3 max=3
```

## License

MIT
