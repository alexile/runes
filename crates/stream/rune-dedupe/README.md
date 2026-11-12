# rune-dedupe

> Idempotency/dedup filter over a keyed, windowed stream.

[![crates.io](https://img.shields.io/crates/v/rune-dedupe)](https://crates.io/crates/rune-dedupe)
[![docs.rs](https://img.shields.io/docsrs/rune-dedupe)](https://docs.rs/rune-dedupe)
[![license](https://img.shields.io/crates/l/rune-dedupe)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Tracks the most recent time each key was seen and reports whether a new
occurrence falls inside a trailing time window — the standard building block
for turning at-least-once delivery into at-most-once processing (retried
webhooks, redelivered queue messages, flaky sensor uplinks). Takes an
explicit `Instant` rather than reading the clock internally, so behavior is
deterministic and testable. Expired entries are purged lazily, so memory
stays bounded by the number of distinct keys seen within the window. Pure
Rust, no dependencies beyond the CLI arg parser.

## Installation

```toml
[dependencies]
rune-dedupe = "0.1"
```

The `rune-dedupe` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-dedupe --features cli
```

## Usage

```rust
use rune_dedupe::Dedupe;
use std::time::{Duration, Instant};

let start = Instant::now();
let mut dedupe = Dedupe::new(Duration::from_secs(60));

assert!(dedupe.check("msg-1", start));
assert!(!dedupe.check("msg-1", start + Duration::from_secs(1)));
assert!(dedupe.check("msg-1", start + Duration::from_secs(61)));
```

## CLI

Filters duplicate keys (one per line) within a trailing time window:

```bash
rune-dedupe --window-secs 60 keys.txt
cat keys.txt | rune-dedupe --window-secs 60 -
```

## Output

```
msg-1
msg-2
2 kept, 1 duplicate(s) dropped
```

## License

MIT
