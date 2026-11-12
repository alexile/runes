# rune-gap-detect

> Detect missing/gap intervals in an expected-cadence timestamped series.

[![crates.io](https://img.shields.io/crates/v/rune-gap-detect)](https://crates.io/crates/rune-gap-detect)
[![docs.rs](https://img.shields.io/docsrs/rune-gap-detect)](https://docs.rs/rune-gap-detect)
[![license](https://img.shields.io/crates/l/rune-gap-detect)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Scans a sorted series of timestamps that's supposed to arrive at a roughly
fixed cadence and reports every interval where samples were skipped, with an
estimate of how many. Useful for spotting outages, dropped connections, or
missed scheduled runs after the fact. Pure Rust, no dependencies beyond the
optional CLI parser.

## Installation

```toml
[dependencies]
rune-gap-detect = "0.1"
```

The `rune-gap-detect` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-gap-detect --features cli
```

## Usage

```rust
use rune_gap_detect::detect_gaps;

let timestamps = vec![0, 1000, 2000, 4000, 5000]; // one sample dropped at t=3000
let gaps = detect_gaps(&timestamps, 1000, 100);
assert_eq!(gaps.len(), 1);
assert_eq!(gaps[0].missing_count, 1);
```

## CLI

```bash
rune-gap-detect timestamps.txt --interval 1000 --tolerance 100
```

## Output

```
2000 -> 4000 (1 missing)
1 gap(s) found
```

## License

MIT
