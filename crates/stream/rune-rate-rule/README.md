# rune-rate-rule

> Composable rule trait plus threshold, rate-of-change, and missing-heartbeat rule implementations.

[![crates.io](https://img.shields.io/crates/v/rune-rate-rule)](https://crates.io/crates/rune-rate-rule)
[![docs.rs](https://img.shields.io/docsrs/rune-rate-rule)](https://docs.rs/rune-rate-rule)
[![license](https://img.shields.io/crates/l/rune-rate-rule)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A small `Rule<T>` trait plus three ready-made stateful rules: a min/max
threshold, a rate-of-change (delta between consecutive values) check, and a
missing-heartbeat liveness check. Rules are trait-object friendly, so a
monitoring loop can hold a `Vec<Box<dyn Rule<f64>>>` and evaluate every
incoming value against all of them. Pure Rust, no dependencies beyond the CLI
arg parser.

## Installation

```toml
[dependencies]
rune-rate-rule = "0.1"
```

The `rune-rate-rule` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-rate-rule --features cli
```

## Usage

```rust
use rune_rate_rule::{Rule, ThresholdRule, RateOfChangeRule};

let mut range = ThresholdRule::new("temp-range").min(0.0).max(100.0);
assert!(range.evaluate(&50.0).is_none());
assert!(range.evaluate(&150.0).is_some());

let mut jump = RateOfChangeRule::new("temp-jump", 10.0);
jump.evaluate(&20.0);
assert!(jump.evaluate(&45.0).is_some());
```

## CLI

Evaluates newline-separated numbers against a min/max threshold:

```bash
rune-rate-rule --min 0 --max 100 readings.txt
cat readings.txt | rune-rate-rule --min 0 --max 100 -
```

## Output

```
line 4: 150 is above maximum 100
1 violation(s)
```

## License

MIT
