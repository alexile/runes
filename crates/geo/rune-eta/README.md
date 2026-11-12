# rune-eta

> Distance- and speed-profile-based arrival time estimator.

[![crates.io](https://img.shields.io/crates/v/rune-eta)](https://crates.io/crates/rune-eta)
[![docs.rs](https://img.shields.io/docsrs/rune-eta)](https://docs.rs/rune-eta)
[![license](https://img.shields.io/crates/l/rune-eta)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Estimates arrival time from a single distance/speed pair, or from a multi-leg
speed profile (different expected speeds per segment of a route), with optional
fixed dwell time added per stop. Pure Rust, no dependencies beyond the optional `clap` for
the CLI.

## Installation

```toml
[dependencies]
rune-eta = "0.1"
```

The `rune-eta` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-eta --features cli
```

## Usage

```rust
use rune_eta::{SpeedProfile, eta_profile, eta_with_stops};

let profile = SpeedProfile { segments: vec![(100.0, 10.0), (50.0, 5.0)] };
assert_eq!(eta_profile(&profile), Some(20.0));
assert_eq!(eta_with_stops(&profile, 30.0, 2), Some(80.0));
```

## CLI

```bash
rune-eta 100.0 10.0
```

## Output

```
10.00s
```

## License

MIT
