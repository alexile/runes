# rune-lowpass

> Low-pass/high-pass digital filter for noisy scalar signals.

[![crates.io](https://img.shields.io/crates/v/rune-lowpass)](https://crates.io/crates/rune-lowpass)
[![docs.rs](https://img.shields.io/docsrs/rune-lowpass)](https://docs.rs/rune-lowpass)
[![license](https://img.shields.io/crates/l/rune-lowpass)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Single-pole (first-order) low-pass and high-pass IIR filters for real-time
smoothing of noisy scalar signals, plus a cutoff-frequency-to-alpha
converter. O(1) memory and time per sample. Pure Rust, no dependencies beyond
the optional CLI parser.

## Installation

```toml
[dependencies]
rune-lowpass = "0.1"
```

The `rune-lowpass` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-lowpass --features cli
```

## Usage

```rust
use rune_lowpass::{LowPassFilter, cutoff_to_alpha};

let alpha = cutoff_to_alpha(2.0, 100.0);
let mut filter = LowPassFilter::new(alpha);
let smoothed: Vec<f64> = [1.0, 5.0, 1.0, 5.0, 1.0].iter().map(|&x| filter.apply(x)).collect();
```

## CLI

```bash
rune-lowpass --alpha 0.2 1.0 5.0 1.0 5.0 1.0
rune-lowpass --alpha 0.2 --high-pass 1.0 5.0 1.0 5.0 1.0
```

## Output

```
1.0000 1.8000 1.6400 2.3120 2.2496
```

## License

MIT
