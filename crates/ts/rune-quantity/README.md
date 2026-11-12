# rune-quantity

> Typed physical-quantity/unit system with compile-time-checked conversions (distance, speed, energy, etc.).

[![crates.io](https://img.shields.io/crates/v/rune-quantity)](https://crates.io/crates/rune-quantity)
[![docs.rs](https://img.shields.io/docsrs/rune-quantity)](https://docs.rs/rune-quantity)
[![license](https://img.shields.io/crates/l/rune-quantity)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A newtype per unit (`Meters`, `Kilometers`, `MetersPerSecond`, `Joules`, ...)
instead of one struct with a runtime unit tag, so mixing units is a compile
error rather than a runtime bug. Covers distance, speed, and energy families,
each converting through one canonical SI unit. Pure Rust, no dependencies
beyond the optional CLI parser.

## Installation

```toml
[dependencies]
rune-quantity = "0.1"
```

The `rune-quantity` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-quantity --features cli
```

## Usage

```rust
use rune_quantity::{Meters, Kilometers};

let a = Meters(500.0);
let b: Meters = Kilometers(1.5).into();
let total = a + b; // same-unit addition compiles directly
assert!((total.0 - 2000.0).abs() < 1e-9);

// Meters(1.0) + Kilometers(1.0) would not compile — convert explicitly first.
```

## CLI

```bash
rune-quantity km-to-m 5
rune-quantity mps-to-kmh 10
```

## Output

```
Meters(5000.0)
```

## License

MIT
