# rune-kalman-1d

> 1D Kalman filter for smoothing a single noisy scalar signal.

[![crates.io](https://img.shields.io/crates/v/rune-kalman-1d)](https://crates.io/crates/rune-kalman-1d)
[![docs.rs](https://img.shields.io/docsrs/rune-kalman-1d)](https://docs.rs/rune-kalman-1d)
[![license](https://img.shields.io/crates/l/rune-kalman-1d)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A scalar Kalman filter: predict + correct on a single hidden state, O(1)
memory and time per update, no matrix math needed. Smooths a noisy sensor
reading into a stable estimate, weighted by how much you trust the process
model versus the sensor. Pure Rust, no dependencies beyond the optional CLI parser.

## Installation

```toml
[dependencies]
rune-kalman-1d = "0.1"
```

The `rune-kalman-1d` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-kalman-1d --features cli
```

## Usage

```rust
use rune_kalman_1d::Kalman1D;

let mut kalman = Kalman1D::new(0.001, 1.0, 0.0, 1.0);
for reading in [9.8, 10.2, 9.9, 10.1] {
    kalman.update(reading);
}
println!("{}", kalman.estimate());
```

## CLI

```bash
rune-kalman-1d --process-variance 0.001 --measurement-variance 1.0 9.8 10.2 9.9 10.1
```

## Output

```
9.7810 9.9803 9.9505 10.0090
```

## License

MIT
