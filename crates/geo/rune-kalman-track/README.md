# rune-kalman-track

> Kalman filter for smoothing noisy position/velocity readings.

[![crates.io](https://img.shields.io/crates/v/rune-kalman-track)](https://crates.io/crates/rune-kalman-track)
[![docs.rs](https://img.shields.io/docsrs/rune-kalman-track)](https://docs.rs/rune-kalman-track)
[![license](https://img.shields.io/crates/l/rune-kalman-track)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A 2D constant-velocity Kalman filter for smoothing noisy position readings —
GPS fixes, radar returns, any noisy 2D position sensor. Tracks a 4-element
state `[x, y, vx, vy]` and its full 4x4 error covariance; `predict` advances
the state under a constant-velocity motion model, `update` folds in a new
position measurement. The matrix math is hand-rolled for this fixed shape, no
external linear-algebra dependency.

## Installation

```toml
[dependencies]
rune-kalman-track = "0.1"
```

The `rune-kalman-track` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-kalman-track --features cli
```

## Usage

```rust
use rune_kalman_track::KalmanTrack;

let mut track = KalmanTrack::new(0.0, 0.0, 0.01, 1.0);
track.predict(1.0);
track.update(1.0, 0.0);
let (x, y) = track.position();
assert!(x > 0.0 && x < 1.5);
```

## CLI

```bash
rune-kalman-track 0.0,0.0 1.0,0.1 2.1,-0.1 3.0,0.2
```

## Output

```
{"x":0.0,"y":0.0,"vx":0.0,"vy":0.0}
{"x":0.52,"y":0.05,"vx":0.51,"vy":0.05}
```

## License

MIT
