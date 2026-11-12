# rune-forecast-ses

> Simple and double exponential smoothing forecaster.

[![crates.io](https://img.shields.io/crates/v/rune-forecast-ses)](https://crates.io/crates/rune-forecast-ses)
[![docs.rs](https://img.shields.io/docsrs/rune-forecast-ses)](https://docs.rs/rune-forecast-ses)
[![license](https://img.shields.io/crates/l/rune-forecast-ses)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Forecasts a numeric series with simple exponential smoothing (flat forecast,
no trend) or double exponential smoothing / Holt's linear method (linear
forecast, tracks a smoothed trend). Pure Rust, no dependencies beyond the optional
CLI parser.

## Installation

```toml
[dependencies]
rune-forecast-ses = "0.1"
```

The `rune-forecast-ses` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-forecast-ses --features cli
```

## Usage

```rust
use rune_forecast_ses::{SimpleExpSmoothing, DoubleExpSmoothing};

let mut ses = SimpleExpSmoothing::new(0.5);
ses.update(10.0);
let forecast = ses.forecast(3);

let mut des = DoubleExpSmoothing::new(0.8, 0.3);
des.update(1.0);
des.update(2.0);
let trend_forecast = des.forecast(3);
```

## CLI

```bash
rune-forecast-ses --alpha 0.3 --steps 5 10 12 11 15 20
rune-forecast-ses --alpha 0.3 --beta 0.2 --steps 5 10 12 11 15 20
```

## Output

```
16.9214 16.9214 16.9214 16.9214 16.9214
```

## License

MIT
