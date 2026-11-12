# rune-forecast-ses

> Exponential smoothing forecasts: SES, Holt, damped trend and Holt-Winters with fitted parameters, prediction intervals and AICc model selection.

[![crates.io](https://img.shields.io/crates/v/rune-forecast-ses)](https://crates.io/crates/rune-forecast-ses)
[![docs.rs](https://img.shields.io/docsrs/rune-forecast-ses)](https://docs.rs/rune-forecast-ses)
[![license](https://img.shields.io/crates/l/rune-forecast-ses)](LICENSE)

## What it does

A standalone implementation of the exponential smoothing family from
Hyndman & Athanasopoulos, *Forecasting: Principles and Practice* (fpp2,
chapter 7), with additive errors:

| Model | Constructor | Notation |
| --- | --- | --- |
| Simple exponential smoothing | `Model::ses()` | ETS(A,N,N) |
| Holt's linear trend | `Model::holt()` | ETS(A,A,N) |
| Damped trend | `Model::damped_holt()` | ETS(A,Ad,N) |
| Holt-Winters additive | `Model::holt_winters(Seasonal::Additive, m)` | ETS(A,A,A) |
| Holt-Winters multiplicative | `Model::holt_winters(Seasonal::Multiplicative, m)` | ETS(A,A,M) |
| Any combination | `Model::new(trend, seasonal, m)` | |

- **Fitting**: smoothing parameters and initial states minimise the sum of
  squared one-step errors. For linear models the initial state is solved
  exactly by least squares, and a grid plus bounded Nelder-Mead searches the
  parameters. Any parameter can be held fixed with `Params`.
- **Prediction intervals**: closed-form variances for the linear models
  (Hyndman et al. 2008, table 6.1); simulated quantiles (10 000 paths, fixed
  seed) for multiplicative seasonality.
- **Model selection**: `Auto` fits every applicable candidate and keeps the
  lowest AICc (or AIC/BIC), using the same likelihood convention as R's
  `forecast::ets`.
- **Validation**: `NaN`/infinite values, series too short for the model or
  season length, non-positive values for multiplicative seasonality and
  out-of-range parameters all return an `Error`, never panic.

Results match the fpp2 worked examples (oil, air passengers, livestock,
Australian tourism) to the printed precision or better; see `tests/fpp2.rs`.

The streaming `SimpleExpSmoothing` and `DoubleExpSmoothing` smoothers with
fixed parameters are still there, unchanged. No dependencies beyond the
optional CLI parser.

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
use rune_forecast_ses::{Auto, Model, Params, Seasonal};

let y: Vec<f64> = (0..32)
    .map(|t| 20.0 + 0.8 * f64::from(t) + [6.0, -2.0, -7.0, 3.0][t as usize % 4])
    .collect();

// Holt-Winters with fitted parameters and 95% intervals.
let fit = Model::holt_winters(Seasonal::Additive, 4).fit(&y)?;
for iv in fit.forecast_intervals(4, 0.95)? {
    println!("{:.2} [{:.2}, {:.2}]", iv.mean, iv.lower, iv.upper);
}

// Damped trend with phi held at 0.9.
let damped = Model::damped_holt().fit_with(&y, Params::new().with_phi(0.9))?;

// Let AICc choose among SES, Holt, damped and Holt-Winters.
let best = Auto::new().period(4).fit(&y)?;
println!("{} alpha={:.3} AICc={:.1}", best.model(), best.alpha(), best.aicc());
```

Streaming with fixed parameters:

```rust
use rune_forecast_ses::{DoubleExpSmoothing, SimpleExpSmoothing};

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
# fixed smoothing factors
rune-forecast-ses --alpha 0.3 --steps 5 10 12 11 15 20
rune-forecast-ses --alpha 0.3 --beta 0.2 --steps 5 10 12 11 15 20

# fitted model (ses, holt, damped, hw-add, hw-mul, auto), with intervals
rune-forecast-ses --model auto --period 4 --level 0.8 --steps 4 \
  42.2 24.6 32.7 37.3 45.2 29.4 36.3 41.8 49.3 31.3 37.9 38.8 51.2 31.8 41.3 42.8
```

## Output

```
14.4028 14.4028 14.4028 14.4028 14.4028
```

With `--level`, one `mean lower upper` line per step; the chosen model and
its parameters go to stderr.

## License

MIT
