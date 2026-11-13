# rune-season-decomp

> Seasonal-trend decomposition: classical additive/multiplicative, STL and MSTL.

[![crates.io](https://img.shields.io/crates/v/rune-season-decomp)](https://crates.io/crates/rune-season-decomp)
[![docs.rs](https://img.shields.io/docsrs/rune-season-decomp)](https://docs.rs/rune-season-decomp)
[![license](https://img.shields.io/crates/l/rune-season-decomp)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Splits a numeric series into trend, seasonal, and remainder components. Three
methods:

- **Classical** (`decompose`): trend via a centered moving average of the
  given period, seasonal as the average detrended value at each phase, and
  residual as whatever's left. The same technique behind R's `decompose()` and
  statsmodels' `seasonal_decompose`, in additive
  (`series = trend + seasonal + residual`) or multiplicative
  (`series = trend * seasonal * residual`) form.
- **STL** (`Stl`): Seasonal-Trend decomposition using Loess (Cleveland et al.
  1990). Iterated loess smoothing of the cycle-subseries and the trend, so the
  seasonal pattern can evolve and every point gets a trend value. An optional
  robust outer loop with bisquare weights pushes outliers into the remainder.
  Spans, degrees, jumps and loop counts are all tunable; defaults follow R's
  `stl()` and the output matches it to floating-point noise.
- **MSTL** (`Mstl`): several seasonal periods at once (Bandara, Hyndman &
  Bergmeir 2021), e.g. daily and weekly cycles in hourly data.

STL and MSTL results also report trend and seasonal strength
(Wang, Smith & Hyndman 2006), each in `[0, 1]`. Bad input (NaN, period below 2,
fewer than two full periods, even or too-small windows) is rejected with an
`StlError`.

## Installation

```toml
[dependencies]
rune-season-decomp = "0.1.1"
```

The `rune-season-decomp` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-season-decomp --features cli
```

## Usage

```rust
use rune_season_decomp::{decompose, DecompMode, Mstl, Stl};

// Classical.
let series = [10.0, 20.0, 10.0, 20.0, 10.0, 20.0, 10.0, 20.0];
let result = decompose(&series, 2, DecompMode::Additive);
assert_eq!(result.seasonal.len(), series.len());

// STL with a 7-cycle seasonal window, robust to outliers.
let monthly: Vec<f64> = (0..48)
    .map(|i| 0.1 * i as f64 + [5.0, 3.0, 0.0, -3.0, -5.0, 0.0][i % 6])
    .collect();
let fit = Stl::new(6, 7).robust(true).fit(&monthly)?;
println!("seasonal strength {:.2}", fit.seasonal_strength());

// Tuning: explicit trend span, linear seasonal fit, no jumps.
let fit = Stl::new(6, 11)
    .seasonal_degree(rune_season_decomp::Degree::Linear)
    .trend_window(15)
    .jumps(1, 1, 1)
    .fit(&monthly)?;
assert_eq!(fit.trend.len(), monthly.len());

// MSTL with two periods.
let fit = Mstl::new(&[6, 12]).fit(&monthly)?;
assert_eq!(fit.seasonal.len(), 2);
```

## CLI

```bash
rune-season-decomp --series "10,20,10,20,10,20,10,20" --period 2 --mode additive
rune-season-decomp --series "..." --period 12 --method stl --seasonal-window 7 --robust
rune-season-decomp --series "..." --period 12 --method stl --seasonal-window periodic
rune-season-decomp --series "..." --period 24,168 --method mstl
```

## Output

```
{"residual":[null,0.0,0.0,0.0,0.0,0.0,0.0,null],"seasonal":[-5.0,5.0,-5.0,5.0,-5.0,5.0,-5.0,5.0],"trend":[null,15.0,15.0,15.0,15.0,15.0,15.0,null]}
```

The `stl` method adds `weights`, `trend_strength` and `seasonal_strength`; the
`mstl` method returns one seasonal array per period plus `periods`.

## License

MIT
