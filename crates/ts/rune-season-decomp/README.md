# rune-season-decomp

> Simple additive/multiplicative seasonal decomposition.

[![crates.io](https://img.shields.io/crates/v/rune-season-decomp)](https://crates.io/crates/rune-season-decomp)
[![docs.rs](https://img.shields.io/docsrs/rune-season-decomp)](https://docs.rs/rune-season-decomp)
[![license](https://img.shields.io/crates/l/rune-season-decomp)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Splits a numeric series into trend, seasonal, and residual components: trend
via a centered moving average of the given period, seasonal as the average
detrended value at each phase of the period, and residual as whatever's left.
The same technique behind R's `decompose()` and statsmodels'
`seasonal_decompose`. Supports both additive
(`series = trend + seasonal + residual`) and multiplicative
(`series = trend * seasonal * residual`) models.

## Installation

```toml
[dependencies]
rune-season-decomp = "0.1"
```

The `rune-season-decomp` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-season-decomp --features cli
```

## Usage

```rust
use rune_season_decomp::{decompose, DecompMode};

let series = [10.0, 20.0, 10.0, 20.0, 10.0, 20.0, 10.0, 20.0];
let result = decompose(&series, 2, DecompMode::Additive);
assert_eq!(result.seasonal.len(), series.len());
```

## CLI

```bash
rune-season-decomp --series "10,20,10,20,10,20" --period 2 --mode additive
```

## Output

```
{"trend":[null,15.0,15.0,15.0,15.0,15.0,null,null],"seasonal":[-5.0,5.0,-5.0,5.0,-5.0,5.0,-5.0,5.0],"residual":[null,0.0,0.0,0.0,0.0,0.0,null,null]}
```

## License

MIT
