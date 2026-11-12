# rune-changepoint

> Change-point detection: PELT and binary segmentation over L2, normal and Poisson costs, CUSUM, and Bayesian online detection.

[![crates.io](https://img.shields.io/crates/v/rune-changepoint)](https://crates.io/crates/rune-changepoint)
[![docs.rs](https://img.shields.io/docsrs/rune-changepoint)](https://docs.rs/rune-changepoint)
[![license](https://img.shields.io/crates/l/rune-changepoint)](LICENSE)

## What it does

- **PELT** (Killick, Fearnhead & Eckley, 2012): the exact minimum of total
  segment cost plus a penalty per change, usually in near-linear time.
- **Binary segmentation**: greedy splitting, with a penalty and/or a cap on
  the number of changes.
- **Pluggable costs** through the `Cost` trait, with three built in:
  - `L2`: change in mean (Gaussian, known or robustly estimated noise
    variance),
  - `NormalMeanVar`: change in mean and/or variance,
  - `Poisson`: change in the rate of count data.
- **Penalties**: BIC (`p ln n`), MBIC (Zhang & Siegmund 2007), or manual.
- **Minimum segment length** for both offline methods.
- **CUSUM**: the classic two-sided control chart, as an incremental `Cusum`
  accumulator and a batch `detect` function (unchanged from earlier
  releases; `Cusum::try_new` validates its settings).
- **BOCPD** (Adams & MacKay, 2007): Bayesian online detection for Gaussian
  data with unknown mean and variance (needs the default `std` feature).

Change points are reported as the index where each new segment starts.
Inputs are validated: `NaN`/infinite values, negative counts, bad penalties
and a zero minimum segment length return an `Error` instead of panicking.

Everything except BOCPD builds without `std` (`core` + `alloc`). No
dependencies beyond the optional CLI parser.

## Installation

```toml
[dependencies]
rune-changepoint = "0.1"
```

The `rune-changepoint` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-changepoint --features cli
```

## Usage

```rust
use rune_changepoint::{BinSeg, L2, NormalMeanVar, Pelt, Penalty, Poisson};

let data: Vec<f64> = (0..90)
    .map(|t| if t < 40 { 1.0 } else if t < 70 { 6.0 } else { 3.0 } + [0.4, -0.3, 0.1][t % 3])
    .collect();

// Mean shifts, noise variance estimated from the data, BIC penalty.
let cost = L2::with_estimated_variance(&data)?;
assert_eq!(Pelt::new().min_size(5).detect(&cost)?, vec![40, 70]);

// Greedy alternative, at most one change.
assert_eq!(BinSeg::new().max_changes(1).detect(&cost)?, vec![40]);

// Other costs plug into the same searches.
let by_var = Pelt::new().penalty(Penalty::Mbic).detect(&NormalMeanVar::new(&data)?)?;
let counts = [1.0, 0.0, 2.0, 1.0, 9.0, 11.0, 10.0, 8.0];
let by_rate = Pelt::new().detect(&Poisson::new(&counts)?)?;
```

CUSUM:

```rust
use rune_changepoint::{detect, ChangeDirection};

let data = [0.0, 0.0, 0.0, 3.0, 3.0, 3.0, 3.0];
let changes = detect(&data, 0.0, 5.0, 0.5);
assert_eq!(changes[0].1, ChangeDirection::Up);
```

Online:

```rust
use rune_changepoint::{Bocpd, NormalGammaPrior};

let mut det = Bocpd::new(100.0, NormalGammaPrior::default())?;
for x in [0.1, -0.2, 0.0, 5.1, 4.9, 5.0] {
    let run_length = det.update(x)?;
}
```

## CLI

```bash
rune-changepoint --target 0 --threshold 5 --drift 0.5 0 0 0 3 3 3 3
rune-changepoint --method pelt --cost l2 --penalty bic 0 0 0 0 5 5 5 5
rune-changepoint --method binseg --cost poisson --penalty mbic --min-size 3 <counts...>
rune-changepoint --method bocpd --expected-run 50 <values...>
```

## Output

```
5: Up
```

CUSUM prints `index: direction`; the other methods print one segment-start
index per line (`4` for the PELT example above).

## License

MIT
