# rune-stats

> Nonparametric statistics: robust descriptives, rank tests and effect sizes

[![crates.io](https://img.shields.io/crates/v/rune-stats)](https://crates.io/crates/rune-stats)
[![docs.rs](https://img.shields.io/docsrs/rune-stats)](https://docs.rs/rune-stats)
[![license](https://img.shields.io/crates/l/rune-stats)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Statistics for deciding whether two small sets of measurements differ —
timings, sizes, counts — without assuming normality and without letting a
few outliers decide the answer. Sans-I/O, `f64` slices in, no dependencies
beyond `thiserror`.

| Area | API |
| --- | --- |
| Descriptive | `mean`, `variance`, `std_dev`, `population_*`, `median`, `quantile`, `percentile` (type 7), `mad`, `robust_sigma`, `RobustScale`, `inlier_mask` |
| Rank tests | `mann_whitney_u` (exact or tie-corrected normal), `ks_two_sample` (exact or asymptotic), `wilcoxon_signed_rank` / `wilcoxon_paired` (exact or normal, Wilcox or Pratt zeros) |
| Effect sizes | rank-biserial correlation / Cliff's delta, probability of superiority, KS `D`, `cohens_d` |
| Intervals | `median_ci` (binomial order statistics), `hodges_lehmann_shift`, `hodges_lehmann_one_sample` |
| Distributions | `dist::erfc`, `normal_cdf`, `normal_sf`, `normal_quantile`, `kolmogorov_sf`, `ln_gamma`, `gamma_p`, `gamma_q`, `chi_squared_sf` |

Every test takes an `Alternative` (two-sided, greater, less) and a `Method`
(`Auto`, `Exact`, `Asymptotic`). Results are checked against SciPy and R
reference values vendored in `tests/known_answers.rs`.

## Installation

```toml
[dependencies]
rune-stats = "0.1"
```

Enable the `serde` feature to serialise results and options.

## Usage

```rust
use rune_stats::{
    hodges_lehmann_shift, ks_two_sample, mann_whitney_u, Alternative, KsOptions,
    MannWhitneyOptions, RobustScale,
};

// Login response times (ms) for valid and invalid user names.
let valid = [212.0, 230.0, 225.0, 241.0, 219.0, 236.0, 228.0, 1900.0];
let invalid = [181.0, 176.0, 190.0, 185.0, 179.0, 188.0, 183.0, 177.0];

// Robust location and spread: the 1900 ms outlier is flagged, not averaged in.
let scale = RobustScale::estimate(&valid).unwrap();
assert!(!scale.is_inlier(1900.0, 3.5));

// Are valid names answered more slowly? (exact p-value: no ties, small n)
let options = MannWhitneyOptions::default().with_alternative(Alternative::Greater);
let test = mann_whitney_u(&valid, &invalid, &options).unwrap();
assert!(test.exact && test.p_value < 1e-3);
assert_eq!(test.rank_biserial, 1.0); // every valid timing beats every invalid one

// By how much, with a 95 % interval (Hodges–Lehmann)?
let shift = hodges_lehmann_shift(&valid, &invalid, 0.95).unwrap();
assert!(shift.lower > 0.0);

// Do the distributions differ at all?
let ks = ks_two_sample(&valid, &invalid, &KsOptions::default()).unwrap();
assert_eq!(ks.statistic, 1.0);
```

Hot paths can avoid allocation with the `_in_place` and `_sorted`
variants (`median_in_place`, `quantile_sorted`, `mann_whitney_u_sorted`,
`ks_two_sample_sorted`, `wilcoxon_signed_rank_in_place`, …).

## Notes

- `NaN` is rejected with `Error::Nan`; ordering uses `f64::total_cmp`.
- Mann–Whitney's normal approximation and z score match SciPy's
  `mannwhitneyu` (tie correction, continuity correction towards the null).
  Under `Method::Auto` the p-value is exact when there are no ties and both
  samples have fewer than 50 observations, as in R.
- The exact KS p-value assumes continuous data and is conservative with
  ties. The two-sided asymptotic p-value is the Kolmogorov limit, as in R.
- Hodges–Lehmann intervals use exact critical values under the same
  conditions as R's `wilcox.test(conf.int = TRUE)`; otherwise order
  statistics picked by the normal approximation.

## License

MIT
