//! Nonparametric statistics for small samples: robust descriptives, rank
//! tests and the effect sizes and confidence intervals that go with them.
//!
//! Built for detection oracles that compare two sets of measurements
//! (timings, sizes, counts) and must decide whether they differ, without
//! assuming normality and without being thrown off by outliers.
//!
//! * **Descriptive** — [`mean`], [`variance`], [`std_dev`], [`median`],
//!   [`quantile`] / [`percentile`] (Hyndman & Fan type 7), [`mad`],
//!   [`robust_sigma`], [`RobustScale`] and [`inlier_mask`].
//! * **Tests** — [`mann_whitney_u`] (tie-corrected normal approximation or
//!   exact), [`ks_two_sample`] (exact or asymptotic) and
//!   [`wilcoxon_signed_rank`] / [`wilcoxon_paired`] (exact or
//!   tie-corrected normal approximation, Wilcox or Pratt zero handling).
//! * **Effect sizes and intervals** — rank-biserial correlations and the
//!   probability of superiority on the test results, [`cohens_d`],
//!   [`median_ci`], and the Hodges–Lehmann estimators
//!   [`hodges_lehmann_shift`] and [`hodges_lehmann_one_sample`].
//! * **Distributions** — [`dist`] has an accurate `erfc`, the normal
//!   distribution and quantile, the Kolmogorov distribution, and the
//!   regularized incomplete gamma functions and chi-squared distribution.
//!
//! Everything is sans-I/O and works on `f64` slices. Order statistics come
//! in `_in_place` / `_sorted` variants, and the tests in `_sorted` variants,
//! that do not allocate, for hot paths; the plain functions copy the input
//! once. `NaN` is rejected with [`Error::Nan`] rather than ranked, and
//! ordering uses [`f64::total_cmp`].
//!
//! Results are checked against `SciPy` and R reference values (see
//! `tests/known_answers.rs`).
//!
//! # Example
//!
//! ```
//! use rune_stats::{mann_whitney_u, Alternative, MannWhitneyOptions, Method, RobustScale};
//!
//! // Response times (ms) for a valid and an invalid user name.
//! let valid = [212.0, 230.0, 225.0, 241.0, 219.0, 236.0, 228.0, 1900.0];
//! let invalid = [181.0, 176.0, 190.0, 185.0, 179.0, 188.0, 183.0, 177.0];
//!
//! // One slow outlier does not move the median or the robust spread much.
//! let scale = RobustScale::estimate(&valid)?;
//! assert_eq!(scale.center, 229.0);
//! assert!(!scale.is_inlier(1900.0, 3.5));
//!
//! // Are valid user names answered more slowly?
//! let options = MannWhitneyOptions::default()
//!     .with_alternative(Alternative::Greater)
//!     .with_method(Method::Exact);
//! let test = mann_whitney_u(&valid, &invalid, &options)?;
//! assert_eq!(test.u, 64.0);
//! assert_eq!(test.rank_biserial, 1.0);
//! assert!(test.p_value < 1e-4);
//! # Ok::<(), rune_stats::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod ci;
mod descriptive;
pub mod dist;
mod effect;
mod error;
mod exact;
mod hypothesis;
mod ks;
mod mann_whitney;
mod rank;
mod regression;
mod util;
mod wilcoxon;

pub use ci::{
    ConfidenceInterval, MAX_PAIRS, hodges_lehmann_one_sample, hodges_lehmann_shift, median_ci,
};
pub use descriptive::{
    MAD_TO_SIGMA, RobustScale, inlier_mask, mad, mad_in_place, mean, median, median_in_place,
    median_sorted, percentile, population_std_dev, population_variance, quantile,
    quantile_in_place, quantile_sorted, robust_sigma, std_dev, variance,
};
pub use effect::cohens_d;
pub use error::Error;
pub use hypothesis::{Alternative, Method};
pub use ks::{KolmogorovSmirnov, KsOptions, ks_two_sample, ks_two_sample_sorted};
pub use mann_whitney::{MannWhitney, MannWhitneyOptions, mann_whitney_u, mann_whitney_u_sorted};
pub use regression::{LinearFit, linear_regression};
pub use wilcoxon::{
    WilcoxonOptions, WilcoxonSignedRank, ZeroMethod, wilcoxon_paired, wilcoxon_signed_rank,
    wilcoxon_signed_rank_in_place,
};
