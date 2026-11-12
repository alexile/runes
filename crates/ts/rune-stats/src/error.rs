//! The crate's error type.

/// Errors returned by this crate.
///
/// Every function validates its input and returns one of these instead of
/// panicking or silently producing `NaN`.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A sample that must hold at least one observation is empty.
    #[error("sample is empty")]
    Empty,
    /// A sample contains `NaN`, which has no rank and no order.
    #[error("sample contains NaN")]
    Nan,
    /// A sample is smaller than the computation needs.
    #[error("need at least {needed} observations, got {got}")]
    TooFew {
        /// Smallest sample size that works.
        needed: usize,
        /// Size that was supplied.
        got: usize,
    },
    /// A function that expects sorted input was given unsorted input.
    #[error("sample is not sorted in ascending order")]
    NotSorted,
    /// A parameter is outside its valid range (for example a probability
    /// outside `[0, 1]`).
    #[error("parameter `{name}` = {value} is outside its valid range")]
    InvalidParameter {
        /// Name of the parameter.
        name: &'static str,
        /// The rejected value.
        value: f64,
    },
    /// The data have no spread, so the requested quantity is undefined
    /// (for example a regression on points that all share one `x`).
    #[error("data are degenerate: {0}")]
    Degenerate(&'static str),
    /// An exact p-value was requested but the sample has ties (or zero
    /// differences), for which the exact null distribution does not hold.
    #[error("exact p-values need samples without ties or zero differences")]
    ExactWithTies,
    /// The samples are too large for the requested computation: an exact
    /// null distribution that cannot be enumerated, or more pairwise
    /// differences than can reasonably be held in memory. For exact tests,
    /// use the asymptotic method instead.
    #[error("samples too large for this computation (limit {limit})")]
    TooLarge {
        /// The limit that was exceeded: total observations for exact
        /// distributions, number of pairs for pairwise estimators.
        limit: usize,
    },
    /// Paired samples have different lengths.
    #[error("paired samples differ in length: {left} vs {right}")]
    LengthMismatch {
        /// Length of the first sample.
        left: usize,
        /// Length of the second sample.
        right: usize,
    },
}
