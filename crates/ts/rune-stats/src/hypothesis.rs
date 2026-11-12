//! Settings shared by the hypothesis tests.

use crate::dist::{normal_cdf, normal_sf};

/// The alternative hypothesis of a test.
///
/// For two-sample tests, `Greater` means "the first sample tends to be
/// larger than the second" (its distribution is shifted right, i.e. its
/// distribution function is smaller). For the signed-rank test it means
/// "the differences tend to be positive".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Alternative {
    /// The two sides differ in either direction.
    #[default]
    TwoSided,
    /// The first sample (or the differences) tends to be larger.
    Greater,
    /// The first sample (or the differences) tends to be smaller.
    Less,
}

/// How a test computes its p-value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Method {
    /// Exact when the exact null distribution holds and is cheap, otherwise
    /// asymptotic. Each test documents its rule.
    #[default]
    Auto,
    /// Exact null distribution. Fails with
    /// [`Error::ExactWithTies`](crate::Error::ExactWithTies) where ties
    /// invalidate it.
    Exact,
    /// Large-sample approximation.
    Asymptotic,
}

/// Sign of the continuity correction for a standardised statistic: always
/// towards the null, so the correction can only increase the p-value.
pub fn correction_sign(numerator: f64, alternative: Alternative) -> f64 {
    match alternative {
        Alternative::Greater => 1.0,
        Alternative::Less => -1.0,
        Alternative::TwoSided => {
            if numerator > 0.0 {
                1.0
            } else if numerator < 0.0 {
                -1.0
            } else {
                0.0
            }
        }
    }
}

/// Normal-approximation p-value of a standardised statistic `z`.
pub fn normal_p_value(z: f64, alternative: Alternative) -> f64 {
    let p = match alternative {
        Alternative::Greater => normal_sf(z),
        Alternative::Less => normal_cdf(z),
        Alternative::TwoSided => 2.0 * normal_sf(z.abs()),
    };
    p.clamp(0.0, 1.0)
}

/// Exact p-value from the tail probabilities `P(X ≥ x)` and `P(X ≤ x)`.
pub fn exact_p_value(upper: f64, lower: f64, alternative: Alternative) -> f64 {
    let p = match alternative {
        Alternative::Greater => upper,
        Alternative::Less => lower,
        Alternative::TwoSided => 2.0 * upper.min(lower),
    };
    p.clamp(0.0, 1.0)
}
