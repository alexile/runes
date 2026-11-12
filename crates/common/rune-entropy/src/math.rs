//! Float helpers that work with or without `std`.
//!
//! With `std` the inherent `f64` methods are used; without it the same
//! functions come from `libm`.

#[cfg(feature = "std")]
mod imp {
    pub fn log2(x: f64) -> f64 {
        x.log2()
    }
    pub fn sqrt(x: f64) -> f64 {
        x.sqrt()
    }
    pub fn cbrt(x: f64) -> f64 {
        x.cbrt()
    }
    pub fn exp(x: f64) -> f64 {
        x.exp()
    }
}

#[cfg(not(feature = "std"))]
mod imp {
    pub fn log2(x: f64) -> f64 {
        libm::log2(x)
    }
    pub fn sqrt(x: f64) -> f64 {
        libm::sqrt(x)
    }
    pub fn cbrt(x: f64) -> f64 {
        libm::cbrt(x)
    }
    pub fn exp(x: f64) -> f64 {
        libm::exp(x)
    }
}

pub use imp::{cbrt, exp, log2, sqrt};

/// Complementary error function (Chebyshev fit, relative error < 1.2e-7).
///
/// The same fit is used in both `std` and `libm` builds so results don't
/// depend on the feature set.
#[allow(
    clippy::unreadable_literal,
    clippy::excessive_precision,
    reason = "published coefficients, kept verbatim"
)]
pub fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let poly = -1.26551223
        + t * (1.00002368
            + t * (0.37409196
                + t * (0.09678418
                    + t * (-0.18628806
                        + t * (0.27886807
                            + t * (-1.13520398
                                + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277))))))));
    let ans = t * exp(-z * z + poly);
    if x >= 0.0 { ans } else { 2.0 - ans }
}

/// Upper-tail probability `P(X >= x)` for a chi-square variable with `dof`
/// degrees of freedom, using the Wilson–Hilferty normal approximation.
///
/// Accurate to a few parts in a thousand for `dof = 255`, which is all this
/// crate needs.
pub fn chi_square_upper_tail(x: f64, dof: f64) -> f64 {
    if x <= 0.0 {
        return 1.0;
    }
    let v = 2.0 / (9.0 * dof);
    let z = (cbrt(x / dof) - (1.0 - v)) / sqrt(v);
    (0.5 * erfc(z / core::f64::consts::SQRT_2)).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erfc_known_values() {
        assert!((erfc(0.0) - 1.0).abs() < 1e-7);
        assert!((erfc(1.0) - 0.157_299_207).abs() < 1e-7);
        assert!((erfc(-1.0) - 1.842_700_793).abs() < 1e-7);
        assert!(erfc(10.0) < 1e-40);
    }

    #[test]
    fn chi_square_tail_matches_reference() {
        // Reference quantiles of chi-square(255).
        assert!((chi_square_upper_tail(255.0, 255.0) - 0.4882).abs() < 2e-3);
        assert!((chi_square_upper_tail(293.25, 255.0) - 0.05).abs() < 2e-3);
        assert!((chi_square_upper_tail(310.46, 255.0) - 0.01).abs() < 1e-3);
        assert_eq!(chi_square_upper_tail(0.0, 255.0), 1.0);
    }
}
