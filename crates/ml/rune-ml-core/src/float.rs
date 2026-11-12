//! The [`Float`] scalar trait, implemented for `f32` and `f64`.

use core::fmt::{Debug, Display};
use core::iter::Sum;
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

mod sealed {
    pub trait Sealed {}
    impl Sealed for f32 {}
    impl Sealed for f64 {}
}

/// A floating-point scalar: `f32` or `f64`.
///
/// Every container and kernel in this crate is generic over `Float`, so an
/// algorithm can be written once and run in single precision (half the
/// memory, twice the SIMD lanes) or double precision.
///
/// The trait is sealed: only `f32` and `f64` implement it, which lets the
/// crate add methods without a breaking change.
///
/// ```
/// use rune_ml_core::Float;
///
/// fn hypot<F: Float>(a: F, b: F) -> F {
///     (a * a + b * b).sqrt()
/// }
/// assert_eq!(hypot(3.0_f32, 4.0), 5.0);
/// assert_eq!(hypot(3.0_f64, 4.0), 5.0);
/// ```
pub trait Float:
    sealed::Sealed
    + Copy
    + Debug
    + Display
    + Default
    + PartialEq
    + PartialOrd
    + Send
    + Sync
    + 'static
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
    + Neg<Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
    + DivAssign
    + Sum
    + for<'a> Sum<&'a Self>
{
    /// `0`.
    const ZERO: Self;
    /// `1`.
    const ONE: Self;
    /// Machine epsilon.
    const EPSILON: Self;
    /// Smallest positive normal value.
    const MIN_POSITIVE: Self;
    /// Largest finite value.
    const MAX: Self;
    /// Positive infinity.
    const INFINITY: Self;
    /// Negative infinity.
    const NEG_INFINITY: Self;
    /// Not a number.
    const NAN: Self;

    /// Converts from `f64`, rounding to the nearest representable value.
    fn from_f64(v: f64) -> Self;
    /// Converts to `f64` (exact for both `f32` and `f64`).
    fn to_f64(self) -> f64;
    /// Converts a count or index, rounding if it exceeds the mantissa.
    fn from_usize(n: usize) -> Self;
    /// Square root.
    #[must_use]
    fn sqrt(self) -> Self;
    /// Absolute value.
    #[must_use]
    fn abs(self) -> Self;
    /// Larger of two values; a `NaN` operand yields the other one.
    #[must_use]
    fn max(self, other: Self) -> Self;
    /// Smaller of two values; a `NaN` operand yields the other one.
    #[must_use]
    fn min(self, other: Self) -> Self;
    /// `e^self`.
    #[must_use]
    fn exp(self) -> Self;
    /// Natural logarithm.
    #[must_use]
    fn ln(self) -> Self;
    /// `self^n` for an integer `n`.
    #[must_use]
    fn powi(self, n: i32) -> Self;
    /// `self^p` for a float `p`.
    #[must_use]
    fn powf(self, p: Self) -> Self;
    /// Fused multiply-add `self * a + b` (one rounding).
    #[must_use]
    fn mul_add(self, a: Self, b: Self) -> Self;
    /// `true` unless the value is infinite or `NaN`.
    fn is_finite(self) -> bool;
    /// `true` if the value is `NaN`.
    fn is_nan(self) -> bool;
}

macro_rules! impl_float {
    ($t:ident) => {
        impl Float for $t {
            const ZERO: Self = 0.0;
            const ONE: Self = 1.0;
            const EPSILON: Self = $t::EPSILON;
            const MIN_POSITIVE: Self = $t::MIN_POSITIVE;
            const MAX: Self = $t::MAX;
            const INFINITY: Self = $t::INFINITY;
            const NEG_INFINITY: Self = $t::NEG_INFINITY;
            const NAN: Self = $t::NAN;

            #[inline]
            #[allow(
                clippy::cast_possible_truncation,
                clippy::unnecessary_cast,
                reason = "rounding to the nearest f32 is the documented behaviour"
            )]
            fn from_f64(v: f64) -> Self {
                v as $t
            }
            #[inline]
            #[allow(
                clippy::cast_lossless,
                clippy::unnecessary_cast,
                reason = "f32 -> f64 is exact; `From` is not usable through the macro for f64 -> f64"
            )]
            fn to_f64(self) -> f64 {
                self as f64
            }
            #[inline]
            #[allow(
                clippy::cast_precision_loss,
                reason = "documented: counts beyond the mantissa round"
            )]
            fn from_usize(n: usize) -> Self {
                n as $t
            }
            #[inline]
            fn sqrt(self) -> Self {
                $t::sqrt(self)
            }
            #[inline]
            fn abs(self) -> Self {
                $t::abs(self)
            }
            #[inline]
            fn max(self, other: Self) -> Self {
                $t::max(self, other)
            }
            #[inline]
            fn min(self, other: Self) -> Self {
                $t::min(self, other)
            }
            #[inline]
            fn exp(self) -> Self {
                $t::exp(self)
            }
            #[inline]
            fn ln(self) -> Self {
                $t::ln(self)
            }
            #[inline]
            fn powi(self, n: i32) -> Self {
                $t::powi(self, n)
            }
            #[inline]
            fn powf(self, p: Self) -> Self {
                $t::powf(self, p)
            }
            #[inline]
            fn mul_add(self, a: Self, b: Self) -> Self {
                $t::mul_add(self, a, b)
            }
            #[inline]
            fn is_finite(self) -> bool {
                $t::is_finite(self)
            }
            #[inline]
            fn is_nan(self) -> bool {
                $t::is_nan(self)
            }
        }
    };
}

impl_float!(f32);
impl_float!(f64);

#[cfg(test)]
mod tests {
    use super::Float;

    fn roundtrip<F: Float>() {
        assert_eq!(F::from_f64(1.5).to_f64(), 1.5);
        assert_eq!(F::from_usize(7).to_f64(), 7.0);
        assert!(F::NAN.is_nan());
        assert!(!F::INFINITY.is_finite());
        assert_eq!(F::ONE.max(F::NAN), F::ONE);
        assert_eq!(
            F::from_f64(2.0).mul_add(F::from_f64(3.0), F::ONE).to_f64(),
            7.0
        );
    }

    #[test]
    fn both_precisions() {
        roundtrip::<f32>();
        roundtrip::<f64>();
    }
}
