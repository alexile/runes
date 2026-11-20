//! The OCP MX shared-scale type [`E8M0`].

use core::fmt;

use crate::format::{floor_log2, pow2_bits};

/// An unsigned power-of-two scale: 8 exponent bits, no sign, no mantissa,
/// bias 127 (OCP MX spec, section 5.4).
///
/// Code `c` in `0..=254` is `2^(c - 127)`, so the range is `2^-127` to
/// `2^127`; `0xFF` is NaN. There is no zero and no infinity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct E8M0(u8);

impl E8M0 {
    /// `2^0`.
    pub const ONE: Self = Self(127);
    /// Smallest scale, `2^-127`.
    pub const MIN: Self = Self(0);
    /// Largest scale, `2^127`.
    pub const MAX: Self = Self(254);
    /// The NaN code, `0xFF`.
    pub const NAN: Self = Self(0xFF);
    /// Exponent bias.
    pub const BIAS: i32 = 127;

    /// Builds a scale from its bit pattern (every byte is valid).
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Raw bit pattern.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        self.0
    }

    /// `2^exponent`, or `None` if `exponent` is outside `-127..=127`.
    #[must_use]
    pub const fn from_exponent(exponent: i32) -> Option<Self> {
        if exponent < -127 || exponent > 127 {
            None
        } else {
            Some(Self((exponent + 127) as u8))
        }
    }

    /// `2^exponent` with the exponent clamped to `-127..=127`.
    #[must_use]
    pub const fn from_exponent_saturating(exponent: i32) -> Self {
        let e = if exponent < -127 {
            -127
        } else if exponent > 127 {
            127
        } else {
            exponent
        };
        Self((e + 127) as u8)
    }

    /// The unbiased exponent, or `None` for NaN.
    #[must_use]
    pub const fn exponent(self) -> Option<i32> {
        if self.0 == 0xFF {
            None
        } else {
            Some(self.0 as i32 - 127)
        }
    }

    /// `true` for the NaN code.
    #[must_use]
    pub const fn is_nan(self) -> bool {
        self.0 == 0xFF
    }

    /// Exact conversion to `f32` (`2^-127` is an `f32` subnormal).
    #[must_use]
    pub const fn to_f32(self) -> f32 {
        if self.0 == 0xFF {
            f32::NAN
        } else {
            f32::from_bits(pow2_bits(self.0 as i32 - 127))
        }
    }

    /// The largest power of two not above `|x|` (rounding the exponent
    /// toward minus infinity), saturating to [`E8M0::MIN`] / [`E8M0::MAX`].
    /// Zero maps to `MIN`, infinity to `MAX`, NaN to `NAN`.
    #[must_use]
    pub fn from_f32_floor(x: f32) -> Self {
        if x.is_nan() {
            return Self::NAN;
        }
        if x.is_infinite() {
            return Self::MAX;
        }
        if x == 0.0 {
            return Self::MIN;
        }
        Self::from_exponent_saturating(floor_log2(x))
    }

    /// The smallest power of two not below `|x|` (rounding the exponent
    /// toward plus infinity), saturating like [`E8M0::from_f32_floor`].
    #[must_use]
    pub fn from_f32_ceil(x: f32) -> Self {
        if x.is_nan() {
            return Self::NAN;
        }
        if x.is_infinite() {
            return Self::MAX;
        }
        if x == 0.0 {
            return Self::MIN;
        }
        let e = floor_log2(x);
        let exact = x.abs().to_bits() == pow2_bits(e);
        Self::from_exponent_saturating(if exact { e } else { e + 1 })
    }
}

impl Default for E8M0 {
    fn default() -> Self {
        Self::ONE
    }
}

impl fmt::Debug for E8M0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.exponent() {
            Some(e) => write!(f, "2^{e}"),
            None => f.write_str("NaN"),
        }
    }
}

impl fmt::Display for E8M0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<E8M0> for f32 {
    fn from(x: E8M0) -> Self {
        x.to_f32()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for E8M0 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for E8M0 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        u8::deserialize(d).map(Self)
    }
}
