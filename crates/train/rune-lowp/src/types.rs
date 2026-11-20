//! The scalar types: [`Bf16`], [`F16`], [`F8E4M3`], [`F8E5M2`], [`F6E2M3`],
//! [`F6E3M2`], [`F4E2M1`], and the [`Element`] trait they share.

use core::cmp::Ordering;
use core::fmt;

use crate::error::{LowpError, Result};
use crate::format::{Format, Overflow, Rounding};

mod sealed {
    pub trait Sealed {}
}

/// A low-precision floating-point element type.
///
/// Implemented by every floating-point scalar type in the crate (not by
/// [`E8M0`](crate::E8M0), which is an unsigned scale). The trait is sealed;
/// it exists so that slice conversions, scaling recipes and block formats can
/// be generic over the element type.
pub trait Element:
    Copy + Default + PartialEq + PartialOrd + fmt::Debug + Send + Sync + sealed::Sealed + 'static
{
    /// The bit-level format.
    const FORMAT: Format;

    /// Builds a value from its code; bits above the format width are ignored.
    fn from_code(code: u16) -> Self;

    /// The code (raw bit pattern), zero-extended to 16 bits.
    fn to_code(self) -> u16;

    /// Exact conversion to `f32`.
    fn to_f32(self) -> f32;

    /// Conversion from `f32` with explicit rounding and overflow behaviour.
    fn from_f32_with(x: f32, rounding: Rounding, overflow: Overflow) -> Self;

    /// Round to nearest even, non-saturating (IEEE semantics).
    #[must_use]
    fn from_f32(x: f32) -> Self {
        Self::from_f32_with(x, Rounding::NearestEven, Overflow::NonSaturating)
    }

    /// Round to nearest even, saturating to the largest finite value.
    #[must_use]
    fn from_f32_sat(x: f32) -> Self {
        Self::from_f32_with(x, Rounding::NearestEven, Overflow::Saturating)
    }

    /// Stochastic rounding with one 32-bit uniform random number,
    /// non-saturating.
    #[must_use]
    fn from_f32_stochastic(x: f32, random: u32) -> Self {
        Self::from_f32_with(x, Rounding::Stochastic(random), Overflow::NonSaturating)
    }

    /// `true` for NaN codes.
    #[must_use]
    fn is_nan(self) -> bool {
        Self::FORMAT.is_nan_code(self.to_code())
    }

    /// Bulk round-to-nearest-even conversion. `src` and `dst` have the same
    /// length (checked by the public slice functions).
    #[doc(hidden)]
    fn encode_slice(src: &[f32], dst: &mut [Self], overflow: Overflow) {
        for (d, &s) in dst.iter_mut().zip(src) {
            *d = Self::from_f32_with(s, Rounding::NearestEven, overflow);
        }
    }

    /// Bulk widening conversion.
    #[doc(hidden)]
    fn decode_slice(src: &[Self], dst: &mut [f32]) {
        for (d, &s) in dst.iter_mut().zip(src) {
            *d = s.to_f32();
        }
    }
}

/// 256-entry decode table (as `f32` bits) for formats of at most 8 bits.
const fn table(f: Format) -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = f.decode_bits(i as u16);
        i += 1;
    }
    t
}

macro_rules! scalar_common {
    ($name:ident, $repr:ty, $fmt:expr) => {
        impl $name {
            /// The bit-level format of this type.
            pub const FORMAT: Format = $fmt;
            /// Positive zero.
            pub const ZERO: Self = Self(0);
            /// Negative zero.
            pub const NEG_ZERO: Self = Self(Self::FORMAT.sign_bit_const() as $repr);
            /// Largest finite value.
            pub const MAX: Self = Self(Self::FORMAT.max_code() as $repr);
            /// Smallest (most negative) finite value.
            pub const MIN: Self =
                Self((Self::FORMAT.max_code() | Self::FORMAT.sign_bit_const()) as $repr);
            /// Smallest positive normal value.
            pub const MIN_POSITIVE: Self = Self((1 << Self::FORMAT.man_bits()) as $repr);
            /// Smallest positive subnormal value.
            pub const MIN_POSITIVE_SUBNORMAL: Self = Self(1);

            /// Round to nearest even, non-saturating (IEEE semantics).
            #[inline]
            #[must_use]
            pub fn from_f32(x: f32) -> Self {
                <Self as Element>::from_f32(x)
            }

            /// Round to nearest even, saturating to `±MAX`.
            #[inline]
            #[must_use]
            pub fn from_f32_sat(x: f32) -> Self {
                <Self as Element>::from_f32_sat(x)
            }

            /// Stochastic rounding with a 32-bit uniform random number,
            /// non-saturating. See [`Rounding::Stochastic`].
            #[inline]
            #[must_use]
            pub fn from_f32_stochastic(x: f32, random: u32) -> Self {
                <Self as Element>::from_f32_stochastic(x, random)
            }

            /// Conversion with explicit rounding and overflow behaviour.
            #[inline]
            #[must_use]
            pub fn from_f32_with(x: f32, rounding: Rounding, overflow: Overflow) -> Self {
                <Self as Element>::from_f32_with(x, rounding, overflow)
            }

            /// Exact conversion to `f32`.
            #[inline]
            #[must_use]
            pub fn to_f32(self) -> f32 {
                <Self as Element>::to_f32(self)
            }

            /// Raw bit pattern.
            #[inline]
            #[must_use]
            pub const fn to_bits(self) -> $repr {
                self.0
            }

            /// `true` for NaN codes.
            #[inline]
            #[must_use]
            pub fn is_nan(self) -> bool {
                <Self as Element>::is_nan(self)
            }

            /// `true` for values that are neither infinite nor NaN.
            #[inline]
            #[must_use]
            pub fn is_finite(self) -> bool {
                self.to_f32().is_finite()
            }

            /// `true` if the sign bit is set (including `-0` and negative NaNs).
            #[inline]
            #[must_use]
            pub const fn is_sign_negative(self) -> bool {
                (self.0 as u16) & Self::FORMAT.sign_bit_const() != 0
            }

            /// Absolute value (clears the sign bit).
            #[inline]
            #[must_use]
            pub const fn abs(self) -> Self {
                Self(((self.0 as u16) & !Self::FORMAT.sign_bit_const()) as $repr)
            }

            /// Negation (flips the sign bit).
            #[inline]
            #[must_use]
            pub const fn neg(self) -> Self {
                Self(((self.0 as u16) ^ Self::FORMAT.sign_bit_const()) as $repr)
            }
        }

        impl sealed::Sealed for $name {}

        impl Default for $name {
            fn default() -> Self {
                Self::ZERO
            }
        }

        /// IEEE equality on the decoded values: `NaN != NaN`, `+0 == -0`.
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.to_f32() == other.to_f32()
            }
        }

        /// IEEE ordering on the decoded values.
        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                self.to_f32().partial_cmp(&other.to_f32())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&self.to_f32(), f)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.to_f32(), f)
            }
        }

        impl From<$name> for f32 {
            fn from(x: $name) -> f32 {
                x.to_f32()
            }
        }

        impl core::ops::Neg for $name {
            type Output = Self;
            fn neg(self) -> Self {
                $name::neg(self)
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(
                &self,
                s: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                <$repr as serde::Serialize>::serialize(&self.0, s)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                d: D,
            ) -> core::result::Result<Self, D::Error> {
                let bits = <$repr as serde::Deserialize>::deserialize(d)?;
                Self::try_from_bits(bits).map_err(serde::de::Error::custom)
            }
        }
    };
}

/// Types whose code fills the whole storage integer.
macro_rules! scalar_full {
    ($name:ident, $repr:ty) => {
        impl $name {
            /// Builds a value from its bit pattern.
            #[inline]
            #[must_use]
            pub const fn from_bits(bits: $repr) -> Self {
                Self(bits)
            }

            /// Builds a value from its bit pattern; never fails for this type
            /// (provided for symmetry with the sub-byte types).
            #[allow(clippy::unnecessary_wraps, reason = "uniform API across widths")]
            pub const fn try_from_bits(bits: $repr) -> Result<Self> {
                Ok(Self(bits))
            }
        }
    };
}

/// Sub-byte types stored in the low bits of a `u8`.
macro_rules! scalar_narrow {
    ($name:ident) => {
        impl $name {
            /// Builds a value from its bit pattern; bits above the format
            /// width are ignored.
            #[inline]
            #[must_use]
            pub const fn from_bits(bits: u8) -> Self {
                Self(bits & Self::FORMAT.code_mask() as u8)
            }

            /// Builds a value from its bit pattern, rejecting bits above the
            /// format width.
            pub const fn try_from_bits(bits: u8) -> Result<Self> {
                if bits as u16 & !Self::FORMAT.code_mask() != 0 {
                    return Err(LowpError::InvalidBits {
                        bits: bits as u16,
                        width: Self::FORMAT.bits(),
                    });
                }
                Ok(Self(bits))
            }
        }
    };
}

/// Byte-sized element types decoded through a 256-entry table.
macro_rules! scalar_table {
    ($name:ident, $table:ident) => {
        static $table: [u32; 256] = table($name::FORMAT);

        impl Element for $name {
            const FORMAT: Format = $name::FORMAT;

            #[inline]
            fn from_code(code: u16) -> Self {
                Self((code & Self::FORMAT.code_mask()) as u8)
            }

            #[inline]
            fn to_code(self) -> u16 {
                u16::from(self.0)
            }

            #[inline]
            fn to_f32(self) -> f32 {
                f32::from_bits($table[usize::from(self.0)])
            }

            #[inline]
            fn from_f32_with(x: f32, rounding: Rounding, overflow: Overflow) -> Self {
                Self(Self::FORMAT.encode(x, rounding, overflow) as u8)
            }
        }
    };
}

impl Format {
    pub(crate) const fn sign_bit_const(&self) -> u16 {
        1 << (self.exp_bits() + self.man_bits())
    }
}

/// bfloat16: 1 sign, 8 exponent, 7 mantissa bits — the upper half of an
/// `f32`, with the same range.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Bf16(u16);

/// IEEE 754 binary16: 1 sign, 5 exponent, 10 mantissa bits, max 65504.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct F16(u16);

/// OCP FP8 E4M3 (bias 7): no infinities, NaN is `S.1111.111`, max 448,
/// smallest subnormal `2^-9`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct F8E4M3(u8);

/// OCP FP8 E5M2 (bias 15): IEEE-like with infinities and NaNs, max 57344,
/// smallest subnormal `2^-16`. The top byte of an `f16`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct F8E5M2(u8);

/// OCP MX FP6 E2M3 (bias 1): finite only, max 7.5, smallest subnormal
/// 0.125. Stored in the low 6 bits of a byte.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct F6E2M3(u8);

/// OCP MX FP6 E3M2 (bias 3): finite only, max 28, smallest subnormal
/// 0.0625. Stored in the low 6 bits of a byte.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct F6E3M2(u8);

/// OCP MX FP4 E2M1 (bias 1): finite only, values
/// `±{0, 0.5, 1, 1.5, 2, 3, 4, 6}`. Stored in the low 4 bits of a byte.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct F4E2M1(u8);

scalar_common!(Bf16, u16, Format::BF16);
scalar_common!(F16, u16, Format::F16);
scalar_common!(F8E4M3, u8, Format::F8_E4M3);
scalar_common!(F8E5M2, u8, Format::F8_E5M2);
scalar_common!(F6E2M3, u8, Format::F6_E2M3);
scalar_common!(F6E3M2, u8, Format::F6_E3M2);
scalar_common!(F4E2M1, u8, Format::F4_E2M1);

scalar_full!(Bf16, u16);
scalar_full!(F16, u16);
scalar_full!(F8E4M3, u8);
scalar_full!(F8E5M2, u8);
scalar_narrow!(F6E2M3);
scalar_narrow!(F6E3M2);
scalar_narrow!(F4E2M1);

scalar_table!(F8E4M3, E4M3_TABLE);
scalar_table!(F8E5M2, E5M2_TABLE);
scalar_table!(F6E2M3, E2M3_TABLE);
scalar_table!(F6E3M2, E3M2_TABLE);
scalar_table!(F4E2M1, E2M1_TABLE);

macro_rules! ieee_consts {
    ($name:ident, $repr:ty) => {
        impl $name {
            /// Positive infinity.
            pub const INFINITY: Self = Self((Self::FORMAT.max_code() + 1) as $repr);
            /// Negative infinity.
            pub const NEG_INFINITY: Self =
                Self(((Self::FORMAT.max_code() + 1) | Self::FORMAT.sign_bit_const()) as $repr);
            /// Canonical positive quiet NaN.
            pub const NAN: Self =
                Self((Self::FORMAT.max_code() + 1 + (1 << (Self::FORMAT.man_bits() - 1))) as $repr);
            /// One.
            pub const ONE: Self = Self((Self::FORMAT.bias() << Self::FORMAT.man_bits()) as $repr);
        }
    };
}

ieee_consts!(Bf16, u16);
ieee_consts!(F16, u16);
ieee_consts!(F8E5M2, u8);

impl F8E4M3 {
    /// The positive NaN, `0x7F` (`0xFF` is the negative one).
    pub const NAN: Self = Self(0x7F);
    /// One.
    pub const ONE: Self = Self(0x38);
}

impl F6E2M3 {
    /// One.
    pub const ONE: Self = Self(0x08);
}

impl F6E3M2 {
    /// One.
    pub const ONE: Self = Self(0x0C);
}

impl F4E2M1 {
    /// One.
    pub const ONE: Self = Self(0x02);
}

// ---- bf16 -----------------------------------------------------------------

/// Round-to-nearest-even, non-saturating bf16 encode: branch-free so that the
/// bulk loop vectorizes. NaNs keep sign and the top payload bits, quieted.
#[inline]
const fn bf16_rne(b: u32) -> u16 {
    let rounded = (b.wrapping_add(0x7FFF + ((b >> 16) & 1))) >> 16;
    let nan = (b >> 16) | 0x0040;
    if b & 0x7FFF_FFFF > 0x7F80_0000 {
        nan as u16
    } else {
        rounded as u16
    }
}

/// bf16 widening: a shift, with NaNs quieted.
#[inline]
const fn bf16_to_f32_bits(h: u16) -> u32 {
    let w = (h as u32) << 16;
    if w & 0x7FFF_FFFF > 0x7F80_0000 {
        w | 0x0040_0000
    } else {
        w
    }
}

impl Element for Bf16 {
    const FORMAT: Format = Format::BF16;

    #[inline]
    fn from_code(code: u16) -> Self {
        Self(code)
    }

    #[inline]
    fn to_code(self) -> u16 {
        self.0
    }

    #[inline]
    fn to_f32(self) -> f32 {
        f32::from_bits(bf16_to_f32_bits(self.0))
    }

    #[inline]
    fn from_f32_with(x: f32, rounding: Rounding, overflow: Overflow) -> Self {
        if rounding == Rounding::NearestEven && overflow == Overflow::NonSaturating {
            return Self(bf16_rne(x.to_bits()));
        }
        Self(Format::BF16.encode(x, rounding, overflow))
    }

    fn encode_slice(src: &[f32], dst: &mut [Self], overflow: Overflow) {
        if overflow == Overflow::NonSaturating {
            for (d, &s) in dst.iter_mut().zip(src) {
                *d = Self(bf16_rne(s.to_bits()));
            }
        } else {
            for (d, &s) in dst.iter_mut().zip(src) {
                *d = Self(Format::BF16.encode(s, Rounding::NearestEven, overflow));
            }
        }
    }

    fn decode_slice(src: &[Self], dst: &mut [f32]) {
        for (d, &s) in dst.iter_mut().zip(src) {
            *d = f32::from_bits(bf16_to_f32_bits(s.0));
        }
    }
}

// ---- f16 ------------------------------------------------------------------

/// Round-to-nearest-even, non-saturating f16 encode without branches on the
/// value class. The rounding is done by the FPU: scaling by `2^112` then
/// `2^-110` maps the f16 range onto f32 exponents where adding a suitable
/// power of two leaves exactly the f16 bits, correctly rounded, in the low
/// half (overflow to infinity and subnormals included).
#[inline]
fn f16_rne(x: f32) -> u16 {
    let scale_to_inf = f32::from_bits(0x7780_0000); // 2^112
    let scale_to_zero = f32::from_bits(0x0880_0000); // 2^-110
    let mut base = (x.abs() * scale_to_inf) * scale_to_zero;
    let w = x.to_bits();
    let shl1 = w.wrapping_add(w);
    let sign = w & 0x8000_0000;
    let bias = (shl1 & 0xFF00_0000).max(0x7100_0000);
    base += f32::from_bits((bias >> 1) + 0x0780_0000);
    let bits = base.to_bits();
    let exp_bits = (bits >> 13) & 0x7C00;
    let mantissa_bits = bits & 0x0FFF;
    let nonsign = exp_bits + mantissa_bits;
    let nan = 0x7E00 | ((w >> 13) & 0x03FF);
    ((sign >> 16) | if shl1 > 0xFF00_0000 { nan } else { nonsign }) as u16
}

/// f16 widening with integer operations only.
#[inline]
fn f16_to_f32_bits(h: u16) -> u32 {
    let h = u32::from(h);
    let sign = (h & 0x8000) << 16;
    let e = (h >> 10) & 0x1F;
    let m = h & 0x03FF;
    let normal = ((e + 112) << 23) | (m << 13);
    let special = 0x7F80_0000 | (m << 13) | if m == 0 { 0 } else { 0x0040_0000 };
    // m * 2^-24, exact (zero included).
    let sub = (m as f32 * f32::from_bits(0x3380_0000)).to_bits();
    sign | if e == 0x1F {
        special
    } else if e == 0 {
        sub
    } else {
        normal
    }
}

impl Element for F16 {
    const FORMAT: Format = Format::F16;

    #[inline]
    fn from_code(code: u16) -> Self {
        Self(code)
    }

    #[inline]
    fn to_code(self) -> u16 {
        self.0
    }

    #[inline]
    fn to_f32(self) -> f32 {
        f32::from_bits(f16_to_f32_bits(self.0))
    }

    #[inline]
    fn from_f32_with(x: f32, rounding: Rounding, overflow: Overflow) -> Self {
        if rounding == Rounding::NearestEven && overflow == Overflow::NonSaturating {
            return Self(f16_rne(x));
        }
        Self(Format::F16.encode(x, rounding, overflow))
    }

    fn encode_slice(src: &[f32], dst: &mut [Self], overflow: Overflow) {
        if overflow == Overflow::NonSaturating {
            for (d, &s) in dst.iter_mut().zip(src) {
                *d = Self(f16_rne(s));
            }
        } else {
            for (d, &s) in dst.iter_mut().zip(src) {
                *d = Self(Format::F16.encode(s, Rounding::NearestEven, overflow));
            }
        }
    }

    fn decode_slice(src: &[Self], dst: &mut [f32]) {
        for (d, &s) in dst.iter_mut().zip(src) {
            *d = f32::from_bits(f16_to_f32_bits(s.0));
        }
    }
}
