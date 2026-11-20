//! Generic minifloat formats and the exact `f32` encoder / decoder that
//! every scalar type in the crate is built on.

use crate::error::{LowpError, Result};

/// How a format uses the all-ones exponent field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Specials {
    /// IEEE 754 style: the all-ones exponent encodes infinity (mantissa 0)
    /// and NaN (any other mantissa). Used by `bf16`, `f16` and FP8 E5M2.
    Ieee,
    /// No infinities and a single NaN mantissa (all ones) per sign; the rest
    /// of the top binade holds finite values. Used by FP8 E4M3.
    NanOnly,
    /// Every code is a finite number. Used by the MX FP6 and FP4 element
    /// types.
    FiniteOnly,
}

/// Rounding direction for a narrowing conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Rounding {
    /// Round to nearest, ties to even (the IEEE 754 default).
    #[default]
    NearestEven,
    /// Truncate the magnitude. A finite value too large for the format
    /// becomes the largest finite value, as IEEE 754 specifies for this
    /// direction.
    TowardZero,
    /// Stochastic rounding: round the magnitude up with probability equal to
    /// the discarded fraction, using this 32-bit uniform random number.
    ///
    /// When at most 32 bits are discarded the probability is exact
    /// (`fraction = k / 2^n`, rounded up for exactly `k · 2^(32 - n)` of the
    /// `2^32` random values). When more are discarded (results far below
    /// the smallest subnormal) the fraction is truncated to 32 bits.
    Stochastic(u32),
}

/// What happens to finite values beyond the largest finite value of the
/// format, and to infinities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Overflow {
    /// IEEE behaviour: overflow produces infinity, or NaN for formats
    /// without infinity (FP8 E4M3). Infinities stay infinite (or become NaN).
    #[default]
    NonSaturating,
    /// Clamp to the largest finite magnitude, including infinite inputs.
    /// NaN stays NaN.
    Saturating,
}

/// A binary floating-point format with `1 + exp_bits + man_bits` bits:
/// sign, biased exponent, trailing significand.
///
/// All the crate's scalar types are instances of this; you can also build
/// your own (for example an E3M4 FP8 variant) with [`Format::new`] and use
/// [`Format::encode`] / [`Format::decode`] directly. Every representable
/// value of a valid format is exactly representable in `f32`, so decoding is
/// exact and encoding rounds exactly once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Format {
    exp_bits: u32,
    man_bits: u32,
    bias: i32,
    specials: Specials,
}

impl Format {
    /// IEEE binary16.
    pub const F16: Self = Self::raw(5, 10, 15, Specials::Ieee);
    /// bfloat16: the top half of an `f32`.
    pub const BF16: Self = Self::raw(8, 7, 127, Specials::Ieee);
    /// OCP FP8 E4M3: bias 7, no infinities, NaN = `S.1111.111`, max 448.
    pub const F8_E4M3: Self = Self::raw(4, 3, 7, Specials::NanOnly);
    /// OCP FP8 E5M2: bias 15, IEEE infinities and NaNs, max 57344.
    pub const F8_E5M2: Self = Self::raw(5, 2, 15, Specials::Ieee);
    /// OCP MX FP6 E2M3: bias 1, finite only, max 7.5.
    pub const F6_E2M3: Self = Self::raw(2, 3, 1, Specials::FiniteOnly);
    /// OCP MX FP6 E3M2: bias 3, finite only, max 28.
    pub const F6_E3M2: Self = Self::raw(3, 2, 3, Specials::FiniteOnly);
    /// OCP MX FP4 E2M1: bias 1, finite only, values ±{0, 0.5, 1, 1.5, 2, 3, 4, 6}.
    pub const F4_E2M1: Self = Self::raw(2, 1, 1, Specials::FiniteOnly);

    const fn raw(exp_bits: u32, man_bits: u32, bias: i32, specials: Specials) -> Self {
        Self {
            exp_bits,
            man_bits,
            bias,
            specials,
        }
    }

    /// Describes a format.
    ///
    /// Requirements: `1 <= exp_bits <= 8`, `1 + exp_bits + man_bits <= 16`,
    /// at least one mantissa bit for [`Specials::Ieee`] and
    /// [`Specials::NanOnly`], at least two exponent bits for
    /// [`Specials::Ieee`], and every value must fit exactly in `f32`
    /// (largest exponent at most 127, smallest subnormal at least `2^-149`).
    pub const fn new(exp_bits: u32, man_bits: u32, bias: i32, specials: Specials) -> Result<Self> {
        if exp_bits == 0 || exp_bits > 8 {
            return Err(LowpError::InvalidFormat("exp_bits must be in 1..=8"));
        }
        if 1 + exp_bits + man_bits > 16 {
            return Err(LowpError::InvalidFormat("formats are limited to 16 bits"));
        }
        match specials {
            Specials::Ieee if man_bits == 0 || exp_bits < 2 => {
                return Err(LowpError::InvalidFormat(
                    "IEEE-style formats need >= 2 exponent bits and >= 1 mantissa bit",
                ));
            }
            Specials::NanOnly if man_bits == 0 => {
                return Err(LowpError::InvalidFormat(
                    "NaN-only formats need a mantissa bit",
                ));
            }
            _ => {}
        }
        if bias < -127 || bias > 300 {
            return Err(LowpError::InvalidFormat("bias out of range"));
        }
        let f = Self::raw(exp_bits, man_bits, bias, specials);
        if f.emax() > 127 {
            return Err(LowpError::InvalidFormat(
                "largest value exceeds the f32 range",
            ));
        }
        if f.emin() - (man_bits as i32) < -149 {
            return Err(LowpError::InvalidFormat(
                "smallest subnormal is below the f32 range",
            ));
        }
        Ok(f)
    }

    /// Exponent field width.
    #[must_use]
    pub const fn exp_bits(&self) -> u32 {
        self.exp_bits
    }

    /// Trailing significand (mantissa) width.
    #[must_use]
    pub const fn man_bits(&self) -> u32 {
        self.man_bits
    }

    /// Exponent bias.
    #[must_use]
    pub const fn bias(&self) -> i32 {
        self.bias
    }

    /// Special-value convention.
    #[must_use]
    pub const fn specials(&self) -> Specials {
        self.specials
    }

    /// Total width in bits, sign included.
    #[must_use]
    pub const fn bits(&self) -> u32 {
        1 + self.exp_bits + self.man_bits
    }

    /// Number of distinct codes, `2^bits`.
    #[must_use]
    pub const fn code_count(&self) -> u32 {
        1 << self.bits()
    }

    /// Mask of the valid code bits.
    #[must_use]
    pub const fn code_mask(&self) -> u16 {
        // bits <= 16, so the shift is at most 16 and fits in u32.
        ((1u32 << self.bits()) - 1) as u16
    }

    const fn sign_bit(&self) -> u16 {
        1 << (self.exp_bits + self.man_bits)
    }

    const fn man_mask(&self) -> u32 {
        (1 << self.man_bits) - 1
    }

    const fn exp_all_ones(&self) -> u32 {
        (1 << self.exp_bits) - 1
    }

    /// Unbiased exponent of the smallest normal number, `1 - bias`.
    #[must_use]
    pub const fn emin(&self) -> i32 {
        1 - self.bias
    }

    /// Unbiased exponent of the largest finite number (the `emax` of the OCP
    /// MX spec): `floor(log2(max_finite))`.
    #[must_use]
    pub const fn emax(&self) -> i32 {
        self.max_biased() as i32 - self.bias
    }

    const fn max_biased(&self) -> u32 {
        match self.specials {
            Specials::Ieee => self.exp_all_ones() - 1,
            Specials::NanOnly | Specials::FiniteOnly => self.exp_all_ones(),
        }
    }

    const fn max_frac(&self) -> u32 {
        match self.specials {
            Specials::Ieee | Specials::FiniteOnly => self.man_mask(),
            Specials::NanOnly => self.man_mask() - 1,
        }
    }

    /// Code of the largest finite positive value.
    #[must_use]
    pub const fn max_code(&self) -> u16 {
        ((self.max_biased() << self.man_bits) | self.max_frac()) as u16
    }

    /// Code of `+inf`, if the format has one.
    #[must_use]
    pub const fn inf_code(&self) -> Option<u16> {
        match self.specials {
            Specials::Ieee => Some((self.exp_all_ones() << self.man_bits) as u16),
            Specials::NanOnly | Specials::FiniteOnly => None,
        }
    }

    /// Code of the canonical positive quiet NaN, if the format has one.
    #[must_use]
    pub const fn nan_code(&self) -> Option<u16> {
        match self.specials {
            Specials::Ieee => {
                Some(((self.exp_all_ones() << self.man_bits) | (1 << (self.man_bits - 1))) as u16)
            }
            Specials::NanOnly => {
                Some(((self.exp_all_ones() << self.man_bits) | self.man_mask()) as u16)
            }
            Specials::FiniteOnly => None,
        }
    }

    /// Code of `1.0`, if representable.
    #[must_use]
    pub const fn one_code(&self) -> Option<u16> {
        if self.emin() <= 0 && self.emax() >= 0 {
            Some(((self.bias as u32) << self.man_bits) as u16)
        } else {
            None
        }
    }

    /// Largest finite value.
    #[must_use]
    pub const fn max_finite(&self) -> f32 {
        self.decode(self.max_code())
    }

    /// Smallest positive normal value, `2^emin`.
    #[must_use]
    pub const fn min_normal(&self) -> f32 {
        self.decode(1 << self.man_bits)
    }

    /// Smallest positive subnormal value, `2^(emin - man_bits)`.
    #[must_use]
    pub const fn min_subnormal(&self) -> f32 {
        self.decode(1)
    }

    /// Distance from 1.0 to the next larger value, `2^-man_bits`.
    #[must_use]
    pub const fn epsilon(&self) -> f32 {
        f32::from_bits(pow2_bits(-(self.man_bits as i32)))
    }

    /// `true` if `code` (masked to the format width) is a NaN.
    #[must_use]
    pub const fn is_nan_code(&self, code: u16) -> bool {
        let c = (code & self.code_mask()) as u32;
        let e = (c >> self.man_bits) & self.exp_all_ones();
        let m = c & self.man_mask();
        match self.specials {
            Specials::Ieee => e == self.exp_all_ones() && m != 0,
            Specials::NanOnly => e == self.exp_all_ones() && m == self.man_mask(),
            Specials::FiniteOnly => false,
        }
    }

    /// Decodes a code (masked to the format width) to the exactly equal
    /// `f32`. NaNs keep their sign and payload and come back quiet, as
    /// hardware widening conversions do.
    #[must_use]
    pub const fn decode(&self, code: u16) -> f32 {
        f32::from_bits(self.decode_bits(code))
    }

    /// Like [`Format::decode`] but returns the `f32` bit pattern; usable in
    /// `const` contexts to build lookup tables.
    #[must_use]
    pub const fn decode_bits(&self, code: u16) -> u32 {
        let c = (code & self.code_mask()) as u32;
        let m_bits = self.man_bits;
        let sign = if c >> (self.exp_bits + m_bits) != 0 {
            0x8000_0000
        } else {
            0
        };
        let e = (c >> m_bits) & self.exp_all_ones();
        let m = c & self.man_mask();
        if e == self.exp_all_ones() {
            match self.specials {
                Specials::Ieee => {
                    if m == 0 {
                        return sign | 0x7F80_0000;
                    }
                    return sign | 0x7FC0_0000 | (m << (23 - m_bits));
                }
                Specials::NanOnly => {
                    if m == self.man_mask() {
                        return sign | 0x7FC0_0000;
                    }
                }
                Specials::FiniteOnly => {}
            }
        }
        if e == 0 {
            if m == 0 {
                return sign;
            }
            // value = m * 2^(emin - M); normalize.
            let p = m.ilog2(); // index of the top set bit
            let exp = p as i32 + self.emin() - m_bits as i32; // unbiased exponent
            if exp >= -126 {
                let frac = (m - (1 << p)) << (23 - p);
                return sign | (((exp + 127) as u32) << 23) | frac;
            }
            // f32 subnormal: bits = value / 2^-149.
            let shift = self.emin() - m_bits as i32 + 149;
            return sign | (m << shift as u32);
        }
        let exp = e as i32 - self.bias;
        sign | (((exp + 127) as u32) << 23) | (m << (23 - m_bits))
    }

    /// Encodes `x` with the given rounding and overflow behaviour.
    ///
    /// Rounding is applied once, to the exact value of `x`; subnormals are
    /// produced exactly. See [`Rounding`] and [`Overflow`] for the special
    /// cases. For [`Specials::FiniteOnly`] formats, out-of-range values and
    /// infinities always saturate (the OCP MX spec defines no other mode)
    /// and NaN maps to the largest positive value.
    #[must_use]
    pub fn encode(&self, x: f32, rounding: Rounding, overflow: Overflow) -> u16 {
        self.encode_scaled(x, 0, rounding, overflow)
    }

    /// Encodes `x · 2^-shift` exactly, without an intermediate `f32`
    /// rounding. Used for power-of-two block scales.
    pub(crate) fn encode_scaled(
        &self,
        x: f32,
        shift: i32,
        rounding: Rounding,
        overflow: Overflow,
    ) -> u16 {
        let b = x.to_bits();
        let negative = b >> 31 != 0;
        let a = b & 0x7FFF_FFFF;
        let sbit = if negative { self.sign_bit() } else { 0 };
        if a > 0x7F80_0000 {
            return self.encode_nan(sbit, a);
        }
        if a == 0x7F80_0000 {
            return self.encode_inf(sbit, overflow);
        }
        if a == 0 {
            return sbit;
        }
        // x = sig * 2^exp exactly.
        let (sig, exp) = if a >= 0x0080_0000 {
            ((a & 0x007F_FFFF) | 0x0080_0000, (a >> 23) as i32 - 150)
        } else {
            (a, -149)
        };
        let exp = exp.saturating_sub(shift);
        let k = exp + sig.ilog2() as i32; // floor(log2 |v|)
        if k > self.emax() {
            return self.overflow(sbit, rounding, overflow);
        }
        let man = self.man_bits as i32;
        let q = k.max(self.emin()) - man; // exponent of one unit in the last place
        let sh = i64::from(q) - i64::from(exp);
        let mut m = if sh <= 0 {
            // Exact: at most 24 significant bits shifted left within M+1 bits.
            sig << (-sh) as u32
        } else {
            round_shift(sig, sh, rounding)
        };
        let mut q = q;
        if m >> (self.man_bits + 1) != 0 {
            m >>= 1;
            q += 1;
        }
        let (biased, frac) = if m >> self.man_bits != 0 {
            ((q + man + self.bias) as u32, m & self.man_mask())
        } else {
            (0, m)
        };
        let max_biased = self.max_biased();
        if biased > max_biased || (biased == max_biased && frac > self.max_frac()) {
            return self.overflow(sbit, rounding, overflow);
        }
        sbit | ((biased << self.man_bits) | frac) as u16
    }

    const fn encode_nan(&self, sbit: u16, a: u32) -> u16 {
        match self.specials {
            Specials::Ieee => {
                let payload = (a & 0x007F_FFFF) >> (23 - self.man_bits);
                let quiet = 1 << (self.man_bits - 1);
                sbit | ((self.exp_all_ones() << self.man_bits) | quiet | payload) as u16
            }
            Specials::NanOnly => {
                sbit | ((self.exp_all_ones() << self.man_bits) | self.man_mask()) as u16
            }
            Specials::FiniteOnly => self.max_code(),
        }
    }

    const fn encode_inf(&self, sbit: u16, overflow: Overflow) -> u16 {
        match (self.specials, overflow) {
            (Specials::Ieee, Overflow::NonSaturating) => {
                sbit | (self.exp_all_ones() << self.man_bits) as u16
            }
            (Specials::NanOnly, Overflow::NonSaturating) => {
                sbit | ((self.exp_all_ones() << self.man_bits) | self.man_mask()) as u16
            }
            _ => sbit | self.max_code(),
        }
    }

    fn overflow(&self, sbit: u16, rounding: Rounding, overflow: Overflow) -> u16 {
        if overflow == Overflow::Saturating
            || rounding == Rounding::TowardZero
            || self.specials == Specials::FiniteOnly
        {
            return sbit | self.max_code();
        }
        self.encode_inf(sbit, overflow)
    }
}

/// `sig >> sh` rounded according to `rounding` (`sh >= 1`, `sig < 2^24`).
#[inline]
fn round_shift(sig: u32, sh: i64, rounding: Rounding) -> u32 {
    if sh >= 32 {
        // sig < 2^24 <= 2^(sh - 8): far below one half.
        return match rounding {
            Rounding::NearestEven | Rounding::TowardZero => 0,
            Rounding::Stochastic(r) => {
                // P(up) = sig / 2^sh, truncated to a 32-bit fraction.
                let drop = sh - 32;
                let threshold = if drop >= 32 { 0 } else { sig >> drop as u32 };
                u32::from(r < threshold)
            }
        };
    }
    let sh = sh as u32;
    let t = sig >> sh;
    let rem = sig & ((1 << sh) - 1);
    match rounding {
        Rounding::NearestEven => {
            let half = 1 << (sh - 1);
            t + u32::from(rem > half || (rem == half && t & 1 == 1))
        }
        Rounding::TowardZero => t,
        Rounding::Stochastic(r) => t + u32::from((r >> (32 - sh)) < rem),
    }
}

/// Bit pattern of the `f32` equal to `2^e`, for `-149 <= e <= 127`
/// (clamped to that range).
#[must_use]
pub(crate) const fn pow2_bits(e: i32) -> u32 {
    let e = if e < -149 {
        -149
    } else if e > 127 {
        127
    } else {
        e
    };
    if e >= -126 {
        ((e + 127) as u32) << 23
    } else {
        1 << (e + 149) as u32
    }
}

/// `2^e` as `f32`, clamped to `[2^-149, 2^127]`.
#[must_use]
pub(crate) const fn pow2(e: i32) -> f32 {
    f32::from_bits(pow2_bits(e))
}

/// `floor(log2 |x|)` for finite non-zero `x`, exact (subnormals included).
#[must_use]
pub(crate) const fn floor_log2(x: f32) -> i32 {
    let a = x.to_bits() & 0x7FFF_FFFF;
    if a >= 0x0080_0000 {
        (a >> 23) as i32 - 127
    } else {
        // subnormal: a * 2^-149
        a.ilog2() as i32 - 149
    }
}
