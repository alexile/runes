//! Independent reference implementation used by the integration tests.
//!
//! Decoding is done with `f64` arithmetic straight from the bit fields, and
//! encoding by searching the sorted list of representable values, so none
//! of the crate's bit manipulation is reused.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::float_cmp,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::suboptimal_flops,
    clippy::manual_midpoint,
    clippy::missing_const_for_fn,
    clippy::needless_range_loop,
    clippy::assert_is_empty,
    reason = "tests: exact float comparisons and bit casts are the point"
)]

use rune_lowp::{Format, Specials};

/// Value of a code, from its fields, in f64.
pub fn ref_decode(f: Format, code: u16) -> f64 {
    let e_bits = f.exp_bits();
    let m_bits = f.man_bits();
    let sign = if (code >> (e_bits + m_bits)) & 1 == 1 {
        -1.0
    } else {
        1.0
    };
    let e = i32::from((code >> m_bits) & ((1 << e_bits) - 1));
    let m = f64::from(code & ((1 << m_bits) - 1));
    let all_ones = (1 << e_bits) - 1;
    let frac_max = f64::from((1u32 << m_bits) - 1);
    if e == all_ones {
        match f.specials() {
            Specials::Ieee => {
                return if m == 0.0 {
                    sign * f64::INFINITY
                } else {
                    f64::NAN
                };
            }
            Specials::NanOnly if m == frac_max => return f64::NAN,
            _ => {}
        }
    }
    let scale = f64::from(1u32 << m_bits);
    if e == 0 {
        sign * (m / scale) * 2f64.powi(1 - f.bias())
    } else {
        sign * (1.0 + m / scale) * 2f64.powi(e - f.bias())
    }
}

/// Non-negative finite values in increasing order with their codes.
pub fn positive_table(f: Format) -> Vec<(f64, u16)> {
    let sign_bit = 1u32 << (f.exp_bits() + f.man_bits());
    let mut v: Vec<(f64, u16)> = (0..sign_bit)
        .map(|c| (ref_decode(f, c as u16), c as u16))
        .filter(|(x, _)| x.is_finite())
        .collect();
    v.sort_by(|a, b| a.0.total_cmp(&b.0));
    v
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RefRound {
    NearestEven,
    TowardZero,
}

/// Reference encoder.
pub fn ref_encode(f: Format, table: &[(f64, u16)], x: f32, round: RefRound, saturate: bool) -> u16 {
    let sign_bit: u16 = 1 << (f.exp_bits() + f.man_bits());
    let neg = x.is_sign_negative();
    let s = if neg { sign_bit } else { 0 };
    let max = table[table.len() - 1];
    let finite_only = f.specials() == Specials::FiniteOnly;
    let overflow_code = |finite_input: bool| -> u16 {
        if saturate || finite_only || (finite_input && round == RefRound::TowardZero) {
            return s | max.1;
        }
        match f.specials() {
            Specials::Ieee => s | f.inf_code().unwrap_or(0),
            Specials::NanOnly => s | f.nan_code().unwrap_or(0),
            Specials::FiniteOnly => s | max.1,
        }
    };
    if x.is_nan() {
        return match f.specials() {
            Specials::Ieee => {
                let payload = (x.to_bits() & 0x007F_FFFF) >> (23 - f.man_bits());
                s | f.nan_code().unwrap_or(0) | payload as u16
            }
            Specials::NanOnly => s | f.nan_code().unwrap_or(0),
            Specials::FiniteOnly => max.1,
        };
    }
    if x.is_infinite() {
        return overflow_code(false);
    }
    let a = f64::from(x.abs());
    if a > max.0 {
        if round == RefRound::TowardZero {
            return overflow_code(true);
        }
        let ulp = max.0 - table[table.len() - 2].0;
        let mid = max.0 + ulp / 2.0;
        if a < mid || (a == mid && max.1 & 1 == 0) {
            return s | max.1;
        }
        return overflow_code(true);
    }
    // Largest index with value <= a.
    let i = table.partition_point(|(v, _)| *v <= a) - 1;
    let lo = table[i];
    if lo.0 == a || i + 1 == table.len() {
        return s | lo.1;
    }
    if round == RefRound::TowardZero {
        return s | lo.1;
    }
    let hi = table[i + 1];
    let mid = (lo.0 + hi.0) / 2.0;
    let pick = if a < mid {
        lo
    } else if a > mid {
        hi
    } else if lo.1 & 1 == 0 {
        lo
    } else {
        hi
    };
    s | pick.1
}

/// Test inputs around every representable value: the values, the
/// midpoints between neighbours (and the virtual neighbour above max), and
/// the adjacent f32 values of each, both signs.
pub fn boundary_inputs(table: &[(f64, u16)]) -> Vec<f32> {
    let mut out = Vec::new();
    let mut push = |v: f64| {
        let x = v as f32;
        for y in [x, next_up(x), next_down(x)] {
            out.push(y);
            out.push(-y);
        }
    };
    for w in table.windows(2) {
        push(w[0].0);
        push((w[0].0 + w[1].0) / 2.0);
    }
    let max = table[table.len() - 1].0;
    let ulp = max - table[table.len() - 2].0;
    push(max);
    push(max + ulp / 2.0);
    push(max + ulp);
    push(max * 4.0);
    out.retain(|x| !x.is_nan());
    out.extend([
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::MAX,
        -f32::MAX,
        f32::MIN_POSITIVE,
    ]);
    out.extend([f32::from_bits(1), -f32::from_bits(1), 0.0, -0.0]);
    out
}

pub fn next_up(x: f32) -> f32 {
    if x.is_nan() || x == f32::INFINITY {
        return x;
    }
    if x == 0.0 {
        return f32::from_bits(1);
    }
    let b = x.to_bits();
    f32::from_bits(if x > 0.0 { b + 1 } else { b - 1 })
}

pub fn next_down(x: f32) -> f32 {
    -next_up(-x)
}

/// xorshift64* generator for test inputs.
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Uniform in [lo, hi).
    pub fn uniform(&mut self, lo: f32, hi: f32) -> f32 {
        let u = (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32;
        lo + (hi - lo) * u
    }

    /// Random f32 bit pattern (NaNs included).
    pub fn any_f32(&mut self) -> f32 {
        f32::from_bits(self.next_u32())
    }

    /// Random f32 with exponent in a window around `center` (log-uniform).
    pub fn near_exponent(&mut self, center: i32, spread: i32) -> f32 {
        let e = center + (self.next_u32() % (2 * spread as u32 + 1)) as i32 - spread;
        let e = e.clamp(-126, 127);
        let m = self.next_u32() & 0x007F_FFFF;
        let s = self.next_u32() & 0x8000_0000;
        f32::from_bits(s | (((e + 127) as u32) << 23) | m)
    }
}
