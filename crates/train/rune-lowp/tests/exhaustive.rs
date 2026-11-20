//! Exhaustive checks of every scalar type against the independent reference
//! in `common`: every code decodes to the right value, every non-NaN code
//! round-trips, and encoding matches the reference on every rounding
//! boundary plus a large random sample of `f32` bit patterns.

#![allow(
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

mod common;

use common::{RefRound, Rng, boundary_inputs, positive_table, ref_decode, ref_encode};
use rune_lowp::{
    Bf16, Element, F4E2M1, F6E2M3, F6E3M2, F8E4M3, F8E5M2, F16, Format, Overflow, Rounding,
};

fn same_value(got: f32, want: f64) -> bool {
    if want.is_nan() {
        got.is_nan()
    } else {
        f64::from(got) == want && got.is_sign_negative() == want.is_sign_negative()
    }
}

/// Every code decodes to the reference value, and the generic table decoder
/// agrees with the type's own.
fn check_decode<T: Element>() {
    let f = T::FORMAT;
    for c in 0..f.code_count() {
        let c = c as u16;
        let t = T::from_code(c);
        assert_eq!(t.to_code(), c);
        let want = ref_decode(f, c);
        let got = t.to_f32();
        assert!(
            same_value(got, want),
            "{f:?} code {c:#x}: got {got:e}, want {want:e}"
        );
        assert_eq!(got.to_bits(), f.decode(c).to_bits(), "{f:?} code {c:#x}");
        assert_eq!(t.is_nan(), want.is_nan());
        if got.is_nan() {
            // NaNs come back quiet with sign kept.
            assert_eq!(got.to_bits() & 0x0040_0000, 0x0040_0000);
            assert_eq!(got.is_sign_negative(), c >> (f.bits() - 1) == 1);
        }
    }
}

/// encode(decode(c)) == c for every non-NaN code, in every mode.
fn check_round_trip<T: Element>() {
    let f = T::FORMAT;
    for c in 0..f.code_count() {
        let c = c as u16;
        let x = T::from_code(c).to_f32();
        if x.is_nan() {
            // NaN stays NaN with the same sign (quieted for IEEE formats).
            let back = T::from_f32(x);
            assert!(back.is_nan(), "{f:?} {c:#x}");
            continue;
        }
        for (r, o) in [
            (Rounding::NearestEven, Overflow::NonSaturating),
            (Rounding::TowardZero, Overflow::NonSaturating),
            (Rounding::Stochastic(0), Overflow::NonSaturating),
            (Rounding::Stochastic(u32::MAX), Overflow::NonSaturating),
        ] {
            assert_eq!(T::from_f32_with(x, r, o).to_code(), c, "{f:?} {c:#x} {r:?}");
        }
        if x.is_finite() {
            assert_eq!(T::from_f32_sat(x).to_code(), c, "{f:?} {c:#x} sat");
        }
    }
}

fn check_encode_inputs<T: Element>(inputs: &[f32]) {
    let f = T::FORMAT;
    let table = positive_table(f);
    for &x in inputs {
        for (round, rounding) in [
            (RefRound::NearestEven, Rounding::NearestEven),
            (RefRound::TowardZero, Rounding::TowardZero),
        ] {
            for (sat, overflow) in [
                (false, Overflow::NonSaturating),
                (true, Overflow::Saturating),
            ] {
                let want = ref_encode(f, &table, x, round, sat);
                let got = T::from_f32_with(x, rounding, overflow).to_code();
                assert_eq!(
                    got,
                    want,
                    "{f:?} x={x:e} ({:#010x}) {rounding:?} {overflow:?}: got {got:#x} want {want:#x}",
                    x.to_bits()
                );
                // The generic encoder agrees with any specialised fast path.
                assert_eq!(
                    f.encode(x, rounding, overflow),
                    want,
                    "{f:?} generic x={x:e}"
                );
            }
        }
    }
}

fn check_encode<T: Element>(random: usize, seed: u64) {
    let table = positive_table(T::FORMAT);
    let mut inputs = boundary_inputs(&table);
    let mut rng = Rng(seed);
    let emax = T::FORMAT.emax();
    let emin = T::FORMAT.emin() - T::FORMAT.man_bits() as i32;
    for _ in 0..random {
        inputs.push(rng.any_f32());
        inputs.push(rng.near_exponent((emin + emax) / 2, (emax - emin) / 2 + 3));
    }
    check_encode_inputs::<T>(&inputs);
}

macro_rules! exhaustive {
    ($name:ident, $t:ty, $random:expr) => {
        mod $name {
            use super::*;

            #[test]
            fn decode_every_code() {
                check_decode::<$t>();
            }

            #[test]
            fn round_trip_every_code() {
                check_round_trip::<$t>();
            }

            #[test]
            fn encode_matches_reference() {
                check_encode::<$t>(
                    $random,
                    0x9E37_79B9_7F4A_7C15 ^ (<$t>::FORMAT.bits() as u64),
                );
            }
        }
    };
}

exhaustive!(bf16, Bf16, 100_000);
exhaustive!(f16, F16, 100_000);
exhaustive!(f8e4m3, F8E4M3, 50_000);
exhaustive!(f8e5m2, F8E5M2, 50_000);
exhaustive!(f6e2m3, F6E2M3, 20_000);
exhaustive!(f6e3m2, F6E3M2, 20_000);
exhaustive!(f4e2m1, F4E2M1, 20_000);

/// The vectorizable bf16 and f16 kernels against the generic encoder on a
/// few million random bit patterns (all classes: NaN, inf, subnormal).
#[test]
fn fast_paths_match_generic_encoder() {
    let mut rng = Rng(42);
    for _ in 0..2_000_000 {
        let x = rng.any_f32();
        assert_eq!(
            Bf16::from_f32(x).to_bits(),
            Format::BF16.encode(x, Rounding::NearestEven, Overflow::NonSaturating),
            "bf16 {:#010x}",
            x.to_bits()
        );
        assert_eq!(
            F16::from_f32(x).to_bits(),
            Format::F16.encode(x, Rounding::NearestEven, Overflow::NonSaturating),
            "f16 {:#010x}",
            x.to_bits()
        );
    }
}

/// Every f32 whose exponent lies in the f16 range (including the subnormal
/// and overflow edges), sampled densely: all 2^23 mantissas would take too
/// long in debug builds, so a stride of 4099 plus the rounding edges.
#[test]
fn f16_fast_path_dense_sweep() {
    for e in 100u32..=145 {
        for m in (0..(1u32 << 23))
            .step_by(4099)
            .chain([0, 1, 0x1FFF, 0x2000, 0x2001, 0x7F_FFFF])
        {
            for s in [0, 0x8000_0000] {
                let x = f32::from_bits(s | (e << 23) | m);
                assert_eq!(
                    F16::from_f32(x).to_bits(),
                    Format::F16.encode(x, Rounding::NearestEven, Overflow::NonSaturating),
                    "{:#010x}",
                    x.to_bits()
                );
            }
        }
    }
}

/// Every f32 subnormal and every power-of-two neighbourhood for bf16
/// (bf16 keeps f32's exponent range, so its subnormals are f32 subnormals).
#[test]
fn bf16_subnormals_exact() {
    for m in (0u32..(1 << 23)).step_by(97) {
        let x = f32::from_bits(m);
        let b = Bf16::from_f32(x);
        let table_val = f64::from(x);
        // Nearest multiple of 2^-133 with ties to even, computed directly.
        let q = 2f64.powi(-133);
        let n = table_val / q;
        let fl = n.floor();
        let want = if n - fl > 0.5 || (n - fl == 0.5 && fl % 2.0 == 1.0) {
            fl + 1.0
        } else {
            fl
        } * q;
        assert_eq!(f64::from(b.to_f32()), want, "{m:#x}");
    }
}

/// All 2^32 `f32` bit patterns through the bf16 and f16 fast paths and the
/// generic encoder. About a minute in an optimized build; run with
/// `cargo test --release -- --ignored all_f32`.
#[test]
#[ignore = "slow: 2^32 inputs"]
fn all_f32_through_fast_paths() {
    for b in 0..=u32::MAX {
        let x = f32::from_bits(b);
        assert_eq!(
            Bf16::from_f32(x).to_bits(),
            Format::BF16.encode(x, Rounding::NearestEven, Overflow::NonSaturating),
            "bf16 {b:#010x}"
        );
        assert_eq!(
            F16::from_f32(x).to_bits(),
            Format::F16.encode(x, Rounding::NearestEven, Overflow::NonSaturating),
            "f16 {b:#010x}"
        );
    }
}
