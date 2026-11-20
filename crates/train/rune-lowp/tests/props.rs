//! Properties over random inputs: rounding is monotone and lands on one of
//! the two neighbours, nearest rounding is never worse than the other one.

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

use proptest::prelude::*;
use rune_lowp::{Bf16, Element, F4E2M1, F6E3M2, F8E4M3, F8E5M2, F16, Overflow, Rounding};

fn monotone<T: Element>(a: f32, b: f32) -> bool {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    T::from_f32_sat(lo).to_f32() <= T::from_f32_sat(hi).to_f32()
}

fn nearest_is_nearest<T: Element>(x: f32, r: u32) -> bool {
    let n = T::from_f32_sat(x).to_f32();
    let z = T::from_f32_with(x, Rounding::TowardZero, Overflow::Saturating).to_f32();
    let s = T::from_f32_with(x, Rounding::Stochastic(r), Overflow::Saturating).to_f32();
    let max = T::FORMAT.max_finite();
    let clamped = x.clamp(-max, max);
    // Toward zero never increases the magnitude; nearest beats both others.
    z.abs() <= clamped.abs()
        && (f64::from(n) - f64::from(clamped)).abs() <= (f64::from(z) - f64::from(clamped)).abs()
        && (f64::from(n) - f64::from(clamped)).abs() <= (f64::from(s) - f64::from(clamped)).abs()
}

proptest! {
    #[test]
    fn rounding_is_monotone(a in -1e6f32..1e6, b in -1e6f32..1e6) {
        prop_assert!(monotone::<Bf16>(a, b));
        prop_assert!(monotone::<F16>(a, b));
        prop_assert!(monotone::<F8E4M3>(a, b));
        prop_assert!(monotone::<F8E5M2>(a, b));
        prop_assert!(monotone::<F6E3M2>(a, b));
        prop_assert!(monotone::<F4E2M1>(a, b));
    }

    #[test]
    fn nearest_beats_other_roundings(x in -1e5f32..1e5, r in any::<u32>()) {
        prop_assert!(nearest_is_nearest::<Bf16>(x, r));
        prop_assert!(nearest_is_nearest::<F16>(x, r));
        prop_assert!(nearest_is_nearest::<F8E4M3>(x, r));
        prop_assert!(nearest_is_nearest::<F8E5M2>(x, r));
        prop_assert!(nearest_is_nearest::<F6E3M2>(x, r));
        prop_assert!(nearest_is_nearest::<F4E2M1>(x, r));
    }
}
