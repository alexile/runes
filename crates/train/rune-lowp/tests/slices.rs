//! Bulk conversions agree with the scalar conversions, sequentially and on
//! the parallel path.

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

use common::Rng;
use rune_lowp::{
    Bf16, Element, F4E2M1, F6E2M3, F6E3M2, F8E4M3, F8E5M2, F16, LowpError, Overflow,
    PARALLEL_THRESHOLD, from_f32_slice, from_f32_vec, from_f32_vec_with, to_f32_slice, to_f32_vec,
};

fn check<T: Element>(src: &[f32]) {
    for overflow in [Overflow::NonSaturating, Overflow::Saturating] {
        let mut dst = vec![T::default(); src.len()];
        from_f32_slice(src, &mut dst, overflow).unwrap();
        let v: Vec<T> = from_f32_vec_with(src, overflow);
        for ((d, w), &x) in dst.iter().zip(&v).zip(src) {
            let want = T::from_f32_with(x, rune_lowp::Rounding::NearestEven, overflow).to_code();
            assert_eq!(d.to_code(), want, "{:?} {x:e}", T::FORMAT);
            assert_eq!(w.to_code(), want);
        }
        let mut back = vec![0.0f32; src.len()];
        to_f32_slice(&dst, &mut back).unwrap();
        let back2 = to_f32_vec(&dst);
        for ((b, b2), d) in back.iter().zip(&back2).zip(&dst) {
            assert_eq!(b.to_bits(), d.to_f32().to_bits());
            assert_eq!(b2.to_bits(), d.to_f32().to_bits());
        }
    }
}

fn inputs(n: usize, seed: u64) -> Vec<f32> {
    let mut rng = Rng(seed);
    (0..n)
        .map(|i| match i % 4 {
            0 => rng.any_f32(),
            1 => rng.near_exponent(0, 20),
            2 => rng.near_exponent(-14, 4),
            _ => rng.uniform(-500.0, 500.0),
        })
        .collect()
}

#[test]
fn bulk_equals_scalar_small_and_large() {
    for n in [0, 1, 17, 1000, PARALLEL_THRESHOLD + 12_345] {
        let src = inputs(n, n as u64 + 1);
        check::<Bf16>(&src);
        check::<F16>(&src);
        check::<F8E4M3>(&src);
        check::<F8E5M2>(&src);
        check::<F6E2M3>(&src);
        check::<F6E3M2>(&src);
        check::<F4E2M1>(&src);
    }
}

#[test]
fn length_mismatch() {
    let mut dst = [Bf16::ZERO; 2];
    assert_eq!(
        from_f32_slice(&[1.0, 2.0, 3.0], &mut dst, Overflow::NonSaturating),
        Err(LowpError::LengthMismatch {
            expected: 3,
            found: 2
        })
    );
    let mut out = [0.0f32; 1];
    assert!(to_f32_slice(&dst, &mut out).is_err());
}

#[test]
fn every_f16_pattern_through_bulk_widening() {
    let codes: Vec<F16> = (0..=u16::MAX).map(F16::from_bits).collect();
    let wide = to_f32_vec(&codes);
    for (c, w) in codes.iter().zip(&wide) {
        assert_eq!(w.to_bits(), c.to_f32().to_bits());
    }
    // And back: every non-NaN pattern survives.
    let narrow: Vec<F16> = from_f32_vec(&wide);
    for (a, b) in codes.iter().zip(&narrow) {
        if !a.is_nan() {
            assert_eq!(a.to_bits(), b.to_bits());
        }
    }
}
