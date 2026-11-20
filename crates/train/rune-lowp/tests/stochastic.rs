//! Stochastic rounding: exact probabilities, unbiasedness, and agreement
//! between the scalar and bulk paths.

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
    Bf16, Element, F4E2M1, F6E2M3, F6E3M2, F8E4M3, F8E5M2, F16, LowpError, Overflow, Rounding,
    from_f32_slice_stochastic,
};

#[test]
fn probability_is_exact_at_the_threshold() {
    // 2.25 lies a quarter of the way from 2 to 3: rounds up for exactly the
    // random numbers below 2^30.
    assert_eq!(
        F4E2M1::from_f32_stochastic(2.25, (1 << 30) - 1).to_f32(),
        3.0
    );
    assert_eq!(F4E2M1::from_f32_stochastic(2.25, 1 << 30).to_f32(), 2.0);
    assert_eq!(F4E2M1::from_f32_stochastic(-2.25, 0).to_f32(), -3.0);
    assert_eq!(F4E2M1::from_f32_stochastic(-2.25, u32::MAX).to_f32(), -2.0);
    // bf16: 1 + 2^-9 is a quarter ulp above 1.
    let x = 1.0 + 2f32.powi(-9);
    assert_eq!(
        Bf16::from_f32_stochastic(x, (1 << 30) - 1).to_f32(),
        1.0 + 2f32.powi(-7)
    );
    assert_eq!(Bf16::from_f32_stochastic(x, 1 << 30).to_f32(), 1.0);
    // 32 discarded bits: 2^-10 is 2^-9 of the way from 0 to 0.5 in FP4.
    assert_eq!(
        F4E2M1::from_f32_stochastic(2f32.powi(-10), (1 << 23) - 1).to_f32(),
        0.5
    );
    assert_eq!(
        F4E2M1::from_f32_stochastic(2f32.powi(-10), 1 << 23).to_f32(),
        0.0
    );
    // 33 discarded bits: probability 2^-10, still exact.
    assert_eq!(
        F4E2M1::from_f32_stochastic(2f32.powi(-11), (1 << 22) - 1).to_f32(),
        0.5
    );
    assert_eq!(
        F4E2M1::from_f32_stochastic(2f32.powi(-11), 1 << 22).to_f32(),
        0.0
    );
    // Representable values never move.
    for r in [0, 1, u32::MAX / 2, u32::MAX] {
        assert_eq!(F8E4M3::from_f32_stochastic(0.375, r).to_f32(), 0.375);
    }
}

fn neighbours<T: Element>(x: f32) -> (f32, f32) {
    let lo = T::from_f32_with(x, Rounding::TowardZero, Overflow::Saturating).to_f32();
    let mag = lo.abs();
    // Next value away from zero.
    let code = T::from_f32(mag).to_code();
    let hi = T::from_code(code + 1).to_f32();
    (lo, if x < 0.0 { -hi } else { hi })
}

fn check_unbiased<T: Element>(xs: &[f32], seed: u64) {
    const N: usize = 100_000;
    let mut rng = Rng(seed);
    for &x in xs {
        let (lo, hi) = neighbours::<T>(x);
        let ulp = f64::from((hi - lo).abs());
        let mut sum = 0.0f64;
        for _ in 0..N {
            let y = T::from_f32_stochastic(x, rng.next_u32()).to_f32();
            assert!(
                y == lo || y == hi,
                "{:?}: {x} → {y}, expected {lo} or {hi}",
                T::FORMAT
            );
            sum += f64::from(y);
        }
        let mean = sum / N as f64;
        // Bernoulli: std of the mean = ulp · sqrt(p(1 - p) / N) <= ulp / (2 sqrt N).
        let tol = 6.0 * ulp / (2.0 * (N as f64).sqrt());
        assert!(
            (mean - f64::from(x)).abs() <= tol,
            "{:?}: x = {x}, mean = {mean}, tol = {tol}",
            T::FORMAT
        );
    }
}

#[test]
fn unbiased_for_every_type() {
    check_unbiased::<Bf16>(&[1.001, -3.172_9, 1e-39, 2.5e30], 1);
    check_unbiased::<F16>(&[1.001, -3.172_9, 3e-6, 1000.3], 2);
    check_unbiased::<F8E4M3>(&[0.3, -100.7, 0.0031, 1e-3], 3);
    check_unbiased::<F8E5M2>(&[0.3, -100.7, 1e-5, 30000.0], 4);
    check_unbiased::<F6E2M3>(&[0.3, -5.1, 0.07], 5);
    check_unbiased::<F6E3M2>(&[0.3, -21.0, 0.02], 6);
    check_unbiased::<F4E2M1>(&[0.3, -5.1, 2.9, 0.2], 7);
}

/// Accumulating tiny increments: nearest rounding stagnates, stochastic
/// rounding tracks the true sum in expectation.
#[test]
fn stochastic_accumulation_does_not_stagnate() {
    let mut rng = Rng(99);
    let steps = 20_000;
    let inc = 1e-3f32; // well below half a bf16 ulp at 1.0 (2^-8 ≈ 3.9e-3)
    let mut nearest = Bf16::ONE;
    let mut stochastic = Bf16::ONE;
    for _ in 0..steps {
        nearest = Bf16::from_f32(nearest.to_f32() + inc);
        stochastic = Bf16::from_f32_stochastic(stochastic.to_f32() + inc, rng.next_u32());
    }
    let want = 1.0 + steps as f32 * inc; // 21
    assert_eq!(nearest.to_f32(), 1.0);
    let got = stochastic.to_f32();
    assert!(
        (got - want).abs() / want < 0.05,
        "stochastic sum {got}, want {want}"
    );
}

#[test]
fn stochastic_overflow_respects_the_mode() {
    // 61440 is halfway between E5M2 max (57344) and the next step (inf).
    let mut seen_inf = false;
    let mut seen_max = false;
    for r in [0, u32::MAX] {
        let y = F8E5M2::from_f32_stochastic(61440.0, r).to_f32();
        seen_inf |= y.is_infinite();
        seen_max |= y == 57344.0;
        let s = F8E5M2::from_f32_with(61440.0, Rounding::Stochastic(r), Overflow::Saturating);
        assert_eq!(s.to_f32(), 57344.0);
    }
    assert!(seen_inf && seen_max);
}

#[test]
fn bulk_matches_scalar() {
    let mut rng = Rng(5);
    let n = 70_000; // above the parallel threshold
    let src: Vec<f32> = (0..n).map(|_| rng.uniform(-500.0, 500.0)).collect();
    let rand: Vec<u32> = (0..n).map(|_| rng.next_u32()).collect();
    let mut dst = vec![F8E4M3::ZERO; n];
    from_f32_slice_stochastic(&src, &rand, &mut dst, Overflow::Saturating)
        .unwrap_or_else(|e| unreachable!("{e}"));
    for i in 0..n {
        let want =
            F8E4M3::from_f32_with(src[i], Rounding::Stochastic(rand[i]), Overflow::Saturating);
        assert_eq!(dst[i].to_bits(), want.to_bits());
    }
    assert_eq!(
        from_f32_slice_stochastic(&src, &rand[1..], &mut dst, Overflow::Saturating),
        Err(LowpError::LengthMismatch {
            expected: n,
            found: n - 1
        })
    );
}
