//! Schedules, gradient utilities, loss scaling, EMA and QK-clip.

#![allow(
    clippy::unwrap_used,
    clippy::missing_const_for_fn,
    clippy::while_float,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::suboptimal_flops,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unreadable_literal
)]

mod common;

use common::Rng;
use proptest::prelude::*;
use rune_optim::{
    DecayShape, EmaWarmup, LossScaler, LossScalerConfig, OptimError, ParamEma, QkLayout, Schedule,
    accumulate, accumulation_factor, clip_grad_norm, global_norm, qk_clip, token_weight,
};

// ---------- schedules ----------

#[test]
fn schedules_hit_exact_endpoints() {
    let peak = 3e-4;
    let min = peak * 0.1;

    let w = Schedule::linear_warmup(peak, 100).unwrap();
    assert_eq!(w.value(0), 0.0);
    assert_eq!(w.value(50), peak * 0.5);
    assert_eq!(w.value(100), peak);
    assert_eq!(w.value(10_000), peak);

    let c = Schedule::warmup_cosine(peak, 100, 1000, 0.1).unwrap();
    assert_eq!(c.value(0), 0.0);
    assert_eq!(c.value(100), peak);
    assert!((c.value(550) - f64::midpoint(peak, min)).abs() < 1e-18);
    assert_eq!(c.value(1000), min);
    assert_eq!(c.value(u64::MAX), min);

    for shape in [
        DecayShape::Linear,
        DecayShape::Cosine,
        DecayShape::OneMinusSqrt,
    ] {
        let s = Schedule::warmup_stable_decay(peak, 100, 1000, 200, 0.1, shape).unwrap();
        assert_eq!(s.value(0), 0.0);
        assert_eq!(s.value(100), peak);
        assert_eq!(s.value(500), peak);
        assert_eq!(s.value(800), peak);
        assert!(s.value(801) < peak && s.value(999) > min);
        assert_eq!(s.value(1000), min);
        assert_eq!(s.value(2000), min);
    }
    let lin = Schedule::warmup_stable_decay(1.0, 0, 100, 100, 0.0, DecayShape::Linear).unwrap();
    assert_eq!(lin.value(0), 1.0);
    assert!((lin.value(25) - 0.75).abs() < 1e-15);
    let sq =
        Schedule::warmup_stable_decay(1.0, 0, 100, 100, 0.0, DecayShape::OneMinusSqrt).unwrap();
    assert!((sq.value(25) - 0.5).abs() < 1e-15);

    let inv = Schedule::inverse_sqrt(1.0, 10, 10).unwrap();
    assert_eq!(inv.value(10), 1.0);
    assert!((inv.value(40) - 0.5).abs() < 1e-15);
    assert_eq!(Schedule::inverse_sqrt(2.0, 0, 1).unwrap().value(0), 2.0);

    let pw = Schedule::piecewise_linear(vec![(10, 1.0), (20, 3.0), (40, 0.5)]).unwrap();
    assert_eq!(pw.value(0), 1.0);
    assert_eq!(pw.value(10), 1.0);
    assert_eq!(pw.value(15), 2.0);
    assert_eq!(pw.value(20), 3.0);
    assert_eq!(pw.value(40), 0.5);
    assert_eq!(pw.value(99), 0.5);

    assert_eq!(Schedule::constant(0.7).unwrap().value(12345), 0.7);

    let cat = Schedule::concat(
        vec![
            (10, Schedule::linear_warmup(1.0, 10).unwrap()),
            (5, Schedule::constant(1.0).unwrap()),
        ],
        Schedule::warmup_cosine(1.0, 0, 20, 0.0).unwrap(),
    );
    assert_eq!(cat.value(0), 0.0);
    assert_eq!(cat.value(9), 0.9);
    assert_eq!(cat.value(10), 1.0);
    assert_eq!(cat.value(15), 1.0);
    assert_eq!(cat.value(35), 0.0);
}

#[test]
fn schedule_validation() {
    assert!(matches!(
        Schedule::warmup_cosine(1.0, 11, 10, 0.0),
        Err(OptimError::InvalidSchedule(_))
    ));
    assert!(Schedule::warmup_cosine(1.0, 1, 10, 1.5).is_err());
    assert!(Schedule::warmup_cosine(f64::NAN, 1, 10, 0.0).is_err());
    assert!(Schedule::warmup_stable_decay(1.0, 90, 100, 20, 0.0, DecayShape::Linear).is_err());
    assert!(Schedule::warmup_stable_decay(1.0, 0, 10, 20, 0.0, DecayShape::Linear).is_err());
    assert!(Schedule::inverse_sqrt(1.0, 0, 0).is_err());
    assert!(Schedule::piecewise_linear(vec![]).is_err());
    assert!(Schedule::piecewise_linear(vec![(5, 1.0), (5, 2.0)]).is_err());
    assert!(Schedule::constant(f64::INFINITY).is_err());
}

proptest! {
    #[test]
    fn decays_stay_in_range_and_never_rise(
        warmup in 0u64..50, decay in 1u64..200, stable in 0u64..100, ratio in 0.0f64..=1.0,
        shape in prop_oneof![Just(DecayShape::Linear), Just(DecayShape::Cosine), Just(DecayShape::OneMinusSqrt)],
    ) {
        let total = warmup + stable + decay;
        let wsd = Schedule::warmup_stable_decay(2.0, warmup, total, decay, ratio, shape).unwrap();
        let cos = Schedule::warmup_cosine(2.0, warmup, total, ratio).unwrap();
        for s in [&wsd, &cos] {
            let mut prev = f64::INFINITY;
            for t in warmup..=total + 3 {
                let v = s.value(t);
                prop_assert!(v <= 2.0 && v >= 2.0 * ratio - 1e-15);
                prop_assert!(v <= prev + 1e-15);
                prev = v;
            }
            for t in 0..warmup {
                prop_assert!(s.value(t) <= s.value(t + 1));
            }
        }
    }
}

// ---------- norms and clipping ----------

#[test]
fn global_norm_detects_non_finite() {
    assert!(global_norm(&[]).finite);
    assert_eq!(global_norm(&[]).norm, 0.0);
    let n = global_norm(&[&[1.0, f32::INFINITY]]);
    assert!(!n.finite && n.norm.is_infinite());
    let n = global_norm(&[&[1.0], &[f32::NAN]]);
    assert!(!n.finite && n.norm.is_nan());
    // f32::MAX squared overflows f32 but not f64.
    let n = global_norm(&[&[f32::MAX, f32::MAX]]);
    assert!(n.finite);
    assert!((n.norm / (f64::from(f32::MAX) * 2f64.sqrt()) - 1.0).abs() < 1e-15);
}

#[test]
fn global_norm_matches_f64_sum_for_large_inputs() {
    let mut rng = Rng::new(31);
    let a = rng.vec_f32(100_000);
    let b = rng.vec_f32(3);
    let want: f64 = a
        .iter()
        .chain(&b)
        .map(|&v| f64::from(v) * f64::from(v))
        .sum::<f64>()
        .sqrt();
    assert!((global_norm(&[&a, &b]).norm - want).abs() < 1e-9 * want);
}

#[test]
fn clipping_is_exact() {
    let mut rng = Rng::new(32);
    let mut a = rng.vec_f32(50_000);
    let mut b = rng.vec_f32(17);
    let before = global_norm(&[&a, &b]).norm;
    let (a0, b0) = (a.clone(), b.clone());
    let n = clip_grad_norm(&mut [&mut a, &mut b], 1.5).unwrap();
    assert_eq!(n.norm, before);
    let s = (1.5 / before) as f32;
    assert!(a.iter().zip(&a0).all(|(x, y)| *x == y * s));
    assert!(b.iter().zip(&b0).all(|(x, y)| *x == y * s));
    let after = global_norm(&[&a, &b]).norm;
    assert!((after - 1.5).abs() < 1.5 * 1e-6, "{after}");

    // Below the limit: untouched, bit for bit.
    let mut c = vec![0.3f32, -0.4];
    let n = clip_grad_norm(&mut [&mut c], 0.5).unwrap();
    assert_eq!(c, [0.3, -0.4]);
    assert!((n.norm - 0.5).abs() < 1e-7);

    // Non-finite: untouched and reported.
    let mut d = vec![1e3f32, f32::NAN];
    let n = clip_grad_norm(&mut [&mut d], 1.0).unwrap();
    assert!(!n.finite && d[0] == 1e3);
    assert!(clip_grad_norm(&mut [&mut d], 0.0).is_err());
}

proptest! {
    #[test]
    fn clipped_norm_never_exceeds_limit(
        v in proptest::collection::vec(-1e3f32..1e3, 1..200), max in 1e-3f64..1e3,
    ) {
        let mut g = v.clone();
        let n = clip_grad_norm(&mut [&mut g], max).unwrap();
        let after = global_norm(&[&g]).norm;
        if n.norm > max {
            prop_assert!((after - max).abs() <= max * 1e-6);
        } else {
            prop_assert_eq!(g, v);
        }
    }
}

#[test]
fn accumulation_helpers() {
    let mut acc = vec![1.0f32, 2.0];
    accumulate(&mut acc, &[0.5, -1.0]).unwrap();
    assert_eq!(acc, [1.5, 1.0]);
    assert!(accumulate(&mut acc, &[1.0]).is_err());
    assert_eq!(accumulation_factor(4).unwrap(), 0.25);
    assert!(accumulation_factor(0).is_err());
    assert_eq!(token_weight(3, 12).unwrap(), 0.25);
    assert!(token_weight(13, 12).is_err());
    assert!(token_weight(0, 0).is_err());
}

// ---------- loss scaling ----------

#[test]
fn loss_scaler_grows_backs_off_and_clamps() {
    let cfg = LossScalerConfig {
        init_scale: 4.0,
        growth_interval: 3,
        min_scale: 1.0,
        max_scale: 16.0,
        ..Default::default()
    };
    let mut s = LossScaler::new(cfg).unwrap();
    assert_eq!(s.scale_loss(0.5), 2.0);
    for _ in 0..3 {
        assert!(s.update(false));
    }
    assert_eq!(s.scale(), 8.0);
    for _ in 0..9 {
        s.update(false);
    }
    assert_eq!(s.scale(), 16.0, "capped at max_scale");
    for _ in 0..10 {
        assert!(!s.update(true));
    }
    assert_eq!(s.scale(), 1.0, "floored at min_scale");
    assert_eq!(s.skipped_steps(), 10);

    // An overflow resets the growth counter.
    let mut s = LossScaler::new(cfg).unwrap();
    s.update(false);
    s.update(false);
    s.update(true);
    assert_eq!(s.scale(), 2.0);
    s.update(false);
    s.update(false);
    assert_eq!(s.scale(), 2.0);
    s.update(false);
    assert_eq!(s.scale(), 4.0);

    let mut g = vec![8.0f32, f32::INFINITY];
    assert!(s.unscale(&mut [&mut g]));
    assert_eq!(g[0], 2.0);
}

#[test]
fn loss_scaler_hysteresis() {
    let cfg = LossScalerConfig {
        init_scale: 64.0,
        hysteresis: 3,
        growth_interval: 2,
        ..Default::default()
    };
    let mut s = LossScaler::new(cfg).unwrap();
    assert!(!s.update(true));
    assert!(!s.update(true));
    assert_eq!(s.scale(), 64.0, "tolerated");
    s.update(true);
    assert_eq!(s.scale(), 32.0);
    s.update(true);
    assert_eq!(s.scale(), 16.0, "keeps backing off until it grows again");
    s.update(false);
    s.update(false);
    assert_eq!(s.scale(), 32.0);
    s.update(true);
    assert_eq!(s.scale(), 32.0, "hysteresis restored after growth");
}

#[test]
fn loss_scaler_validation() {
    let bad = [
        LossScalerConfig {
            init_scale: 0.0,
            ..Default::default()
        },
        LossScalerConfig {
            growth_factor: 0.5,
            ..Default::default()
        },
        LossScalerConfig {
            backoff_factor: 1.0,
            ..Default::default()
        },
        LossScalerConfig {
            growth_interval: 0,
            ..Default::default()
        },
        LossScalerConfig {
            hysteresis: 0,
            ..Default::default()
        },
        LossScalerConfig {
            min_scale: 10.0,
            max_scale: 1.0,
            ..Default::default()
        },
    ];
    for c in bad {
        assert!(LossScaler::new(c).is_err(), "{c:?}");
    }
}

// ---------- EMA ----------

#[test]
fn ema_follows_closed_form() {
    let mut ema = ParamEma::new(&[&[0.0, 10.0]], 0.5, EmaWarmup::None).unwrap();
    for _ in 0..3 {
        ema.update(&[&[1.0, 10.0]]).unwrap();
    }
    // 1 - 0.5^3
    assert_eq!(ema.shadow(0).unwrap(), [0.875, 10.0]);
    assert_eq!(ema.updates(), 3);
    let mut out = vec![0.0f32; 2];
    ema.copy_to(&mut [&mut out]).unwrap();
    assert_eq!(out, [0.875, 10.0]);
    assert!(ema.update(&[&[1.0]]).is_err());
    assert!(ema.update(&[]).is_err());
}

#[test]
fn ema_warmup() {
    let ratio = ParamEma::new(&[], 0.999, EmaWarmup::Ratio).unwrap();
    assert_eq!(ratio.decay_at(0), 0.1);
    assert_eq!(ratio.decay_at(10), 11.0 / 20.0);
    assert!((ratio.decay_at(1_000_000) - f64::from(0.999f32)).abs() < 1e-12);
    let power = ParamEma::new(
        &[],
        0.9999,
        EmaWarmup::Power {
            gamma: 1.0,
            power: 0.75,
        },
    )
    .unwrap();
    assert_eq!(power.decay_at(0), 0.0);
    assert!((power.decay_at(15) - (1.0 - 16f64.powf(-0.75))).abs() < 1e-15);
    assert!(ParamEma::new(&[], 1.0, EmaWarmup::None).is_err());
    // First update with the ratio warmup mostly copies the parameters.
    let mut e = ParamEma::new(&[&[0.0]], 0.99, EmaWarmup::Ratio).unwrap();
    e.update(&[&[1.0]]).unwrap();
    assert!((e.shadow(0).unwrap()[0] - 0.9).abs() < 1e-7);
}

// ---------- QK-clip ----------

#[test]
fn qk_clip_rescales_only_offending_heads_exactly() {
    // 4 query heads, 2 key heads (GQA groups {0,1} and {2,3}), head_dim 2, model_dim 3.
    let layout = QkLayout {
        num_heads: 4,
        num_kv_heads: 2,
        head_dim: 2,
        model_dim: 3,
    };
    let mut rng = Rng::new(41);
    let wq0 = rng.vec_f32(4 * 6);
    let wk0 = rng.vec_f32(2 * 6);
    let x = rng.vec_f32(3);
    let logit = |wq: &[f32], wk: &[f32], h: usize| -> f64 {
        let proj = |w: &[f32], row: usize| -> f64 {
            (0..3)
                .map(|j| f64::from(w[row * 3 + j]) * f64::from(x[j]))
                .sum()
        };
        (0..2)
            .map(|d| proj(wq, h * 2 + d) * proj(wk, (h / 2) * 2 + d))
            .sum()
    };
    let (mut wq, mut wk) = (wq0.clone(), wk0.clone());
    let gamma = qk_clip(
        &mut wq,
        &mut wk,
        layout,
        &[200.0, 50.0, 80.0, 90.0],
        100.0,
        0.5,
    )
    .unwrap();
    assert_eq!(gamma, [0.5, 1.0, 1.0, 1.0]);
    for (h, g) in gamma.iter().enumerate() {
        let before = logit(&wq0, &wk0, h);
        let after = logit(&wq, &wk, h);
        assert!(
            (after - f64::from(*g) * before).abs() < 1e-5 * (1.0 + before.abs()),
            "head {h}"
        );
    }
    // The second key head and its query heads are untouched.
    assert_eq!(wk[6..], wk0[6..]);
    assert_eq!(wq[12..], wq0[12..]);

    // Nothing above the threshold: no change at all.
    let (mut wq2, mut wk2) = (wq0.clone(), wk0.clone());
    qk_clip(
        &mut wq2,
        &mut wk2,
        layout,
        &[1.0, -5.0, 100.0, 0.0],
        100.0,
        0.5,
    )
    .unwrap();
    assert_eq!((wq2, wk2), (wq0.clone(), wk0.clone()));

    // Errors.
    let (mut a, mut b) = (wq0.clone(), wk0);
    assert!(qk_clip(&mut a, &mut b, layout, &[1.0; 3], 100.0, 0.5).is_err());
    assert!(qk_clip(&mut a, &mut b, layout, &[f32::NAN; 4], 100.0, 0.5).is_err());
    assert!(qk_clip(&mut a, &mut b, layout, &[1.0; 4], 0.0, 0.5).is_err());
    assert!(qk_clip(&mut a, &mut b, layout, &[1.0; 4], 1.0, 1.5).is_err());
    let odd = QkLayout {
        num_kv_heads: 3,
        ..layout
    };
    assert!(qk_clip(&mut a, &mut b, odd, &[1.0; 4], 1.0, 0.5).is_err());
    assert!(qk_clip(&mut a[..5], &mut b, layout, &[1.0; 4], 1.0, 0.5).is_err());
    assert_eq!(a, wq0);
}
