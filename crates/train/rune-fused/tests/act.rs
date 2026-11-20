//! Activations and gated units against f64 references and finite
//! differences.

#![allow(
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::excessive_precision,
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::redundant_clone,
    clippy::many_single_char_names,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::suboptimal_flops
)]

mod common;

use common::{Rng, assert_close, bits, check_fd, dot, same_on_all_pools};
use proptest::prelude::*;
use rune_fused::{
    Activation, FusedError, activation_backward, activation_forward, erf, glu_backward,
    glu_backward_fused, glu_forward, glu_forward_fused,
};

const ALL: [Activation; 4] = [
    Activation::Silu,
    Activation::GeluTanh,
    Activation::GeluErf,
    Activation::ReluSquared,
];

fn f64_act(a: Activation, x: f64) -> f64 {
    match a {
        Activation::Silu => x / (1.0 + (-x).exp()),
        Activation::GeluTanh => {
            let k = (2.0 / std::f64::consts::PI).sqrt();
            0.5 * x * (1.0 + (k * (x + 0.044_715 * x * x * x)).tanh())
        }
        Activation::GeluErf => 0.5 * x * (1.0 + erf(x / std::f64::consts::SQRT_2)),
        Activation::ReluSquared => x.max(0.0).powi(2),
    }
}

/// Inputs that stay clear of the ReLU kink so finite differences are
/// valid.
fn inputs(rng: &mut Rng, n: usize, scale: f32) -> Vec<f32> {
    rng.vec(n, scale)
        .into_iter()
        .map(|v| if v.abs() < 0.05 { v + 0.1 } else { v })
        .collect()
}

#[test]
fn forward_matches_reference() {
    let mut rng = Rng::new(10);
    let x = inputs(&mut rng, 500, 6.0);
    for a in ALL {
        let mut y = vec![0.0; x.len()];
        activation_forward(a, &x, &mut y).unwrap();
        let want: Vec<f64> = x.iter().map(|&v| f64_act(a, f64::from(v))).collect();
        assert_close("act", &y, &want, 1e-6, 1e-5);
    }
}

#[test]
fn known_values() {
    // GELU(1) = Φ(1) = 0.841344746068543.
    assert!((Activation::GeluErf.apply(1.0) - 0.841_344_75).abs() < 1e-7);
    assert!((Activation::GeluErf.apply(-1.0) + 0.158_655_25).abs() < 1e-7);
    // Far tail: x Φ(x) for x = -8 is -8 · 6.22e-16 = -4.98e-15, not 0.
    let tail = Activation::GeluErf.apply(-8.0);
    assert!((tail / -4.976_768_5e-15 - 1.0).abs() < 1e-5, "{tail}");
    assert_eq!(Activation::Silu.apply(0.0), 0.0);
    assert_eq!(Activation::Silu.derivative(0.0), 0.5);
    assert_eq!(Activation::GeluTanh.derivative(0.0), 0.5);
    assert_eq!(Activation::GeluErf.derivative(0.0), 0.5);
    assert_eq!(Activation::ReluSquared.apply(3.0), 9.0);
    assert_eq!(Activation::ReluSquared.derivative(3.0), 6.0);
    for a in ALL {
        assert!(a.apply(-200.0).is_finite() && a.apply(200.0).is_finite());
        assert!(a.derivative(-200.0).is_finite());
    }
}

#[test]
fn derivatives_by_finite_differences() {
    let mut rng = Rng::new(11);
    let x = inputs(&mut rng, 64, 4.0);
    let dy = rng.vec(64, 1.0);
    for a in ALL {
        let mut dx = vec![0.0; x.len()];
        activation_backward(a, &dy, &x, &mut dx).unwrap();
        check_fd("act dx", &x, &dx, 1e-2, 2e-3, |xp| {
            let mut y = vec![0.0; xp.len()];
            activation_forward(a, xp, &mut y).unwrap();
            dot(&y, &dy)
        });
    }
}

#[test]
fn gated_units_both_layouts() {
    let mut rng = Rng::new(12);
    let (rows, inter) = (5, 13);
    let gate = inputs(&mut rng, rows * inter, 3.0);
    let up = rng.vec(rows * inter, 2.0);
    let dy = rng.vec(rows * inter, 1.0);
    let mut gu = Vec::new();
    for r in 0..rows {
        gu.extend_from_slice(&gate[r * inter..(r + 1) * inter]);
        gu.extend_from_slice(&up[r * inter..(r + 1) * inter]);
    }
    for a in ALL {
        let mut y = vec![0.0; rows * inter];
        glu_forward(a, &gate, &up, &mut y).unwrap();
        let want: Vec<f64> = gate
            .iter()
            .zip(&up)
            .map(|(&g, &u)| f64_act(a, f64::from(g)) * f64::from(u))
            .collect();
        assert_close("glu", &y, &want, 1e-5, 1e-5);
        let mut yf = vec![0.0; rows * inter];
        glu_forward_fused(a, &gu, inter, &mut yf).unwrap();
        assert_eq!(bits(&y), bits(&yf));

        let (mut dg, mut du) = (vec![0.0; y.len()], vec![0.0; y.len()]);
        glu_backward(a, &dy, &gate, &up, &mut dg, &mut du).unwrap();
        let mut dgu = vec![0.0; gu.len()];
        glu_backward_fused(a, &dy, &gu, inter, &mut dgu).unwrap();
        for r in 0..rows {
            let row = &dgu[r * 2 * inter..(r + 1) * 2 * inter];
            assert_eq!(bits(&row[..inter]), bits(&dg[r * inter..(r + 1) * inter]));
            assert_eq!(bits(&row[inter..]), bits(&du[r * inter..(r + 1) * inter]));
        }
        let loss = |g: &[f32], u: &[f32]| {
            let mut y = vec![0.0; g.len()];
            glu_forward(a, g, u, &mut y).unwrap();
            dot(&y, &dy)
        };
        check_fd("glu dgate", &gate, &dg, 1e-2, 3e-3, |g| loss(g, &up));
        check_fd("glu dup", &up, &du, 1e-2, 3e-3, |u| loss(&gate, u));
        check_fd("glu fused", &gu, &dgu, 1e-2, 3e-3, |gu| {
            let mut y = vec![0.0; rows * inter];
            glu_forward_fused(a, gu, inter, &mut y).unwrap();
            dot(&y, &dy)
        });
    }
}

#[test]
fn shape_errors() {
    let mut out = [0.0f32; 3];
    assert!(matches!(
        glu_forward(Activation::Silu, &[0.0; 3], &[0.0; 2], &mut out),
        Err(FusedError::LengthMismatch { what: "up", .. })
    ));
    assert!(glu_forward_fused(Activation::Silu, &[0.0; 6], 0, &mut out).is_err());
    assert!(matches!(
        glu_forward_fused(Activation::Silu, &[0.0; 5], 1, &mut out),
        Err(FusedError::RaggedRows { .. })
    ));
    assert!(glu_forward_fused(Activation::Silu, &[0.0; 6], 1, &mut out[..2]).is_err());
    let mut d = [0.0f32; 6];
    assert!(glu_backward_fused(Activation::Silu, &[0.0; 2], &[0.0; 6], 1, &mut d).is_err());
    assert!(activation_forward(Activation::Silu, &[0.0; 2], &mut out).is_err());
}

#[test]
fn deterministic_across_thread_counts() {
    let mut rng = Rng::new(13);
    let (rows, inter) = (90, 600);
    let gu = rng.vec(rows * 2 * inter, 4.0);
    let dy = rng.vec(rows * inter, 1.0);
    for a in ALL {
        same_on_all_pools(|| {
            let mut y = vec![0.0; rows * inter];
            glu_forward_fused(a, &gu, inter, &mut y).unwrap();
            let mut d = vec![0.0; gu.len()];
            glu_backward_fused(a, &dy, &gu, inter, &mut d).unwrap();
            (bits(&y), bits(&d))
        });
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_fused_matches_reference(rows in 0usize..6, inter in 1usize..70, seed in any::<u64>()) {
        let mut rng = Rng::new(seed);
        let gu = rng.vec(rows * 2 * inter, 5.0);
        for a in ALL {
            let mut y = vec![0.0; rows * inter];
            glu_forward_fused(a, &gu, inter, &mut y).unwrap();
            let mut want = Vec::new();
            for r in gu.chunks(2 * inter) {
                for j in 0..inter {
                    want.push(f64_act(a, f64::from(r[j])) * f64::from(r[inter + j]));
                }
            }
            assert_close("fused", &y, &want, 1e-5, 1e-5);
        }
    }
}
