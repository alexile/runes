//! Singular values of the Newton–Schulz output land in the documented band.

#![allow(
    clippy::unwrap_used,
    clippy::missing_const_for_fn,
    clippy::while_float,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::float_cmp,
    clippy::suboptimal_flops,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unreadable_literal
)]

mod common;

use common::{
    Rng, matmul, max_singular_power, singular_values, to_f32, to_f64, transpose,
    with_singular_values,
};
use rune_optim::{NewtonSchulz, OptimError};

/// The documented band with a little room for `f32` rounding.
const BAND: (f64, f64) = (0.67, 1.21);

fn ortho(g: &[f32], r: usize, c: usize) -> Vec<f64> {
    let mut o = vec![0.0f32; g.len()];
    NewtonSchulz::default()
        .orthogonalize(g, r, c, &mut o)
        .unwrap();
    to_f64(&o)
}

fn assert_band(o: &[f64], r: usize, c: usize, what: &str) {
    let s = singular_values(o, r, c);
    let (lo, hi) = (s[0], s[s.len() - 1]);
    assert!(
        lo >= BAND.0 && hi <= BAND.1,
        "{what}: singular values in [{lo}, {hi}]"
    );
    let pmax = max_singular_power(o, r, c);
    assert!(
        (pmax - hi).abs() < 1e-3 && pmax <= BAND.1,
        "{what}: power iteration {pmax} vs {hi}"
    );
}

/// The scalar map each singular value goes through: `s / ‖G‖_F` then the
/// quintic polynomial five times.
fn scalar_map(x: f64) -> f64 {
    let (a, b, c) = (3.4445f64, -4.7750, 2.0315);
    let mut s = x;
    for _ in 0..5 {
        s = a * s + b * s.powi(3) + c * s.powi(5);
    }
    s
}

#[test]
fn documented_threshold_reaches_band() {
    // Every relative singular value from 1.5e-3 up to 1 ends in
    // [0.68, 1.203].
    let mut x = 1.5e-3f64;
    while x <= 1.0 {
        let y = scalar_map(x);
        assert!((0.679..=1.203).contains(&y), "{x} -> {y}");
        x *= 1.01;
    }
}

#[test]
fn random_matrices_land_in_band() {
    // Rectangular Gaussian matrices have well-separated singular values.
    let mut rng = Rng::new(1);
    for (r, c) in [(32, 64), (64, 32), (16, 100), (100, 16)] {
        let g = rng.vec_f32(r * c);
        let o = ortho(&g, r, c);
        assert_band(&o, r, c, &format!("random {r}x{c}"));
    }
}

#[test]
fn square_random_matrices_follow_the_scalar_map() {
    // Square Gaussian matrices have singular values near 0, below what five
    // steps can lift. Each output singular value is the scalar map of an
    // input one, and the ones above the threshold land in the band.
    let mut rng = Rng::new(6);
    for n in [3, 24, 48] {
        let g = rng.vec_f32(n * n);
        let g64 = to_f64(&g);
        let fro = g64.iter().map(|v| v * v).sum::<f64>().sqrt();
        let mut want: Vec<f64> = singular_values(&g64, n, n)
            .iter()
            .map(|s| scalar_map(s / fro).abs())
            .collect();
        want.sort_by(f64::total_cmp);
        let got = singular_values(&ortho(&g, n, n), n, n);
        for (w, s) in want.iter().zip(&got) {
            assert!((w - s).abs() < 2e-3, "n={n}: {s} vs scalar map {w}");
        }
        for sin in singular_values(&g64, n, n) {
            if sin / fro >= 1.5e-3 {
                let y = scalar_map(sin / fro);
                assert!(y >= BAND.0 && y <= BAND.1);
            }
        }
        assert!(got[got.len() - 1] <= BAND.1);
    }
}

#[test]
fn ill_conditioned_matrices_land_in_band() {
    let mut rng = Rng::new(2);
    for (r, c, cond) in [(32, 48, 100.0f64), (48, 32, 100.0), (24, 24, 50.0)] {
        let k = r.min(c);
        let s: Vec<f64> = (0..k)
            .map(|i| cond.powf(-(i as f64) / (k as f64 - 1.0)))
            .collect();
        let g = to_f32(&with_singular_values(&mut rng, r, c, &s));
        let o = ortho(&g, r, c);
        assert_band(&o, r, c, &format!("cond {cond} {r}x{c}"));
        // The output is close to semi-orthogonal: O Oᵀ ≈ I within the band.
        let (m, n, oo) = if r <= c {
            (r, c, o.clone())
        } else {
            (c, r, transpose(&o, r, c))
        };
        let gram = matmul(&oo, &transpose(&oo, m, n), m, n, m);
        for i in 0..m {
            let d = gram[i * m + i];
            assert!(d > BAND.0 * BAND.0 && d < BAND.1 * BAND.1, "diag {d}");
        }
    }
}

#[test]
fn output_is_scale_invariant_and_shares_singular_vectors() {
    let mut rng = Rng::new(3);
    let g = rng.vec_f32(10 * 20);
    let g2: Vec<f32> = g.iter().map(|v| v * 1000.0).collect();
    let (a, b) = (ortho(&g, 10, 20), ortho(&g2, 10, 20));
    for (x, y) in a.iter().zip(&b) {
        assert!((x - y).abs() < 1e-4);
    }
    // The update points in a descent direction: <G, O> > 0.
    let dot: f64 = to_f64(&g).iter().zip(&a).map(|(x, y)| x * y).sum();
    assert!(dot > 0.0);
}

#[test]
fn null_directions_stay_small() {
    // Rank 2 in 6 × 6: the four zero singular values stay zero.
    let mut rng = Rng::new(4);
    let g = to_f32(&with_singular_values(&mut rng, 6, 6, &[1.0, 0.5]));
    let s = singular_values(&ortho(&g, 6, 6), 6, 6);
    assert!(s[3] < 1e-3, "{s:?}");
    assert!(s[4] >= BAND.0 && s[5] <= BAND.1, "{s:?}");
}

#[test]
fn zero_matrix_and_bad_shapes() {
    let mut o = vec![1.0f32; 6];
    NewtonSchulz::default()
        .orthogonalize(&[0.0; 6], 2, 3, &mut o)
        .unwrap();
    assert!(o.iter().all(|&v| v == 0.0));
    assert!(matches!(
        NewtonSchulz::default().orthogonalize(&[0.0; 6], 2, 2, &mut o),
        Err(OptimError::BadShape { .. })
    ));
    assert!(matches!(
        NewtonSchulz::default().orthogonalize(&[0.0; 4], 2, 2, &mut o),
        Err(OptimError::LengthMismatch { .. })
    ));
}
