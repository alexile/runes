//! RMSNorm and LayerNorm against f64 references and finite differences.

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
    clippy::suboptimal_flops,
    clippy::similar_names
)]

mod common;

use common::{Rng, assert_close, bits, check_fd, dot, same_on_all_pools, to64};
use proptest::prelude::*;
use rune_fused::{FusedError, LayerNorm, RmsNorm};

/// f64 RMSNorm: returns (y, rstd).
fn rms_ref(x: &[f64], w: Option<&[f64]>, off: f64, eps: f64, h: usize) -> (Vec<f64>, Vec<f64>) {
    let mut y = vec![0.0; x.len()];
    let mut rs = Vec::new();
    for (xr, yr) in x.chunks(h).zip(y.chunks_mut(h)) {
        let ms = xr.iter().map(|v| v * v).sum::<f64>() / h as f64;
        let r = 1.0 / (ms + eps).sqrt();
        rs.push(r);
        for j in 0..h {
            yr[j] = xr[j] * r * w.map_or(1.0, |w| w[j] + off);
        }
    }
    (y, rs)
}

/// f64 RMSNorm backward: (dx, dw).
fn rms_bwd_ref(
    dy: &[f64],
    x: &[f64],
    w: Option<&[f64]>,
    off: f64,
    eps: f64,
    h: usize,
) -> (Vec<f64>, Vec<f64>) {
    let (_, rs) = rms_ref(x, None, 0.0, eps, h);
    let mut dx = vec![0.0; x.len()];
    let mut dw = vec![0.0; h];
    for (i, r) in rs.iter().enumerate() {
        let (xr, dyr) = (&x[i * h..(i + 1) * h], &dy[i * h..(i + 1) * h]);
        let g: Vec<f64> = (0..h)
            .map(|j| dyr[j] * w.map_or(1.0, |w| w[j] + off))
            .collect();
        let c = (0..h).map(|j| g[j] * xr[j] * r).sum::<f64>() / h as f64;
        for j in 0..h {
            dx[i * h + j] = r * (g[j] - xr[j] * r * c);
            dw[j] += dyr[j] * xr[j] * r;
        }
    }
    (dx, dw)
}

/// f64 LayerNorm: (y, mean, rstd).
fn ln_ref(
    x: &[f64],
    w: Option<&[f64]>,
    b: Option<&[f64]>,
    eps: f64,
    h: usize,
) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let mut y = vec![0.0; x.len()];
    let (mut ms, mut rs) = (Vec::new(), Vec::new());
    for (xr, yr) in x.chunks(h).zip(y.chunks_mut(h)) {
        let m = xr.iter().sum::<f64>() / h as f64;
        let var = xr.iter().map(|v| (v - m) * (v - m)).sum::<f64>() / h as f64;
        let r = 1.0 / (var + eps).sqrt();
        ms.push(m);
        rs.push(r);
        for j in 0..h {
            yr[j] = (xr[j] - m) * r * w.map_or(1.0, |w| w[j]) + b.map_or(0.0, |b| b[j]);
        }
    }
    (y, ms, rs)
}

fn ln_bwd_ref(
    dy: &[f64],
    x: &[f64],
    w: Option<&[f64]>,
    eps: f64,
    h: usize,
) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let (_, ms, rs) = ln_ref(x, None, None, eps, h);
    let mut dx = vec![0.0; x.len()];
    let (mut dw, mut db) = (vec![0.0; h], vec![0.0; h]);
    for i in 0..rs.len() {
        let (m, r) = (ms[i], rs[i]);
        let (xr, dyr) = (&x[i * h..(i + 1) * h], &dy[i * h..(i + 1) * h]);
        let xh: Vec<f64> = xr.iter().map(|v| (v - m) * r).collect();
        let g: Vec<f64> = (0..h).map(|j| dyr[j] * w.map_or(1.0, |w| w[j])).collect();
        let a = g.iter().sum::<f64>() / h as f64;
        let c = (0..h).map(|j| g[j] * xh[j]).sum::<f64>() / h as f64;
        for j in 0..h {
            dx[i * h + j] = r * (g[j] - a - xh[j] * c);
            dw[j] += dyr[j] * xh[j];
            db[j] += dyr[j];
        }
    }
    (dx, dw, db)
}

fn rms_fwd(n: &RmsNorm, x: &[f32], w: Option<&[f32]>) -> (Vec<f32>, Vec<f32>) {
    let mut y = vec![0.0; x.len()];
    let mut r = vec![0.0; x.len() / n.hidden()];
    n.forward(x, w, &mut y, &mut r).unwrap();
    (y, r)
}

#[test]
fn rms_forward_matches_reference() {
    let mut rng = Rng::new(1);
    for &(rows, h) in &[(1, 1), (3, 7), (5, 128), (2, 300), (4, 1031)] {
        let x = rng.vec(rows * h, 2.0);
        let w = rng.vec(h, 1.0);
        for off in [false, true] {
            let n = RmsNorm::new(h, 1e-5).unwrap().with_unit_offset(off);
            let (y, r) = rms_fwd(&n, &x, Some(&w));
            let o = if off { 1.0 } else { 0.0 };
            let (ye, re) = rms_ref(&to64(&x), Some(&to64(&w)), o, 1e-5, h);
            assert_close("y", &y, &ye, 1e-6, 1e-5);
            assert_close("rstd", &r, &re, 0.0, 1e-6);
        }
        let (y, _) = rms_fwd(&RmsNorm::new(h, 1e-5).unwrap(), &x, None);
        assert_close(
            "y no weight",
            &y,
            &rms_ref(&to64(&x), None, 0.0, 1e-5, h).0,
            1e-6,
            1e-5,
        );
    }
}

#[test]
fn rms_backward_matches_reference_and_finite_differences() {
    let mut rng = Rng::new(2);
    let (rows, h) = (3, 9);
    let x = rng.vec(rows * h, 1.5);
    let w = rng.vec(h, 1.0);
    let dy = rng.vec(rows * h, 1.0);
    for off in [false, true] {
        let o = if off { 1.0 } else { 0.0 };
        let n = RmsNorm::new(h, 1e-3).unwrap().with_unit_offset(off);
        for weight in [Some(&w[..]), None] {
            let (_, r) = rms_fwd(&n, &x, weight);
            let mut dx = vec![0.0; x.len()];
            let mut dw = vec![0.0; h];
            n.backward(&dy, &x, weight, &r, &mut dx, Some(&mut dw))
                .unwrap();
            let w64 = weight.map(to64);
            let (dxe, dwe) = rms_bwd_ref(&to64(&dy), &to64(&x), w64.as_deref(), o, 1e-3, h);
            assert_close("dx", &dx, &dxe, 1e-5, 1e-4);
            assert_close("dw", &dw, &dwe, 1e-5, 1e-4);
            check_fd("rms dx", &x, &dx, 1e-2, 3e-3, |xp| {
                dot(&rms_fwd(&n, xp, weight).0, &dy)
            });
            if weight.is_some() {
                check_fd("rms dw", &w, &dw, 1e-2, 3e-3, |wp| {
                    dot(&rms_fwd(&n, &x, Some(wp)).0, &dy)
                });
            }
        }
    }
}

#[test]
fn rms_residual_fusion() {
    let mut rng = Rng::new(3);
    let (rows, h) = (4, 16);
    let x = rng.vec(rows * h, 1.0);
    let res0 = rng.vec(rows * h, 1.0);
    let w = rng.vec(h, 1.0);
    let n = RmsNorm::new(h, 1e-6).unwrap().with_unit_offset(true);
    let mut res = res0.clone();
    let mut y = vec![0.0; x.len()];
    let mut r = vec![0.0; rows];
    n.forward_residual(&x, &mut res, Some(&w), &mut y, &mut r)
        .unwrap();
    let sum: Vec<f32> = x.iter().zip(&res0).map(|(a, b)| a + b).collect();
    assert_eq!(bits(&res), bits(&sum));
    let (y2, r2) = rms_fwd(&n, &sum, Some(&w));
    assert_eq!(bits(&y), bits(&y2));
    assert_eq!(bits(&r), bits(&r2));

    // Loss = <dy, out> + <dres, residual_out>; d/dx = d/dresidual = dx.
    let dy = rng.vec(rows * h, 1.0);
    let dres = rng.vec(rows * h, 1.0);
    let mut dx = vec![0.0; x.len()];
    let mut dw = vec![0.0; h];
    n.backward_residual(&dy, &dres, &res, Some(&w), &r, &mut dx, Some(&mut dw))
        .unwrap();
    let loss = |xp: &[f32], rp: &[f32]| {
        let mut res = rp.to_vec();
        let mut y = vec![0.0; xp.len()];
        let mut r = vec![0.0; rows];
        n.forward_residual(xp, &mut res, Some(&w), &mut y, &mut r)
            .unwrap();
        dot(&y, &dy) + dot(&res, &dres)
    };
    check_fd("residual dx", &x, &dx, 1e-2, 3e-3, |xp| loss(xp, &res0));
    check_fd("residual dres", &res0, &dx, 1e-2, 3e-3, |rp| loss(&x, rp));
    check_fd("residual dw", &w, &dw, 1e-2, 3e-3, |wp| {
        let mut res = res0.clone();
        let mut y = vec![0.0; x.len()];
        let mut r = vec![0.0; rows];
        n.forward_residual(&x, &mut res, Some(wp), &mut y, &mut r)
            .unwrap();
        dot(&y, &dy) + dot(&res, &dres)
    });
}

fn ln_fwd(n: &LayerNorm, x: &[f32], w: Option<&[f32]>, b: Option<&[f32]>) -> Vec<f32> {
    let rows = x.len() / n.hidden();
    let mut y = vec![0.0; x.len()];
    let (mut m, mut r) = (vec![0.0; rows], vec![0.0; rows]);
    n.forward(x, w, b, &mut y, &mut m, &mut r).unwrap();
    y
}

#[test]
fn layer_norm_forward_matches_reference() {
    let mut rng = Rng::new(4);
    for &(rows, h) in &[(1, 1), (2, 5), (3, 128), (2, 777)] {
        // An offset makes the naive E[x²] - E[x]² formula lose digits.
        let x: Vec<f32> = rng.vec(rows * h, 1.0).iter().map(|v| v + 100.0).collect();
        let w = rng.vec(h, 1.0);
        let b = rng.vec(h, 1.0);
        let n = LayerNorm::new(h, 1e-5).unwrap();
        let mut y = vec![0.0; x.len()];
        let (mut m, mut r) = (vec![0.0; rows], vec![0.0; rows]);
        n.forward(&x, Some(&w), Some(&b), &mut y, &mut m, &mut r)
            .unwrap();
        let (ye, me, re) = ln_ref(&to64(&x), Some(&to64(&w)), Some(&to64(&b)), 1e-5, h);
        assert_close("mean", &m, &me, 0.0, 1e-6);
        assert_close("rstd", &r, &re, 0.0, 2e-3);
        assert_close("y", &y, &ye, 2e-3, 2e-3);
    }
}

#[test]
fn layer_norm_backward_matches_reference_and_finite_differences() {
    let mut rng = Rng::new(5);
    let (rows, h) = (3, 8);
    let x = rng.vec(rows * h, 1.5);
    let w = rng.vec(h, 1.0);
    let b = rng.vec(h, 1.0);
    let dy = rng.vec(rows * h, 1.0);
    let n = LayerNorm::new(h, 1e-3).unwrap();
    for weight in [Some(&w[..]), None] {
        let mut y = vec![0.0; x.len()];
        let (mut m, mut r) = (vec![0.0; rows], vec![0.0; rows]);
        n.forward(&x, weight, Some(&b), &mut y, &mut m, &mut r)
            .unwrap();
        let mut dx = vec![0.0; x.len()];
        let (mut dw, mut db) = (vec![0.0; h], vec![0.0; h]);
        n.backward(
            &dy,
            &x,
            weight,
            &m,
            &r,
            &mut dx,
            Some(&mut dw),
            Some(&mut db),
        )
        .unwrap();
        let w64 = weight.map(to64);
        let (dxe, dwe, dbe) = ln_bwd_ref(&to64(&dy), &to64(&x), w64.as_deref(), 1e-3, h);
        assert_close("dx", &dx, &dxe, 1e-5, 1e-4);
        assert_close("dw", &dw, &dwe, 1e-5, 1e-4);
        assert_close("db", &db, &dbe, 1e-5, 1e-4);
        check_fd("ln dx", &x, &dx, 1e-2, 3e-3, |xp| {
            dot(&ln_fwd(&n, xp, weight, Some(&b)), &dy)
        });
        check_fd("ln db", &b, &db, 1e-2, 3e-3, |bp| {
            dot(&ln_fwd(&n, &x, weight, Some(bp)), &dy)
        });
        if weight.is_some() {
            check_fd("ln dw", &w, &dw, 1e-2, 3e-3, |wp| {
                dot(&ln_fwd(&n, &x, Some(wp), Some(&b)), &dy)
            });
        }
    }
}

#[test]
fn param_grads_reduce_over_many_rows() {
    // More rows than one gradient block, and a row count that is not a
    // multiple of it.
    let mut rng = Rng::new(6);
    let (rows, h) = (64 * 5 + 7, 12);
    let x = rng.vec(rows * h, 1.0);
    let dy = rng.vec(rows * h, 1.0);
    let w = rng.vec(h, 1.0);
    let n = RmsNorm::new(h, 1e-5).unwrap();
    let (_, r) = rms_fwd(&n, &x, Some(&w));
    let mut dx = vec![0.0; x.len()];
    let mut dw = vec![0.0; h];
    n.backward(&dy, &x, Some(&w), &r, &mut dx, Some(&mut dw))
        .unwrap();
    let (_, dwe) = rms_bwd_ref(&to64(&dy), &to64(&x), Some(&to64(&w)), 0.0, 1e-5, h);
    assert_close("dw", &dw, &dwe, 1e-4, 1e-5);

    let ln = LayerNorm::new(h, 1e-5).unwrap();
    let (mut m, mut rs, mut y) = (vec![0.0; rows], vec![0.0; rows], vec![0.0; x.len()]);
    ln.forward(&x, None, None, &mut y, &mut m, &mut rs).unwrap();
    let mut db = vec![0.0; h];
    ln.backward(&dy, &x, None, &m, &rs, &mut dx, None, Some(&mut db))
        .unwrap();
    let (_, _, dbe) = ln_bwd_ref(&to64(&dy), &to64(&x), None, 1e-5, h);
    assert_close("db", &db, &dbe, 1e-4, 1e-5);
}

#[test]
fn deterministic_across_thread_counts() {
    let mut rng = Rng::new(7);
    let (rows, h) = (700, 129);
    let x = rng.vec(rows * h, 1.0);
    let res0 = rng.vec(rows * h, 1.0);
    let dy = rng.vec(rows * h, 1.0);
    let w = rng.vec(h, 1.0);
    let b = rng.vec(h, 1.0);
    let n = RmsNorm::new(h, 1e-5).unwrap().with_unit_offset(true);
    let ln = LayerNorm::new(h, 1e-5).unwrap();
    same_on_all_pools(|| {
        let mut res = res0.clone();
        let (mut y, mut r) = (vec![0.0; x.len()], vec![0.0; rows]);
        n.forward_residual(&x, &mut res, Some(&w), &mut y, &mut r)
            .unwrap();
        let (mut dx, mut dw) = (vec![0.0; x.len()], vec![0.0; h]);
        n.backward_residual(&dy, &dy, &res, Some(&w), &r, &mut dx, Some(&mut dw))
            .unwrap();
        let (mut ly, mut lm, mut lr) = (vec![0.0; x.len()], vec![0.0; rows], vec![0.0; rows]);
        ln.forward(&x, Some(&w), Some(&b), &mut ly, &mut lm, &mut lr)
            .unwrap();
        let (mut ldx, mut ldw, mut ldb) = (vec![0.0; x.len()], vec![0.0; h], vec![0.0; h]);
        ln.backward(
            &dy,
            &x,
            Some(&w),
            &lm,
            &lr,
            &mut ldx,
            Some(&mut ldw),
            Some(&mut ldb),
        )
        .unwrap();
        [y, r, dx, dw, ly, lm, lr, ldx, ldw, ldb].map(|v| bits(&v))
    });
}

#[test]
fn bad_shapes_are_errors_and_leave_outputs_alone() {
    assert!(RmsNorm::new(0, 1e-5).is_err());
    assert!(RmsNorm::new(4, -1.0).is_err());
    assert!(RmsNorm::new(4, f32::NAN).is_err());
    assert!(LayerNorm::new(0, 1e-5).is_err());
    let n = RmsNorm::new(4, 1e-5).unwrap();
    let mut y = [7.0f32; 8];
    let mut r = [7.0f32; 2];
    assert!(matches!(
        n.forward(&[1.0; 7], None, &mut y[..7], &mut r),
        Err(FusedError::RaggedRows { .. })
    ));
    assert!(matches!(
        n.forward(&[1.0; 8], Some(&[1.0; 3]), &mut y, &mut r),
        Err(FusedError::LengthMismatch { what: "weight", .. })
    ));
    assert!(n.forward(&[1.0; 8], None, &mut y, &mut r[..1]).is_err());
    let mut res = [0.0f32; 4];
    assert!(
        n.forward_residual(&[1.0; 8], &mut res, None, &mut y, &mut r)
            .is_err()
    );
    let mut dx = [7.0f32; 8];
    let mut dw = [7.0f32; 3];
    assert!(
        n.backward(
            &[1.0; 8],
            &[1.0; 8],
            None,
            &[1.0; 2],
            &mut dx,
            Some(&mut dw)
        )
        .is_err()
    );
    assert!(
        n.backward_residual(
            &[1.0; 8], &[1.0; 4], &[1.0; 8], None, &[1.0; 2], &mut dx, None
        )
        .is_err()
    );
    assert_eq!(y, [7.0; 8]);
    assert_eq!(r, [7.0; 2]);
    assert_eq!(dx, [7.0; 8]);
    assert_eq!(res, [0.0; 4]);
    let ln = LayerNorm::new(4, 1e-5).unwrap();
    let (mut m, mut rs) = ([0.0f32; 2], [0.0f32; 2]);
    assert!(
        ln.forward(&[1.0; 8], None, Some(&[0.0; 5]), &mut y, &mut m, &mut rs)
            .is_err()
    );
    // Empty input is fine.
    n.forward(&[], None, &mut [], &mut []).unwrap();
}

#[test]
fn constant_rows_are_finite() {
    let ln = LayerNorm::new(4, 1e-5).unwrap();
    let x = [3.0f32; 4];
    let (mut y, mut m, mut r) = ([0.0f32; 4], [0.0f32], [0.0f32]);
    ln.forward(&x, None, None, &mut y, &mut m, &mut r).unwrap();
    assert_eq!(y, [0.0; 4]);
    let n = RmsNorm::new(4, 1e-6).unwrap();
    n.forward(&[0.0; 4], None, &mut y, &mut r).unwrap();
    assert_eq!(y, [0.0; 4]);
    assert!(r[0].is_finite());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prop_rms_any_shape(rows in 0usize..9, h in 1usize..300, seed in any::<u64>(), off in any::<bool>()) {
        let mut rng = Rng::new(seed);
        let x = rng.vec(rows * h, 3.0);
        let w = rng.vec(h, 1.0);
        let dy = rng.vec(rows * h, 1.0);
        let n = RmsNorm::new(h, 1e-5).unwrap().with_unit_offset(off);
        let (y, r) = rms_fwd(&n, &x, Some(&w));
        let o = if off { 1.0 } else { 0.0 };
        let (ye, _) = rms_ref(&to64(&x), Some(&to64(&w)), o, 1e-5, h);
        assert_close("y", &y, &ye, 1e-5, 1e-5);
        let (mut dx, mut dw) = (vec![0.0; x.len()], vec![0.0; h]);
        n.backward(&dy, &x, Some(&w), &r, &mut dx, Some(&mut dw)).unwrap();
        let (dxe, dwe) = rms_bwd_ref(&to64(&dy), &to64(&x), Some(&to64(&w)), o, 1e-5, h);
        assert_close("dx", &dx, &dxe, 1e-4, 1e-4);
        assert_close("dw", &dw, &dwe, 1e-4, 1e-4);
    }

    #[test]
    fn prop_layer_norm_any_shape(rows in 0usize..9, h in 1usize..300, seed in any::<u64>()) {
        let mut rng = Rng::new(seed);
        let x = rng.vec(rows * h, 3.0);
        let w = rng.vec(h, 1.0);
        let b = rng.vec(h, 1.0);
        let dy = rng.vec(rows * h, 1.0);
        let n = LayerNorm::new(h, 1e-5).unwrap();
        let mut y = vec![0.0; x.len()];
        let (mut m, mut r) = (vec![0.0; rows], vec![0.0; rows]);
        n.forward(&x, Some(&w), Some(&b), &mut y, &mut m, &mut r).unwrap();
        let (ye, _, _) = ln_ref(&to64(&x), Some(&to64(&w)), Some(&to64(&b)), 1e-5, h);
        // h = 1 rows are constant: rstd = 1/sqrt(eps) amplifies rounding.
        if h > 1 {
            assert_close("y", &y, &ye, 1e-4, 1e-4);
        }
        let mut dx = vec![0.0; x.len()];
        let (mut dw, mut db) = (vec![0.0; h], vec![0.0; h]);
        n.backward(&dy, &x, Some(&w), &m, &r, &mut dx, Some(&mut dw), Some(&mut db)).unwrap();
        let (dxe, dwe, dbe) = ln_bwd_ref(&to64(&dy), &to64(&x), Some(&to64(&w)), 1e-5, h);
        if h > 1 {
            assert_close("dx", &dx, &dxe, 1e-3, 1e-3);
            assert_close("dw", &dw, &dwe, 1e-3, 1e-3);
        }
        assert_close("db", &db, &dbe, 1e-4, 1e-5);
    }
}
