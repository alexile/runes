//! Cross-entropy and fused linear cross-entropy against f64 references,
//! finite differences and the unfused matmul + loss.

#![allow(
    clippy::unwrap_used,
    clippy::similar_names,
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
    clippy::float_cmp
)]

mod common;

use common::{Rng, assert_close, bits, check_fd, same_on_all_pools, to64};
use proptest::prelude::*;
use rune_fused::{CrossEntropy, FusedError, LinearCrossEntropy, Reduction};
use rune_gemm::{MatMut, MatRef, gemm};

const IGNORE: i64 = -100;

#[derive(Clone, Copy)]
struct Opts {
    eps: f64,
    lambda: f64,
    cap: Option<f64>,
    mean: bool,
}

impl Opts {
    fn ce(self) -> CrossEntropy {
        CrossEntropy::new()
            .with_label_smoothing(self.eps as f32)
            .unwrap()
            .with_z_loss(self.lambda as f32)
            .unwrap()
            .with_softcap(self.cap.map(|c| c as f32))
            .unwrap()
            .with_reduction(if self.mean {
                Reduction::Mean
            } else {
                Reduction::Sum
            })
    }
}

fn all_opts() -> Vec<Opts> {
    let mut v = Vec::new();
    for eps in [0.0, 0.1] {
        for lambda in [0.0, 1e-2] {
            for cap in [None, Some(3.0)] {
                for mean in [true, false] {
                    v.push(Opts {
                        eps,
                        lambda,
                        cap,
                        mean,
                    });
                }
            }
        }
    }
    v
}

/// f64 reference: (loss, z-loss, dlogits).
fn ce_ref(x: &[f64], vocab: usize, targets: &[i64], o: Opts) -> (f64, f64, Vec<f64>) {
    let valid = targets.iter().filter(|&&t| t != IGNORE).count();
    let norm = if o.mean {
        if valid == 0 { 0.0 } else { 1.0 / valid as f64 }
    } else {
        1.0
    };
    let (mut loss, mut zl) = (0.0, 0.0);
    let mut g = vec![0.0; x.len()];
    for (r, &t) in targets.iter().enumerate() {
        if t == IGNORE {
            continue;
        }
        let y = t as usize;
        let row = &x[r * vocab..(r + 1) * vocab];
        let z: Vec<f64> = row
            .iter()
            .map(|&v| o.cap.map_or(v, |c| c * (v / c).tanh()))
            .collect();
        let m = z.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let lse = m + z.iter().map(|v| (v - m).exp()).sum::<f64>().ln();
        let mean_z = z.iter().sum::<f64>() / vocab as f64;
        let l = (1.0 - o.eps) * (lse - z[y]) + o.eps * (lse - mean_z) + o.lambda * lse * lse;
        loss += l;
        zl += o.lambda * lse * lse;
        for j in 0..vocab {
            let p = (z[j] - lse).exp();
            let mut d = p * (1.0 + 2.0 * o.lambda * lse) - o.eps / vocab as f64;
            if j == y {
                d -= 1.0 - o.eps;
            }
            if let Some(c) = o.cap {
                d *= 1.0 - (z[j] / c).powi(2);
            }
            g[r * vocab + j] = d * norm;
        }
    }
    (loss * norm, zl * norm, g)
}

fn matmul64(a: &[f64], b: &[f64], m: usize, k: usize, n: usize, bt: bool) -> Vec<f64> {
    // C = A · B (B: k × n) or A · Bᵀ (B: n × k).
    let mut c = vec![0.0; m * n];
    for i in 0..m {
        for j in 0..n {
            let mut s = 0.0;
            for p in 0..k {
                let bv = if bt { b[j * k + p] } else { b[p * n + j] };
                s += a[i * k + p] * bv;
            }
            c[i * n + j] = s;
        }
    }
    c
}

fn transpose(a: &[f64], rows: usize, cols: usize) -> Vec<f64> {
    let mut t = vec![0.0; a.len()];
    for i in 0..rows {
        for j in 0..cols {
            t[j * rows + i] = a[i * cols + j];
        }
    }
    t
}

/// f64 linear + CE: (loss, z-loss, dhidden, dweight).
fn fused_ref(
    h: &[f32],
    w: &[f32],
    t: usize,
    hd: usize,
    v: usize,
    targets: &[i64],
    o: Opts,
) -> (f64, f64, Vec<f64>, Vec<f64>) {
    let (h, w) = (to64(h), to64(w));
    let logits = matmul64(&h, &w, t, hd, v, true);
    let (loss, zl, g) = ce_ref(&logits, v, targets, o);
    let dh = matmul64(&g, &w, t, v, hd, false);
    let dw = matmul64(&transpose(&g, t, v), &h, v, t, hd, false);
    (loss, zl, dh, dw)
}

fn targets_with_ignores(rng: &mut Rng, t: usize, v: usize) -> Vec<i64> {
    (0..t)
        .map(|_| {
            if rng.below(4) == 0 {
                IGNORE
            } else {
                rng.below(v) as i64
            }
        })
        .collect()
}

#[test]
fn standalone_matches_reference() {
    let mut rng = Rng::new(30);
    let (t, v) = (7, 37);
    let x = rng.vec(t * v, 4.0);
    let targets = targets_with_ignores(&mut rng, t, v);
    for o in all_opts() {
        let ce = o.ce();
        let (le, ze, ge) = ce_ref(&to64(&x), v, &targets, o);
        let mut lse = vec![0.0; t];
        let out = ce.forward(&x, v, &targets, &mut lse).unwrap();
        assert!((f64::from(out.loss) - le).abs() < 1e-5 * (1.0 + le.abs()));
        assert!((f64::from(out.z_loss) - ze).abs() < 1e-6 * (1.0 + ze.abs()));
        assert_eq!(
            out.valid_tokens,
            targets.iter().filter(|&&t| t != IGNORE).count()
        );
        let mut g = vec![0.0; x.len()];
        ce.backward(1.0, &x, v, &targets, &lse, &mut g).unwrap();
        assert_close("backward", &g, &ge, 1e-6, 1e-4);
        // Upstream gradient scales linearly.
        let mut g2 = vec![0.0; x.len()];
        ce.backward(2.0, &x, v, &targets, &lse, &mut g2).unwrap();
        let ge2: Vec<f64> = ge.iter().map(|v| 2.0 * v).collect();
        assert_close("backward x2", &g2, &ge2, 2e-6, 1e-4);
        let mut g3 = vec![0.0; x.len()];
        let out3 = ce.forward_backward(&x, v, &targets, &mut g3).unwrap();
        assert_eq!(out3, out);
        assert_close("forward_backward", &g3, &ge, 1e-6, 1e-4);
    }
}

#[test]
fn standalone_finite_differences() {
    let mut rng = Rng::new(31);
    let (t, v) = (3, 6);
    let x = rng.vec(t * v, 2.0);
    let targets = [2i64, IGNORE, 5];
    for o in all_opts() {
        let ce = o.ce();
        let mut g = vec![0.0; x.len()];
        ce.forward_backward(&x, v, &targets, &mut g).unwrap();
        check_fd("ce dlogits", &x, &g, 1e-2, 2e-3, |xp| {
            let mut lse = vec![0.0; t];
            f64::from(ce.forward(xp, v, &targets, &mut lse).unwrap().loss)
        });
    }
}

#[test]
fn extreme_and_masked_logits() {
    let ce = CrossEntropy::new();
    let mut g = [0.0f32; 3];
    let mut lse = [0.0f32];
    let big = [1e30f32, 0.0, -1e30];
    assert_eq!(ce.forward(&big, 3, &[0], &mut lse).unwrap().loss, 0.0);
    assert_eq!(ce.forward(&big, 3, &[1], &mut lse).unwrap().loss, 1e30);
    ce.forward_backward(&big, 3, &[0], &mut g).unwrap();
    assert_eq!(g, [0.0, 0.0, 0.0]);
    ce.forward_backward(&big, 3, &[2], &mut g).unwrap();
    assert_eq!(g, [1.0, 0.0, -1.0]);

    // -inf masks a class out entirely.
    let masked = [0.0f32, f32::NEG_INFINITY, 0.0];
    let out = ce.forward(&masked, 3, &[0], &mut lse).unwrap();
    assert!((out.loss - 2f32.ln()).abs() < 1e-7);
    ce.forward_backward(&masked, 3, &[0], &mut g).unwrap();
    assert_eq!(g, [-0.5, 0.0, 0.5]);

    // Large but finite logits keep full precision: lse - z_y would lose
    // ~1e-3 at this magnitude; (max - z_y) + ln Σ does not.
    let x = [20_000.0f32, 20_000.0, 19_990.0];
    let out = ce.forward(&x, 3, &[1], &mut lse).unwrap();
    let want = (2.0 + (-10.0f64).exp()).ln();
    assert!((f64::from(out.loss) - want).abs() < 1e-6, "{}", out.loss);
    ce.forward_backward(&x, 3, &[1], &mut g).unwrap();
    let p0 = 1.0 / (2.0 + (-10.0f64).exp());
    assert_close(
        "large grads",
        &g,
        &[p0, p0 - 1.0, p0 * (-10.0f64).exp()],
        1e-7,
        1e-5,
    );

    // A huge vocabulary with one dominant logit.
    let v = 200_000;
    let mut row = vec![-5.0f32; v];
    row[123] = 50.0;
    let out = ce.forward(&row, v, &[123], &mut lse).unwrap();
    let want = ((v - 1) as f64 * (-55.0f64).exp()).ln_1p();
    assert!((f64::from(out.loss) - want).abs() < 1e-7);
    let uniform = vec![0.25f32; v];
    let out = ce.forward(&uniform, v, &[7], &mut lse).unwrap();
    assert!(
        (f64::from(out.loss) - (v as f64).ln()).abs() < 2e-6,
        "{}",
        out.loss
    );
}

#[test]
fn all_ignored_is_zero_not_nan() {
    let (t, hd, v) = (4, 3, 5);
    let mut rng = Rng::new(32);
    let h = rng.vec(t * hd, 1.0);
    let w = rng.vec(v * hd, 1.0);
    let targets = [IGNORE; 4];
    for o in all_opts() {
        let ce = o.ce();
        let mut lse = vec![1.0; t];
        let x = rng.vec(t * v, 1.0);
        let out = ce.forward(&x, v, &targets, &mut lse).unwrap();
        assert_eq!((out.loss, out.z_loss, out.valid_tokens), (0.0, 0.0, 0));
        let mut g = vec![f32::NAN; x.len()];
        ce.backward(1.0, &x, v, &targets, &lse, &mut g).unwrap();
        assert!(g.iter().all(|&v| v == 0.0));
        let fused = LinearCrossEntropy::new(ce).with_chunk_tokens(3).unwrap();
        let (mut dh, mut dw) = (vec![f32::NAN; h.len()], vec![f32::NAN; w.len()]);
        let out = fused
            .forward_backward(&h, &w, hd, &targets, &mut dh, Some(&mut dw))
            .unwrap();
        assert_eq!((out.loss, out.z_loss, out.valid_tokens), (0.0, 0.0, 0));
        assert!(dh.iter().chain(&dw).all(|&v| v == 0.0));
    }
    // No tokens at all.
    let fused = LinearCrossEntropy::new(CrossEntropy::new());
    let out = fused
        .forward_backward(&[], &w, hd, &[], &mut [], None)
        .unwrap();
    assert_eq!(out.loss, 0.0);
}

#[test]
fn fused_matches_reference_for_all_chunkings() {
    let mut rng = Rng::new(33);
    let (t, hd, v) = (11, 9, 23);
    let h = rng.vec(t * hd, 1.0);
    let w = rng.vec(v * hd, 1.0);
    let mut targets = targets_with_ignores(&mut rng, t, v);
    // A chunk that is entirely ignored, in the middle.
    targets[3] = IGNORE;
    targets[4] = IGNORE;
    targets[5] = IGNORE;
    for o in all_opts() {
        let (le, ze, dhe, dwe) = fused_ref(&h, &w, t, hd, v, &targets, o);
        for chunk in [1, 3, 4, 11, 100] {
            let fused = LinearCrossEntropy::new(o.ce())
                .with_chunk_tokens(chunk)
                .unwrap();
            let (mut dh, mut dw) = (vec![0.0; h.len()], vec![0.0; w.len()]);
            let out = fused
                .forward_backward(&h, &w, hd, &targets, &mut dh, Some(&mut dw))
                .unwrap();
            assert!((f64::from(out.loss) - le).abs() < 1e-5 * (1.0 + le.abs()));
            assert!((f64::from(out.z_loss) - ze).abs() < 1e-6 * (1.0 + ze.abs()));
            assert_close("dhidden", &dh, &dhe, 1e-6, 1e-4);
            assert_close("dweight", &dw, &dwe, 1e-6, 1e-4);
            // Loss-only pass and the frozen-weight variant agree.
            let lo = fused.forward(&h, &w, hd, &targets).unwrap();
            assert_eq!(lo, out);
            let mut dh2 = vec![0.0; h.len()];
            fused
                .forward_backward(&h, &w, hd, &targets, &mut dh2, None)
                .unwrap();
            assert_eq!(bits(&dh2), bits(&dh));
        }
    }
}

#[test]
fn fused_equals_unfused_matmul_then_loss() {
    let mut rng = Rng::new(34);
    let (t, hd, v) = (37, 16, 300);
    let h = rng.vec(t * hd, 1.0);
    let w = rng.vec(v * hd, 1.0);
    let targets = targets_with_ignores(&mut rng, t, v);
    let ce = CrossEntropy::new()
        .with_z_loss(1e-4)
        .unwrap()
        .with_label_smoothing(0.05)
        .unwrap()
        .with_softcap(Some(15.0))
        .unwrap();
    // Unfused: full logits, standalone loss, two more matmuls.
    let mut logits = vec![0.0; t * v];
    let wm = MatRef::row_major(&w, v, hd).unwrap();
    let hm = MatRef::row_major(&h, t, hd).unwrap();
    gemm(
        1.0,
        hm,
        wm.t(),
        0.0,
        MatMut::row_major(&mut logits, t, v).unwrap(),
    )
    .unwrap();
    let mut g = vec![0.0; t * v];
    let want = ce.forward_backward(&logits, v, &targets, &mut g).unwrap();
    let gm = MatRef::row_major(&g, t, v).unwrap();
    let mut dh_u = vec![0.0; t * hd];
    gemm(
        1.0,
        gm,
        wm,
        0.0,
        MatMut::row_major(&mut dh_u, t, hd).unwrap(),
    )
    .unwrap();
    let mut dw_u = vec![0.0; v * hd];
    gemm(
        1.0,
        gm.t(),
        hm,
        0.0,
        MatMut::row_major(&mut dw_u, v, hd).unwrap(),
    )
    .unwrap();

    for chunk in [5, 37] {
        let fused = LinearCrossEntropy::new(ce)
            .with_chunk_tokens(chunk)
            .unwrap();
        let (mut dh, mut dw) = (vec![0.0; h.len()], vec![0.0; w.len()]);
        let out = fused
            .forward_backward(&h, &w, hd, &targets, &mut dh, Some(&mut dw))
            .unwrap();
        assert!((out.loss - want.loss).abs() <= 1e-6 * want.loss.abs());
        assert_eq!(out.valid_tokens, want.valid_tokens);
        assert_close("dhidden", &dh, &to64(&dh_u), 1e-7, 1e-5);
        assert_close("dweight", &dw, &to64(&dw_u), 1e-7, 1e-5);
    }
}

#[test]
fn fused_finite_differences() {
    let mut rng = Rng::new(35);
    let (t, hd, v) = (4, 3, 7);
    let h = rng.vec(t * hd, 1.0);
    let w = rng.vec(v * hd, 1.0);
    let targets = [1i64, IGNORE, 6, 0];
    for o in all_opts() {
        let fused = LinearCrossEntropy::new(o.ce())
            .with_chunk_tokens(3)
            .unwrap();
        let (mut dh, mut dw) = (vec![0.0; h.len()], vec![0.0; w.len()]);
        fused
            .forward_backward(&h, &w, hd, &targets, &mut dh, Some(&mut dw))
            .unwrap();
        check_fd("fused dhidden", &h, &dh, 1e-2, 2e-3, |hp| {
            f64::from(fused.forward(hp, &w, hd, &targets).unwrap().loss)
        });
        check_fd("fused dweight", &w, &dw, 1e-2, 2e-3, |wp| {
            f64::from(fused.forward(&h, wp, hd, &targets).unwrap().loss)
        });
    }
}

#[test]
fn fused_extreme_logits() {
    // Logits around ±2e4 from the matmul.
    let (t, hd, v) = (3, 2, 4);
    let h = [100.0f32, 100.0, -100.0, 50.0, 1.0, -1.0];
    let w = [100.0f32, 0.0, 0.0, 100.0, -100.0, 0.0, 99.0, 99.0];
    let targets = [3i64, 1, 2];
    let o = Opts {
        eps: 0.0,
        lambda: 0.0,
        cap: None,
        mean: true,
    };
    let (le, _, dhe, dwe) = fused_ref(&h, &w, t, hd, v, &targets, o);
    let fused = LinearCrossEntropy::new(o.ce())
        .with_chunk_tokens(2)
        .unwrap();
    let (mut dh, mut dw) = (vec![0.0; h.len()], vec![0.0; w.len()]);
    let out = fused
        .forward_backward(&h, &w, hd, &targets, &mut dh, Some(&mut dw))
        .unwrap();
    assert!(out.loss.is_finite());
    assert!((f64::from(out.loss) - le).abs() < 1e-4 * (1.0 + le.abs()));
    assert_close("dhidden", &dh, &dhe, 1e-3, 1e-4);
    assert_close("dweight", &dw, &dwe, 1e-3, 1e-4);
    // With a softcap the same logits saturate smoothly.
    let capped = LinearCrossEntropy::new(o.ce().with_softcap(Some(30.0)).unwrap());
    let out = capped
        .forward_backward(&h, &w, hd, &targets, &mut dh, Some(&mut dw))
        .unwrap();
    assert!(out.loss.is_finite() && dh.iter().chain(&dw).all(|v| v.is_finite()));
}

#[test]
fn grad_scale_and_chunk_budget() {
    let mut rng = Rng::new(36);
    let (t, hd, v) = (6, 4, 10);
    let h = rng.vec(t * hd, 1.0);
    let w = rng.vec(v * hd, 1.0);
    let targets = [0i64, 1, 2, 3, 4, 5];
    let base = LinearCrossEntropy::new(CrossEntropy::new());
    let scaled = base.with_grad_scale(0.5).unwrap();
    let (mut a, mut b) = (vec![0.0; h.len()], vec![0.0; h.len()]);
    base.forward_backward(&h, &w, hd, &targets, &mut a, None)
        .unwrap();
    scaled
        .forward_backward(&h, &w, hd, &targets, &mut b, None)
        .unwrap();
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(x * 0.5, *y);
    }
    // The default chunk keeps the logits buffer at 2^23 floats.
    assert_eq!(base.chunk_tokens(100_000, 128_000), 65);
    assert!(base.chunk_tokens(100_000, 128_000) * 128_000 <= 1 << 23);
    assert_eq!(base.chunk_tokens(10, 1000), 10);
    assert_eq!(base.chunk_tokens(100, 1 << 30), 1);
    assert_eq!(base.chunk_tokens(0, 10), 1);
}

#[test]
fn errors() {
    let ce = CrossEntropy::new();
    let mut lse = [0.0f32; 2];
    assert!(matches!(
        ce.forward(&[0.0; 6], 3, &[0, 3], &mut lse),
        Err(FusedError::TargetOutOfRange {
            index: 1,
            target: 3,
            vocab: 3
        })
    ));
    assert!(ce.forward(&[0.0; 6], 3, &[0, -1], &mut lse).is_err());
    assert!(
        ce.with_ignore_index(-1)
            .forward(&[0.0; 6], 3, &[0, -1], &mut lse)
            .is_ok()
    );
    assert!(ce.forward(&[0.0; 6], 3, &[0], &mut lse).is_err());
    assert!(ce.forward(&[0.0; 5], 3, &[0, 0], &mut lse).is_err());
    assert!(ce.forward(&[0.0; 6], 0, &[0, 0], &mut lse).is_err());
    assert!(CrossEntropy::new().with_label_smoothing(1.5).is_err());
    assert!(CrossEntropy::new().with_label_smoothing(f32::NAN).is_err());
    assert!(CrossEntropy::new().with_z_loss(-1.0).is_err());
    assert!(CrossEntropy::new().with_softcap(Some(0.0)).is_err());
    assert!(LinearCrossEntropy::new(ce).with_chunk_tokens(0).is_err());
    assert!(
        LinearCrossEntropy::new(ce)
            .with_grad_scale(f32::INFINITY)
            .is_err()
    );
    let fused = LinearCrossEntropy::new(ce);
    let mut dh = [7.0f32; 4];
    let mut dw = [7.0f32; 6];
    assert!(fused.forward(&[0.0; 4], &[], 2, &[0, 0]).is_err());
    assert!(fused.forward(&[0.0; 4], &[0.0; 5], 2, &[0, 0]).is_err());
    assert!(
        fused
            .forward_backward(&[0.0; 4], &[0.0; 6], 2, &[0, 3], &mut dh, Some(&mut dw))
            .is_err()
    );
    assert!(
        fused
            .forward_backward(&[0.0; 4], &[0.0; 6], 2, &[0, 0], &mut dh[..3], None)
            .is_err()
    );
    assert!(
        fused
            .forward_backward(
                &[0.0; 4],
                &[0.0; 6],
                2,
                &[0, 0],
                &mut dh,
                Some(&mut dw[..5])
            )
            .is_err()
    );
    assert_eq!(dh, [7.0; 4]);
    assert_eq!(dw, [7.0; 6]);
}

#[test]
fn deterministic_across_thread_counts() {
    let mut rng = Rng::new(37);
    let (t, hd, v) = (150, 32, 2000);
    let h = rng.vec(t * hd, 1.0);
    let w = rng.vec(v * hd, 1.0);
    let targets = targets_with_ignores(&mut rng, t, v);
    let ce = CrossEntropy::new()
        .with_z_loss(1e-4)
        .unwrap()
        .with_label_smoothing(0.1)
        .unwrap();
    for chunk in [None, Some(17)] {
        let mut fused = LinearCrossEntropy::new(ce);
        if let Some(c) = chunk {
            fused = fused.with_chunk_tokens(c).unwrap();
        }
        same_on_all_pools(|| {
            let (mut dh, mut dw) = (vec![0.0; h.len()], vec![0.0; w.len()]);
            let out = fused
                .forward_backward(&h, &w, hd, &targets, &mut dh, Some(&mut dw))
                .unwrap();
            (out.loss.to_bits(), bits(&dh), bits(&dw))
        });
    }
    let x = rng.vec(t * v, 5.0);
    same_on_all_pools(|| {
        let mut lse = vec![0.0; t];
        let out = ce.forward(&x, v, &targets, &mut lse).unwrap();
        let mut g = vec![0.0; x.len()];
        ce.backward(1.0, &x, v, &targets, &lse, &mut g).unwrap();
        (out.loss.to_bits(), bits(&lse), bits(&g))
    });
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_fused_any_shape(
        t in 0usize..12,
        hd in 1usize..12,
        v in 1usize..40,
        chunk in 1usize..14,
        oi in 0usize..16,
        seed in any::<u64>(),
    ) {
        let mut rng = Rng::new(seed);
        let h = rng.vec(t * hd, 1.0);
        let w = rng.vec(v * hd, 1.0);
        let targets = targets_with_ignores(&mut rng, t, v);
        let o = all_opts()[oi];
        let (le, _, dhe, dwe) = fused_ref(&h, &w, t, hd, v, &targets, o);
        let fused = LinearCrossEntropy::new(o.ce()).with_chunk_tokens(chunk).unwrap();
        let (mut dh, mut dw) = (vec![0.0; h.len()], vec![0.0; w.len()]);
        let out = fused.forward_backward(&h, &w, hd, &targets, &mut dh, Some(&mut dw)).unwrap();
        prop_assert!((f64::from(out.loss) - le).abs() < 1e-5 * (1.0 + le.abs()));
        assert_close("dhidden", &dh, &dhe, 1e-6, 1e-4);
        assert_close("dweight", &dw, &dwe, 1e-6, 1e-4);
    }
}
