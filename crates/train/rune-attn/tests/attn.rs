//! Correctness against a naive f64 reference, gradients against finite
//! differences, varlen, chunk merging, determinism and edge cases.
#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::suboptimal_flops,
    clippy::type_complexity,
    clippy::cast_precision_loss,
    clippy::float_cmp,
    clippy::too_many_lines,
    clippy::many_single_char_names
)]

mod common;

use common::{BiasKind, Problem, Rng, Spec, assert_close, f32s};
use rune_attn::{Attention, AttnError, AttnInputs, AttnLayout, Bias, HeadDims, merge_partials};

const MASKS: [(bool, Option<usize>, Option<usize>); 6] = [
    (false, None, None),
    (true, None, None),
    (false, Some(2), None),
    (false, Some(1), Some(2)),
    (true, Some(3), None),
    (false, None, Some(0)),
];
const HEADS: [(usize, usize); 3] = [(2, 2), (4, 2), (3, 1)];
const BIASES: [BiasKind; 3] = [BiasKind::None, BiasKind::Alibi, BiasKind::Dense];
const BLOCKS: [(usize, usize); 5] = [(2, 3), (4, 2), (64, 64), (1, 1), (3, 5)];

fn specs() -> Vec<Spec> {
    let mut v = Vec::new();
    for &(causal, left, right) in &MASKS {
        for softcap in [None, Some(5.0)] {
            for bias in BIASES {
                v.push(Spec {
                    causal,
                    left,
                    right,
                    softcap,
                    scale: None,
                    bias,
                });
            }
        }
    }
    v
}

#[test]
fn forward_matches_reference_for_every_feature_combination() {
    let shapes = [(1, 1), (5, 5), (7, 3), (3, 7), (1, 9), (9, 1), (13, 11)];
    let dims = [(3, 3), (5, 2), (1, 4)];
    let mut rng = Rng::new(1);
    let mut n = 0usize;
    for spec in specs() {
        for &(hq, hkv) in &HEADS {
            for &(sq, sk) in &shapes {
                for &(dqk, dv) in &dims {
                    let p = Problem::dense(2, sq, sk, HeadDims::new(hq, hkv, dqk, dv), &mut rng);
                    let blocks = BLOCKS[n % BLOCKS.len()];
                    n += 1;
                    let got = p.forward(&spec, &spec.attention(blocks));
                    let (out, lse) = p.reference(&spec);
                    let ctx = format!(
                        "{spec:?} heads {hq}/{hkv} seq {sq}x{sk} dims {dqk}/{dv} blocks {blocks:?}"
                    );
                    assert_close(&format!("out {ctx}"), &got.out, &out, 2e-6, 2e-5);
                    assert_close(&format!("lse {ctx}"), &got.lse, &lse, 2e-6, 2e-5);
                }
            }
        }
    }
}

#[test]
fn explicit_scale_is_used() {
    let mut rng = Rng::new(2);
    let p = Problem::dense(1, 4, 6, HeadDims::mha(2, 3), &mut rng);
    let spec = Spec {
        scale: Some(0.9),
        ..Spec::PLAIN
    };
    let got = p.forward(&spec, &spec.attention((2, 2)));
    let (out, lse) = p.reference(&spec);
    assert_close("out", &got.out, &out, 2e-6, 2e-5);
    assert_close("lse", &got.lse, &lse, 2e-6, 2e-5);
}

#[test]
fn gradients_match_finite_differences() {
    let shapes = [(5, 4), (3, 6), (1, 1), (4, 1)];
    let mut rng = Rng::new(3);
    let mut n = 0usize;
    for spec in specs() {
        for &(hq, hkv) in &HEADS {
            let (sq, sk) = shapes[n % shapes.len()];
            let p = Problem::dense(2, sq, sk, HeadDims::new(hq, hkv, 3, 2), &mut rng);
            let blocks = BLOCKS[n % BLOCKS.len()];
            n += 1;
            let w = rng.vec(p.reference(&spec).0.len(), 1.0);
            let (_, g) = p.backward(&spec, &spec.attention(blocks), &f32s(&w));
            let fd = p.fd_grads(&spec, &w);
            let ctx = format!("{spec:?} heads {hq}/{hkv} seq {sq}x{sk} blocks {blocks:?}");
            assert_close(&format!("dq {ctx}"), &g.dq, &fd[0], 1e-4, 1e-3);
            assert_close(&format!("dk {ctx}"), &g.dk, &fd[1], 1e-4, 1e-3);
            assert_close(&format!("dv {ctx}"), &g.dv, &fd[2], 1e-4, 1e-3);
            match spec.bias {
                BiasKind::Dense => {
                    let db = g.dbias.as_deref().unwrap_or_default();
                    assert_close(&format!("dbias {ctx}"), db, &fd[3], 1e-4, 1e-3);
                }
                _ => assert!(g.dbias.is_none()),
            }
        }
    }
}

#[test]
fn mla_style_head_dims_and_longer_rows() {
    let mut rng = Rng::new(4);
    let spec = Spec {
        causal: true,
        ..Spec::PLAIN
    };
    let p = Problem::dense(1, 17, 23, HeadDims::new(4, 1, 12, 5), &mut rng);
    let got = p.forward(&spec, &spec.attention((8, 4)));
    let (out, lse) = p.reference(&spec);
    assert_close("out", &got.out, &out, 2e-6, 2e-5);
    assert_close("lse", &got.lse, &lse, 2e-6, 2e-5);
    let w = rng.vec(out.len(), 1.0);
    let (_, g) = p.backward(&spec, &spec.attention((8, 4)), &f32s(&w));
    let fd = p.fd_grads(&spec, &w);
    assert_close("dq", &g.dq, &fd[0], 1e-4, 1e-3);
    assert_close("dk", &g.dk, &fd[1], 1e-4, 1e-3);
    assert_close("dv", &g.dv, &fd[2], 1e-4, 1e-3);
}

/// Packed sequences give exactly what each sequence gives on its own.
#[test]
fn varlen_equals_separate_sequences() {
    let cu_q = vec![0, 3, 3, 8, 9, 15];
    let cu_k = vec![0, 4, 6, 6, 11, 18];
    let hd = HeadDims::new(4, 2, 3, 2);
    let mut rng = Rng::new(5);
    for spec in specs() {
        let p = Problem::new(cu_q.clone(), cu_k.clone(), hd, &mut rng, 1.0);
        let attn = spec.attention((2, 3));
        let w = f32s(&rng.vec(p.reference(&spec).0.len(), 1.0));
        let (fwd, g) = p.backward(&spec, &attn, &w);
        let (out_ref, lse_ref) = p.reference(&spec);
        assert_close("varlen out", &fwd.out, &out_ref, 2e-6, 2e-5);
        assert_close("varlen lse", &fwd.lse, &lse_ref, 2e-6, 2e-5);
        let mut bias_off = 0;
        for b in 0..cu_q.len() - 1 {
            let (q0, q1, k0, k1) = (cu_q[b], cu_q[b + 1], cu_k[b], cu_k[b + 1]);
            let (sq, sk) = (q1 - q0, k1 - k0);
            let qs = hd.heads_q * hd.dim_qk;
            let ks = hd.heads_kv * hd.dim_qk;
            let vs = hd.heads_kv * hd.dim_v;
            let os = hd.heads_q * hd.dim_v;
            let nb = hd.heads_q * sq * sk;
            let one = Problem {
                cu_q: vec![0, sq],
                cu_k: vec![0, sk],
                hd,
                q: p.q[q0 * qs..q1 * qs].to_vec(),
                k: p.k[k0 * ks..k1 * ks].to_vec(),
                v: p.v[k0 * vs..k1 * vs].to_vec(),
                slopes: p.slopes.clone(),
                bias: p.bias[bias_off..bias_off + nb].to_vec(),
            };
            let (f1, g1) = one.backward(&spec, &attn, &w[q0 * os..q1 * os]);
            assert_eq!(f1.out, fwd.out[q0 * os..q1 * os], "out seq {b} {spec:?}");
            assert_eq!(
                f1.lse,
                fwd.lse[q0 * hd.heads_q..q1 * hd.heads_q],
                "lse seq {b}"
            );
            assert_eq!(g1.dq, g.dq[q0 * qs..q1 * qs], "dq seq {b}");
            assert_eq!(g1.dk, g.dk[k0 * ks..k1 * ks], "dk seq {b}");
            assert_eq!(g1.dv, g.dv[k0 * vs..k1 * vs], "dv seq {b}");
            if let (Some(a), Some(all)) = (&g1.dbias, &g.dbias) {
                assert_eq!(a[..], all[bias_off..bias_off + nb], "dbias seq {b}");
            }
            bias_off += nb;
        }
    }
}

#[test]
fn chunked_keys_merge_to_the_full_result() {
    let cu_q = vec![0, 5, 6, 16];
    let cu_k = vec![0, 9, 9, 21];
    let mut rng = Rng::new(6);
    for spec in specs() {
        let p = Problem::new(
            cu_q.clone(),
            cu_k.clone(),
            HeadDims::new(4, 2, 4, 3),
            &mut rng,
            1.0,
        );
        let attn = spec.attention((4, 3));
        let full = p.forward(&spec, &attn);
        let (q, k, v, s, b) = p.f32_parts();
        let inputs = p.inputs(&spec, &q, &k, &v, &s, &b);
        let layout = p.layout();
        for chunk in [1, 2, 4, 7, 12, 100] {
            let merged = attn.forward_kv_chunked(&layout, &inputs, chunk).unwrap();
            let want: Vec<f64> = full.out.iter().map(|&x| f64::from(x)).collect();
            let want_lse: Vec<f64> = full.lse.iter().map(|&x| f64::from(x)).collect();
            assert_close(
                &format!("out chunk {chunk} {spec:?}"),
                &merged.out,
                &want,
                1e-5,
                1e-4,
            );
            assert_close(
                &format!("lse chunk {chunk}"),
                &merged.lse,
                &want_lse,
                1e-5,
                1e-4,
            );
        }
        // Two explicit halves, merged by hand.
        let a = attn.forward_key_range(&layout, &inputs, 0..5).unwrap();
        let bb = attn
            .forward_key_range(&layout, &inputs, 5..usize::MAX)
            .unwrap();
        let m = merge_partials(&a.out, &a.lse, &bb.out, &bb.lse).unwrap();
        let (out_ref, lse_ref) = p.reference(&spec);
        assert_close("halves out", &m.out, &out_ref, 1e-5, 1e-4);
        assert_close("halves lse", &m.lse, &lse_ref, 1e-5, 1e-4);
    }
}

#[test]
fn merge_is_symmetric_and_handles_empty_sides() {
    let ninf = f32::NEG_INFINITY;
    let a = merge_partials(
        &[1.0, 2.0, 0.0, 0.0],
        &[0.0, ninf],
        &[3.0, 4.0, 5.0, 6.0],
        &[0.0, ninf],
    )
    .unwrap();
    assert_eq!(a.out, [2.0, 3.0, 0.0, 0.0]);
    assert!((a.lse[0] - 2f32.ln()).abs() < 1e-7);
    assert_eq!(a.lse[1], ninf);
    // NaN garbage behind an empty side does not leak.
    let b = merge_partials(&[f32::NAN], &[ninf], &[7.0], &[1.5]).unwrap();
    assert_eq!(b.out, [7.0]);
    assert_eq!(b.lse, [1.5]);
    // Huge LSE gap: no overflow.
    let c = merge_partials(&[1.0], &[80.0], &[2.0], &[-80.0]).unwrap();
    assert_eq!(c.out, [1.0]);
    assert_eq!(c.lse, [80.0]);
    assert!(matches!(
        merge_partials(&[1.0, 2.0], &[0.0], &[1.0], &[0.0]),
        Err(AttnError::ShapeMismatch { .. })
    ));
    assert!(matches!(
        merge_partials(&[1.0, 2.0, 3.0], &[0.0, 0.0], &[1.0, 2.0, 3.0], &[0.0, 0.0]),
        Err(AttnError::ShapeMismatch { .. })
    ));
    assert_eq!(
        merge_partials(&[], &[], &[], &[]).unwrap().out,
        Vec::<f32>::new()
    );
}

fn run_in_pool<T: Send>(threads: usize, f: impl FnOnce() -> T + Send) -> T {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap()
        .install(f)
}

#[test]
fn bitwise_deterministic_across_thread_counts() {
    let mut rng = Rng::new(7);
    let cu_q = vec![0, 40, 41, 110];
    let cu_k = vec![0, 50, 70, 130];
    let p = Problem::new(cu_q, cu_k, HeadDims::new(4, 2, 16, 8), &mut rng, 1.0);
    let spec = Spec {
        causal: true,
        left: Some(30),
        softcap: Some(20.0),
        bias: BiasKind::Dense,
        ..Spec::PLAIN
    };
    let w = f32s(&rng.vec(p.reference(&spec).0.len(), 1.0));
    let attn = spec.attention((16, 16));
    let base = run_in_pool(1, || p.backward(&spec, &attn, &w));
    let serial = p.backward(&spec, &attn.parallel(false), &w);
    assert_eq!(base, serial);
    for threads in [2, 3, 8] {
        let other = run_in_pool(threads, || p.backward(&spec, &attn, &w));
        let bits = |x: &[f32]| x.iter().map(|v| v.to_bits()).collect::<Vec<_>>();
        assert_eq!(
            bits(&base.0.out),
            bits(&other.0.out),
            "out, {threads} threads"
        );
        assert_eq!(
            bits(&base.0.lse),
            bits(&other.0.lse),
            "lse, {threads} threads"
        );
        assert_eq!(bits(&base.1.dq), bits(&other.1.dq), "dq, {threads} threads");
        assert_eq!(bits(&base.1.dk), bits(&other.1.dk), "dk, {threads} threads");
        assert_eq!(bits(&base.1.dv), bits(&other.1.dv), "dv, {threads} threads");
        assert_eq!(
            bits(base.1.dbias.as_deref().unwrap_or_default()),
            bits(other.1.dbias.as_deref().unwrap_or_default())
        );
    }
}

#[test]
fn extreme_logits_stay_finite() {
    let mut rng = Rng::new(8);
    for amp in [30.0, 300.0, 3000.0] {
        for softcap in [None, Some(30.0)] {
            let p = Problem::new(
                vec![0, 7, 12],
                vec![0, 9, 20],
                HeadDims::new(2, 1, 8, 4),
                &mut rng,
                amp,
            );
            let spec = Spec {
                causal: true,
                softcap,
                ..Spec::PLAIN
            };
            let w = f32s(&rng.vec(p.reference(&spec).0.len(), 1.0));
            let (fwd, g) = p.backward(&spec, &spec.attention((4, 4)), &w);
            for x in fwd
                .out
                .iter()
                .chain(&fwd.lse)
                .chain(&g.dq)
                .chain(&g.dk)
                .chain(&g.dv)
            {
                assert!(x.is_finite(), "amp {amp} softcap {softcap:?}: {x}");
            }
            let (out, lse) = p.reference(&spec);
            // Logits reach ~amp² · 8 / sqrt(8); compare relative to that.
            let lse_scale = amp * amp * 3.0;
            assert_close("lse", &fwd.lse, &lse, 1e-6 * lse_scale, 1e-5);
            if amp <= 30.0 {
                assert_close("out", &fwd.out, &out, 1e-3, 1e-3);
            } else {
                // Near-ties at this magnitude are below f32 resolution; the
                // output must still be a convex combination of values.
                assert!(fwd.out.iter().all(|x| x.abs() <= 1.0 + 1e-6));
            }
        }
    }
}

#[test]
fn fully_masked_rows_give_zero_and_neg_inf() {
    let mut rng = Rng::new(9);
    // Causal with seq_q > seq_k: the first 4 queries see nothing.
    let p = Problem::dense(2, 7, 3, HeadDims::new(2, 1, 4, 3), &mut rng);
    let spec = Spec {
        causal: true,
        ..Spec::PLAIN
    };
    let w = f32s(&rng.vec(p.reference(&spec).0.len(), 1.0));
    let (fwd, g) = p.backward(&spec, &spec.attention((3, 2)), &w);
    for b in 0..2 {
        for i in 0..7 {
            for h in 0..2 {
                let row = (b * 7 + i) * 2 + h;
                if i < 4 {
                    assert_eq!(fwd.lse[row], f32::NEG_INFINITY);
                    assert!(fwd.out[row * 3..row * 3 + 3].iter().all(|&x| x == 0.0));
                    assert!(g.dq[row * 4..row * 4 + 4].iter().all(|&x| x == 0.0));
                } else {
                    assert!(fwd.lse[row].is_finite());
                }
            }
        }
    }
    assert!(g.dk.iter().chain(&g.dv).all(|x| x.is_finite()));

    // A dense bias of -inf masks whole rows, and an empty key range masks
    // everything.
    let mut p = Problem::dense(1, 3, 4, HeadDims::mha(1, 2), &mut rng);
    for j in 0..4 {
        p.bias[4 + j] = f64::NEG_INFINITY; // row 1
    }
    let spec = Spec {
        bias: BiasKind::Dense,
        ..Spec::PLAIN
    };
    let w = f32s(&rng.vec(6, 1.0));
    let (fwd, g) = p.backward(&spec, &spec.attention((2, 2)), &w);
    assert_eq!(fwd.lse[1], f32::NEG_INFINITY);
    assert_eq!(&fwd.out[2..4], &[0.0, 0.0]);
    assert_eq!(&g.dq[2..4], &[0.0, 0.0]);
    let db = g.dbias.unwrap_or_default();
    assert!(db.iter().all(|x| x.is_finite()));
    assert!(db[4..8].iter().all(|&x| x == 0.0));
    let (q, k, v, s, b) = p.f32_parts();
    let inputs = p.inputs(&spec, &q, &k, &v, &s, &b);
    let empty = Attention::new()
        .forward_key_range(&p.layout(), &inputs, 2..2)
        .unwrap();
    assert!(empty.out.iter().all(|&x| x == 0.0));
    assert!(empty.lse.iter().all(|&x| x == f32::NEG_INFINITY));
}

#[test]
fn decode_against_a_cache_is_bottom_right_aligned() {
    // One new query against 6 cached keys: causal sees all 6, a window of
    // left 2 sees the last 3.
    let mut rng = Rng::new(10);
    let p = Problem::dense(1, 1, 6, HeadDims::new(2, 1, 4, 4), &mut rng);
    let causal = Spec {
        causal: true,
        ..Spec::PLAIN
    };
    let full = p.forward(&Spec::PLAIN, &Spec::PLAIN.attention((64, 64)));
    let c = p.forward(&causal, &causal.attention((64, 64)));
    assert_eq!(full.out, c.out);
    let win = Spec {
        causal: true,
        left: Some(2),
        ..Spec::PLAIN
    };
    let got = p.forward(&win, &win.attention((1, 2)));
    // Same as attending to keys 3..6 only.
    let (q, k, v, s, b) = p.f32_parts();
    let inputs = p.inputs(&Spec::PLAIN, &q, &k, &v, &s, &b);
    let tail = Attention::new()
        .forward_key_range(&p.layout(), &inputs, 3..6)
        .unwrap();
    for (a, b) in got.out.iter().zip(&tail.out) {
        assert!((a - b).abs() < 1e-6);
    }
}

#[test]
fn invalid_inputs_are_errors() {
    let hd = HeadDims::new(4, 2, 3, 2);
    assert!(matches!(
        AttnLayout::dense(1, 2, 2, HeadDims::new(3, 2, 3, 2)),
        Err(AttnError::Heads { .. })
    ));
    assert!(matches!(
        AttnLayout::dense(1, 2, 2, HeadDims::new(0, 0, 3, 2)),
        Err(AttnError::Heads { .. })
    ));
    assert!(matches!(
        AttnLayout::dense(1, 2, 2, HeadDims::new(2, 2, 0, 2)),
        Err(AttnError::Zero { .. })
    ));
    assert!(matches!(
        AttnLayout::varlen(&[0, 2], &[0, 2, 3], hd),
        Err(AttnError::Seqlens { .. })
    ));
    assert!(matches!(
        AttnLayout::varlen(&[1, 2], &[0, 2], hd),
        Err(AttnError::Seqlens { .. })
    ));
    assert!(matches!(
        AttnLayout::varlen(&[0, 3, 2], &[0, 2, 4], hd),
        Err(AttnError::Seqlens { .. })
    ));
    assert!(matches!(
        AttnLayout::varlen(&[], &[], hd),
        Err(AttnError::Seqlens { .. })
    ));
    assert!(matches!(
        AttnLayout::dense(usize::MAX, 2, 2, hd),
        Err(AttnError::Overflow)
    ));

    let layout = AttnLayout::dense(1, 2, 3, hd).unwrap();
    let q = vec![0.0f32; layout.q_len()];
    let k = vec![0.0f32; layout.k_len()];
    let v = vec![0.0f32; layout.v_len()];
    let ok = AttnInputs::new(&q, &k, &v);
    let a = Attention::new();
    assert!(a.forward(&layout, &ok).is_ok());
    let short = AttnInputs::new(&q[1..], &k, &v);
    assert!(matches!(
        a.forward(&layout, &short),
        Err(AttnError::ShapeMismatch { what: "q", .. })
    ));
    let bad_v = AttnInputs::new(&q, &k, &k);
    assert!(a.forward(&layout, &bad_v).is_err());
    let slopes = [1.0f32; 3];
    assert!(
        a.forward(&layout, &ok.with_bias(Bias::Alibi(&slopes)))
            .is_err()
    );
    let bias = vec![0.0f32; layout.bias_len() + 1];
    assert!(
        a.forward(&layout, &ok.with_bias(Bias::Dense(&bias)))
            .is_err()
    );
    assert!(matches!(
        a.blocks(0, 4).forward(&layout, &ok),
        Err(AttnError::Zero { .. })
    ));
    assert!(a.scale(f32::NAN).forward(&layout, &ok).is_err());
    assert!(a.softcap(-1.0).forward(&layout, &ok).is_err());
    assert!(a.softcap(f32::INFINITY).forward(&layout, &ok).is_err());
    assert!(a.softcap(0.0).forward(&layout, &ok).is_ok());
    #[allow(clippy::reversed_empty_ranges)]
    let rev = a.forward_key_range(&layout, &ok, 3..1);
    assert!(rev.is_err());
    assert!(a.forward_kv_chunked(&layout, &ok, 0).is_err());

    let f = a.forward(&layout, &ok).unwrap();
    assert!(
        a.backward(&layout, &ok, &f.out, &f.lse[1..], &f.out)
            .is_err()
    );
    assert!(
        a.backward(&layout, &ok, &f.out[1..], &f.lse, &f.out)
            .is_err()
    );
    assert!(
        a.backward(&layout, &ok, &f.out, &f.lse, &f.out[1..])
            .is_err()
    );
    assert!(a.backward(&layout, &ok, &f.out, &f.lse, &f.out).is_ok());
}

#[test]
fn empty_problems_work() {
    let hd = HeadDims::mha(2, 3);
    for (cu_q, cu_k) in [
        (vec![0], vec![0]),
        (vec![0, 0], vec![0, 4]),
        (vec![0, 3], vec![0, 0]),
    ] {
        let layout = AttnLayout::varlen(&cu_q, &cu_k, hd).unwrap();
        let q = vec![0.5f32; layout.q_len()];
        let k = vec![0.5f32; layout.k_len()];
        let v = vec![0.5f32; layout.v_len()];
        let inputs = AttnInputs::new(&q, &k, &v);
        let a = Attention::new().causal(true);
        let f = a.forward(&layout, &inputs).unwrap();
        assert!(f.out.iter().all(|&x| x == 0.0));
        assert!(f.lse.iter().all(|&x| x == f32::NEG_INFINITY));
        let g = a
            .backward(&layout, &inputs, &f.out, &f.lse, &f.out)
            .unwrap();
        assert!(g.dq.iter().chain(&g.dk).chain(&g.dv).all(|&x| x == 0.0));
        let c = a.forward_kv_chunked(&layout, &inputs, 2).unwrap();
        assert_eq!(c, f);
    }
}
