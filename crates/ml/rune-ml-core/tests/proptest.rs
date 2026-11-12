//! Property tests: unrolled kernels and matrix operations agree with naive
//! reference implementations; metric axioms; RNG invariants.

#![allow(
    clippy::float_cmp,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::unwrap_used,
    reason = "test code: exact comparisons are intended (same kernel on both sides), \
              casts are on small test values, and strategies unwrap valid shapes"
)]

use proptest::prelude::*;
use rune_ml_core::{Matrix, MatrixView, Metric, Rng, kernels};

fn close(a: f64, b: f64, scale: f64, tol: f64) -> bool {
    (a - b).abs() <= tol * (1.0 + scale)
}

fn naive(metric: Metric, a: &[f64], b: &[f64]) -> f64 {
    let pairs = a.iter().zip(b);
    match metric {
        Metric::Euclidean => pairs.map(|(x, y)| (x - y) * (x - y)).sum::<f64>().sqrt(),
        Metric::SqEuclidean => pairs.map(|(x, y)| (x - y) * (x - y)).sum(),
        Metric::Manhattan => pairs.map(|(x, y)| (x - y).abs()).sum(),
        Metric::Chebyshev => pairs.map(|(x, y)| (x - y).abs()).fold(0.0, f64::max),
        Metric::Cosine => {
            let ab: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
            let aa: f64 = a.iter().map(|x| x * x).sum();
            let bb: f64 = b.iter().map(|x| x * x).sum();
            match (aa == 0.0, bb == 0.0) {
                (true, true) => 0.0,
                (true, false) | (false, true) => 1.0,
                _ => (1.0 - ab / (aa.sqrt() * bb.sqrt())).clamp(0.0, 2.0),
            }
        }
        _ => unreachable!(),
    }
}

/// Magnitude used to scale the absolute tolerance for a metric.
fn scale(metric: Metric, a: &[f64], b: &[f64]) -> f64 {
    let s: f64 = a.iter().chain(b).map(|v| v.abs()).sum();
    match metric {
        Metric::SqEuclidean => s * s,
        Metric::Cosine => 1.0,
        _ => s,
    }
}

fn pair(max_len: usize) -> impl Strategy<Value = (Vec<f64>, Vec<f64>)> {
    (0..=max_len).prop_flat_map(|n| {
        (
            prop::collection::vec(-1e3..1e3_f64, n),
            prop::collection::vec(-1e3..1e3_f64, n),
        )
    })
}

fn triple(max_len: usize) -> impl Strategy<Value = (Vec<f64>, Vec<f64>, Vec<f64>)> {
    (0..=max_len).prop_flat_map(|n| {
        (
            prop::collection::vec(-1e3..1e3_f64, n),
            prop::collection::vec(-1e3..1e3_f64, n),
            prop::collection::vec(-1e3..1e3_f64, n),
        )
    })
}

fn matrix(max_rows: usize, max_cols: usize) -> impl Strategy<Value = Matrix<f64>> {
    (0..=max_rows, 0..=max_cols).prop_flat_map(|(r, c)| {
        prop::collection::vec(-100.0..100.0_f64, r * c)
            .prop_map(move |v| Matrix::from_vec(v, r, c).unwrap())
    })
}

proptest! {
    #[test]
    fn metrics_match_naive_f64((a, b) in pair(70)) {
        for m in Metric::ALL {
            let got = m.distance(&a, &b);
            let want = naive(m, &a, &b);
            prop_assert!(close(got, want, scale(m, &a, &b), 1e-12), "{m}: {got} vs {want}");
        }
    }

    #[test]
    fn metrics_match_naive_f32((a, b) in pair(70)) {
        let a32: Vec<f32> = a.iter().map(|&v| v as f32).collect();
        let b32: Vec<f32> = b.iter().map(|&v| v as f32).collect();
        let a64: Vec<f64> = a32.iter().map(|&v| f64::from(v)).collect();
        let b64: Vec<f64> = b32.iter().map(|&v| f64::from(v)).collect();
        for m in Metric::ALL {
            let got = f64::from(m.distance(&a32, &b32));
            let want = naive(m, &a64, &b64);
            prop_assert!(close(got, want, scale(m, &a64, &b64), 1e-4), "{m}: {got} vs {want}");
        }
    }

    #[test]
    fn dot_matches_naive((a, b) in pair(70)) {
        let want: f64 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
        let s: f64 = a.iter().chain(&b).map(|v| v.abs()).sum();
        prop_assert!(close(kernels::dot(&a, &b), want, s * s, 1e-12));
        let (ab, aa, bb) = kernels::dot_and_norms(&a, &b);
        prop_assert!(close(ab, want, s * s, 1e-12));
        prop_assert!(close(aa, kernels::norm_sq(&a), s * s, 1e-12));
        prop_assert!(close(bb, kernels::norm_sq(&b), s * s, 1e-12));
    }

    #[test]
    fn metric_axioms((a, b) in pair(40)) {
        for m in Metric::ALL {
            let ab = m.distance(&a, &b);
            let ba = m.distance(&b, &a);
            prop_assert!(ab >= 0.0, "{m} negative");
            prop_assert!(close(ab, ba, scale(m, &a, &b), 1e-12), "{m} asymmetric");
            prop_assert!(m.distance(&a, &a) <= 1e-12, "{m} d(a, a) = {}", m.distance(&a, &a));
        }
    }

    #[test]
    fn triangle_inequality((a, b, c) in triple(30)) {
        for m in Metric::ALL.into_iter().filter(|m| m.is_true_metric()) {
            let lhs = m.distance(&a, &c);
            let rhs = m.distance(&a, &b) + m.distance(&b, &c);
            prop_assert!(lhs <= rhs.mul_add(1.0 + 1e-12, 1e-9), "{m}: {lhs} > {rhs}");
        }
    }

    #[test]
    fn pairwise_matches_direct(x in matrix(12, 6)) {
        for m in Metric::ALL {
            let d = m.pairwise(x.view()).unwrap();
            prop_assert_eq!(d.shape(), (x.nrows(), x.nrows()));
            for i in 0..x.nrows() {
                for j in 0..x.nrows() {
                    let (lo, hi) = (i.min(j), i.max(j));
                    let want = if i == j { 0.0 } else { m.distance(x.row(lo), x.row(hi)) };
                    prop_assert_eq!(d[(i, j)], want);
                }
            }
            let c = m.cdist(x.view(), x.view()).unwrap();
            for i in 0..x.nrows() {
                for j in 0..x.nrows() {
                    prop_assert_eq!(c[(i, j)], m.distance(x.row(i), x.row(j)));
                }
            }
        }
    }

    #[test]
    fn nearest_matches_scan(
        x in (0..=12usize).prop_flat_map(|r| prop::collection::vec(-100.0..100.0_f64, r * 4)
            .prop_map(move |v| Matrix::from_vec(v, r, 4).unwrap())),
        q in prop::collection::vec(-100.0..100.0_f64, 4),
    ) {
        let got = Metric::Euclidean.nearest(&q, x.view()).unwrap();
        let want = x.rows().map(|r| Metric::Euclidean.distance(&q, r))
            .enumerate()
            .fold(None, |best: Option<(usize, f64)>, (i, d)| match best {
                Some((_, b)) if b <= d => best,
                _ => Some((i, d)),
            });
        prop_assert_eq!(got, want);
    }

    #[test]
    fn rows_round_trip(x in matrix(10, 10)) {
        let rows = x.to_rows();
        prop_assert_eq!(rows.len(), x.nrows());
        if x.nrows() > 0 {
            prop_assert_eq!(&Matrix::from_rows(&rows).unwrap(), &x);
        }
        let v = MatrixView::new(x.as_slice(), x.nrows(), x.ncols()).unwrap();
        prop_assert_eq!(v.to_matrix(), x.clone());
        prop_assert_eq!(x.rows().count(), x.nrows());
        let mut rev: Vec<&[f64]> = x.rows().rev().collect();
        rev.reverse();
        prop_assert_eq!(rev, x.rows().collect::<Vec<_>>());
    }

    #[test]
    fn transpose_involution(x in matrix(10, 10)) {
        let t = x.transpose();
        prop_assert_eq!(t.shape(), (x.ncols(), x.nrows()));
        for i in 0..x.nrows() {
            for j in 0..x.ncols() {
                prop_assert_eq!(t[(j, i)], x[(i, j)]);
            }
        }
        prop_assert_eq!(t.transpose(), x);
    }

    #[test]
    fn matmul_matches_naive(
        (a, b) in (0..6usize, 0..6usize, 0..6usize).prop_flat_map(|(n, k, m)| (
            prop::collection::vec(-10.0..10.0_f64, n * k)
                .prop_map(move |v| Matrix::from_vec(v, n, k).unwrap()),
            prop::collection::vec(-10.0..10.0_f64, k * m)
                .prop_map(move |v| Matrix::from_vec(v, k, m).unwrap()),
        ))
    ) {
        let p = a.matmul(b.view()).unwrap();
        prop_assert_eq!(p.shape(), (a.nrows(), b.ncols()));
        for i in 0..a.nrows() {
            for j in 0..b.ncols() {
                let want: f64 = (0..a.ncols()).map(|t| a[(i, t)] * b[(t, j)]).sum();
                prop_assert!(close(p[(i, j)], want, 600.0, 1e-12));
            }
        }
    }

    #[test]
    fn column_means_match(x in matrix(10, 5)) {
        let means = x.column_means();
        for (j, &m) in means.iter().enumerate() {
            let want = if x.nrows() == 0 { 0.0 } else {
                x.column(j).sum::<f64>() / x.nrows() as f64
            };
            prop_assert!(close(m, want, 100.0, 1e-12));
        }
    }

    #[test]
    fn rng_is_deterministic(seed: u64) {
        let mut a = Rng::new(seed);
        let mut b = Rng::new(seed);
        for _ in 0..16 {
            prop_assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn rng_ranges(seed: u64, n in 1u64..u64::MAX, k in 0usize..50, len in 0usize..50) {
        let mut r = Rng::new(seed);
        prop_assert!(r.below(n) < n);
        let f = r.next_f64();
        prop_assert!((0.0..1.0).contains(&f));
        let g = r.next_f32();
        prop_assert!((0.0..1.0).contains(&g));
        let s = r.sample_indices(len, k);
        prop_assert_eq!(s.len(), k.min(len));
        let mut sorted = s.clone();
        sorted.sort_unstable();
        sorted.dedup();
        prop_assert_eq!(sorted.len(), s.len());
        prop_assert!(s.iter().all(|&i| i < len));
    }

    #[test]
    fn shuffle_is_permutation(seed: u64, mut v in prop::collection::vec(any::<u32>(), 0..64)) {
        let mut sorted = v.clone();
        sorted.sort_unstable();
        Rng::new(seed).shuffle(&mut v);
        v.sort_unstable();
        prop_assert_eq!(v, sorted);
    }

    #[test]
    fn weighted_index_never_picks_zero_weight(
        seed: u64,
        w in prop::collection::vec(prop_oneof![Just(0.0_f64), 0.0..10.0_f64], 0..20),
    ) {
        let mut r = Rng::new(seed);
        match r.weighted_index(&w) {
            Some(i) => prop_assert!(w[i] > 0.0),
            None => prop_assert!(w.iter().all(|&x| x <= 0.0)),
        }
    }
}

#[cfg(feature = "serde")]
mod serde_round_trip {
    use super::*;

    proptest! {
        #[test]
        fn matrix_json(mut x in matrix(6, 6)) {
            // serde_json's default float parser is not exactly round-trip;
            // dyadic values are, so this tests the shape/validation logic.
            x.map_inplace(|v| (v * 4.0).round() / 4.0);
            let s = serde_json::to_string(&x).unwrap();
            let back: Matrix<f64> = serde_json::from_str(&s).unwrap();
            prop_assert_eq!(back, x);
        }
    }

    #[test]
    fn rejects_bad_shape() {
        let bad = r#"{"data":[1.0,2.0,3.0],"rows":2,"cols":2}"#;
        assert!(serde_json::from_str::<Matrix<f64>>(bad).is_err());
    }

    #[test]
    fn metric_and_rng() {
        assert_eq!(
            serde_json::to_string(&Metric::SqEuclidean).unwrap(),
            "\"sqeuclidean\""
        );
        let mut r = Rng::new(3);
        r.next_u64();
        let s = serde_json::to_string(&r).unwrap();
        let mut back: Rng = serde_json::from_str(&s).unwrap();
        assert_eq!(back.next_u64(), r.next_u64());
    }
}
