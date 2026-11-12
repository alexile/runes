//! Property tests: `fit` never panics, and valid input always yields an
//! orthonormal basis, consistent variances and an exact full reconstruction.

#![allow(clippy::suboptimal_flops, reason = "test tolerances, not numerics")]

use proptest::prelude::*;
use rune_pca::{Components, Pca, Solver};

/// 2..=12 rows of 1..=6 finite values each.
fn finite_rows() -> impl Strategy<Value = Vec<Vec<f64>>> {
    (1usize..=6).prop_flat_map(|dim| {
        prop::collection::vec(prop::collection::vec(-1e6f64..1e6, dim), 2..=12)
    })
}

/// Arbitrary (possibly ragged, possibly non-finite) input.
fn any_rows() -> impl Strategy<Value = Vec<Vec<f64>>> {
    prop::collection::vec(prop::collection::vec(any::<f64>(), 0..4), 0..8)
}

fn solver() -> impl Strategy<Value = Solver> {
    prop_oneof![
        Just(Solver::Auto),
        Just(Solver::Covariance),
        Just(Solver::Svd),
        Just(Solver::Randomized),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn never_panics_on_arbitrary_input(
        rows in any_rows(),
        k in 0usize..5,
        ratio in any::<f64>(),
        by_ratio in any::<bool>(),
        solver in solver(),
        whiten in any::<bool>(),
    ) {
        let components = if by_ratio { Components::VarianceRatio(ratio) } else { Components::Count(k) };
        let pca = Pca::default().with_components(components).with_solver(solver).with_whiten(whiten);
        if let Ok(model) = pca.fit(&rows) {
            let _ = model.transform(&rows);
            let _ = model.inverse_transform(&rows);
        }
    }

    #[test]
    fn valid_input_gives_a_consistent_model(rows in finite_rows(), solver in solver(), seed in any::<u64>()) {
        let pca = Pca::default().with_solver(solver).with_seed(seed);
        let (model, projected) = pca.fit_transform(&rows).unwrap();
        let k = model.n_components();
        prop_assert_eq!(k, rows.len().min(rows[0].len()));
        let c = model.components();
        for i in 0..k {
            for j in 0..k {
                let d: f64 = c[i].iter().zip(&c[j]).map(|(a, b)| a * b).sum();
                let want = if i == j { 1.0 } else { 0.0 };
                prop_assert!((d - want).abs() < 1e-8, "<c{},c{}> = {}", i, j, d);
            }
        }
        let ev = model.explained_variance();
        prop_assert!(ev.windows(2).all(|w| w[0] >= w[1] * (1.0 - 1e-9) - 1e-9));
        let total: f64 = model.explained_variance_ratio().iter().sum();
        prop_assert!(total <= 1.0 + 1e-9);
        prop_assert!(total >= 1.0 - 1e-9 || ev[0] == 0.0);

        let back = model.inverse_transform(&projected).unwrap();
        let mag = rows.iter().flatten().fold(1.0f64, |m, x| m.max(x.abs()));
        for (r, s) in rows.iter().zip(&back) {
            for (a, b) in r.iter().zip(s) {
                prop_assert!((a - b).abs() <= 1e-8 * mag, "{} vs {}", a, b);
            }
        }
        prop_assert_eq!(pca.fit(&rows).unwrap(), model);
    }
}
