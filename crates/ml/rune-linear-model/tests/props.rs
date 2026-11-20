//! Property tests: arbitrary (including degenerate) input never panics, and
//! every fit is deterministic.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::missing_const_for_fn,
    clippy::many_single_char_names,
    reason = "test helpers"
)]

use proptest::prelude::*;
use rune_linear_model::{
    ClassifierLoss, ElasticNet, LinearRegression, LogisticRegression, Ridge, Selection,
    SgdClassifier, SgdPenalty, SgdRegressor,
};
use rune_ml_core::Matrix;

fn value() -> impl Strategy<Value = f64> {
    prop_oneof![
        8 => -1e3..1e3_f64,
        1 => Just(0.0),
        1 => prop_oneof![Just(f64::NAN), Just(f64::INFINITY), Just(1e200), Just(-1e-300)],
    ]
}

prop_compose! {
    fn problem()(n in 0usize..12, p in 0usize..5)
        (x in prop::collection::vec(value(), n * p),
         y in prop::collection::vec(value(), n),
         labels in prop::collection::vec(0u8..3, n),
         w in prop::collection::vec(prop_oneof![Just(0.0), 0.0..5.0_f64], n),
         n in Just(n), p in Just(p))
        -> (Matrix<f64>, Vec<f64>, Vec<u8>, Vec<f64>) {
        (Matrix::from_vec(x, n, p).unwrap(), y, labels, w)
    }
}

fn finite(v: &[f64]) -> bool {
    v.iter().all(|x| x.is_finite())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn regressors_never_panic((x, y, _, w) in problem()) {
        let v = x.view();
        for sw in [None, Some(w.as_slice())] {
            let a = LinearRegression::new().fit_weighted(v, &y, sw);
            prop_assert_eq!(&a, &LinearRegression::new().fit_weighted(v, &y, sw));
            if let Ok(m) = &a { prop_assert!(finite(m.coef()) || !finite(&y)); }

            let r = Ridge::new(0.5).fit_weighted(v, &y, sw);
            prop_assert_eq!(&r, &Ridge::new(0.5).fit_weighted(v, &y, sw));
            if let Ok(m) = &r { let _ = m.predict(v); }

            let est = ElasticNet::new(0.3, 0.6).with_max_iter(50);
            let e = est.fit_weighted(v, &y, sw);
            prop_assert_eq!(&e, &est.fit_weighted(v, &y, sw));
            let rnd = est.with_selection(Selection::Random).with_seed(9);
            prop_assert_eq!(rnd.fit_weighted(v, &y, sw), rnd.fit_weighted(v, &y, sw));

            let sgd = SgdRegressor::new()
                .with_max_iter(5)
                .with_seed(3)
                .with_penalty(SgdPenalty::ElasticNet);
            let s = sgd.fit_weighted(v, &y, sw);
            prop_assert_eq!(&s, &sgd.fit_weighted(v, &y, sw));
            if let Ok(m) = &s { prop_assert!(finite(m.coef())); }
        }
    }

    #[test]
    fn classifiers_never_panic((x, _, labels, w) in problem(), l1 in prop_oneof![Just(0.0), Just(1.0), 0.0..1.0_f64]) {
        let v = x.view();
        for sw in [None, Some(w.as_slice())] {
            let est = LogisticRegression::new().with_l1_ratio(l1).with_max_iter(30);
            let a = est.fit_weighted(v, &labels, sw);
            prop_assert_eq!(&a, &est.fit_weighted(v, &labels, sw));
            if let Ok(m) = &a {
                prop_assert!(finite(m.coef().as_slice()));
                let p = m.predict_proba(v).unwrap();
                for row in p.rows() {
                    prop_assert!((row.iter().sum::<f64>() - 1.0).abs() < 1e-9);
                }
            }
            for loss in [ClassifierLoss::Hinge, ClassifierLoss::LogLoss, ClassifierLoss::ModifiedHuber] {
                let sgd = SgdClassifier::new().with_loss(loss).with_max_iter(5).with_seed(5);
                let s = sgd.fit_weighted(v, &labels, sw);
                prop_assert_eq!(&s, &sgd.fit_weighted(v, &labels, sw));
                if let Ok(m) = &s {
                    let _ = m.predict(v);
                    let _ = m.predict_proba(v);
                }
            }
        }
    }

    #[test]
    fn ridge_primal_and_dual_agree(n in 2usize..8, p in 1usize..8, seed in 0u64..1000) {
        let mut rng = rune_ml_core::Rng::new(seed);
        let x = Matrix::from_fn(n, p, |_, _| rng.normal()).unwrap();
        let y: Vec<f64> = (0..n).map(|_| rng.normal()).collect();
        let a = Ridge::new(0.7).with_solver(rune_linear_model::RidgeSolver::Primal).fit(x.view(), &y).unwrap();
        let b = Ridge::new(0.7).with_solver(rune_linear_model::RidgeSolver::Dual).fit(x.view(), &y).unwrap();
        for (u, v) in a.coef().iter().zip(b.coef()) {
            prop_assert!((u - v).abs() < 1e-8 * u.abs().max(1.0));
        }
    }
}
