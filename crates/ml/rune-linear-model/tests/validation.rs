//! Hostile input: every estimator returns an error instead of panicking or
//! producing `NaN` coefficients.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::missing_const_for_fn,
    clippy::many_single_char_names,
    reason = "test helpers"
)]

use rune_linear_model::{
    ClassWeight, ClassifierLoss, ElasticNet, LearningRate, LinearError, LinearRegression,
    LogisticRegression, Ridge, SgdClassifier, SgdRegressor,
};
use rune_ml_core::{Matrix, MatrixView, MlError};

fn data() -> (Matrix<f64>, Vec<f64>, Vec<u8>) {
    let x =
        Matrix::from_rows(&[[0.0, 1.0], [1.0, 0.5], [2.0, 2.5], [3.0, 1.0], [4.0, 3.0]]).unwrap();
    (x, vec![1.0, 2.0, 2.5, 4.0, 5.5], vec![0, 0, 1, 1, 1])
}

/// Runs every regressor on the input and returns their errors.
fn regress_errors(x: MatrixView<'_, f64>, y: &[f64], sw: Option<&[f64]>) -> Vec<LinearError> {
    vec![
        LinearRegression::new().fit_weighted(x, y, sw).unwrap_err(),
        Ridge::new(1.0).fit_weighted(x, y, sw).unwrap_err(),
        ElasticNet::new(0.1, 0.5)
            .fit_weighted(x, y, sw)
            .unwrap_err(),
        SgdRegressor::new().fit_weighted(x, y, sw).unwrap_err(),
    ]
}

fn classify_errors(x: MatrixView<'_, f64>, y: &[u8], sw: Option<&[f64]>) -> Vec<LinearError> {
    vec![
        LogisticRegression::new()
            .fit_weighted(x, y, sw)
            .unwrap_err(),
        SgdClassifier::new().fit_weighted(x, y, sw).unwrap_err(),
    ]
}

#[test]
fn rejects_non_finite_features() {
    let (mut x, y, labels) = data();
    x[(2, 1)] = f64::NAN;
    for e in regress_errors(x.view(), &y, None) {
        assert_eq!(e, LinearError::Core(MlError::NonFinite { row: 2, col: 1 }));
    }
    x[(2, 1)] = f64::INFINITY;
    for e in classify_errors(x.view(), &labels, None) {
        assert_eq!(e, LinearError::Core(MlError::NonFinite { row: 2, col: 1 }));
    }
}

#[test]
fn rejects_non_finite_targets() {
    let (x, mut y, _) = data();
    y[3] = f64::NEG_INFINITY;
    for e in regress_errors(x.view(), &y, None) {
        assert_eq!(e, LinearError::NonFiniteTarget { index: 3 });
    }
}

#[test]
fn rejects_empty_input() {
    let x = Matrix::<f64>::zeros(0, 2).unwrap();
    for e in regress_errors(x.view(), &[], None) {
        assert_eq!(
            e,
            LinearError::Core(MlError::TooFewSamples { needed: 1, got: 0 })
        );
    }
    for e in classify_errors(x.view(), &[], None) {
        assert!(matches!(
            e,
            LinearError::Core(MlError::TooFewSamples { .. })
                | LinearError::TooFewClasses { found: 0 }
        ));
    }
    let no_features = Matrix::<f64>::zeros(3, 0).unwrap();
    for e in regress_errors(no_features.view(), &[1.0, 2.0, 3.0], None) {
        assert!(matches!(
            e,
            LinearError::Core(MlError::InvalidParameter { name: "x", .. })
        ));
    }
}

#[test]
fn rejects_mismatched_shapes() {
    let (x, y, labels) = data();
    for e in regress_errors(x.view(), &y[..4], None) {
        assert_eq!(
            e,
            LinearError::LengthMismatch {
                expected: 5,
                found: 4
            }
        );
    }
    for e in classify_errors(x.view(), &labels[..2], None) {
        assert_eq!(
            e,
            LinearError::LengthMismatch {
                expected: 5,
                found: 2
            }
        );
    }
    // Predicting with the wrong number of features.
    let model = Ridge::new(1.0).fit(x.view(), &y).unwrap();
    let wide = Matrix::<f64>::zeros(2, 3).unwrap();
    assert_eq!(
        model.predict(wide.view()),
        Err(LinearError::FeatureMismatch {
            expected: 2,
            found: 3
        })
    );
    let clf = LogisticRegression::new().fit(x.view(), &labels).unwrap();
    assert!(matches!(
        clf.predict_proba(wide.view()),
        Err(LinearError::FeatureMismatch { .. })
    ));
    let mut nan = Matrix::<f64>::zeros(1, 2).unwrap();
    nan[(0, 0)] = f64::NAN;
    assert!(model.predict(nan.view()).is_err());
}

#[test]
fn rejects_bad_sample_weights() {
    let (x, y, labels) = data();
    let negative = [1.0, -1.0, 1.0, 1.0, 1.0];
    for e in regress_errors(x.view(), &y, Some(&negative)) {
        assert_eq!(e, LinearError::InvalidSampleWeight { index: 1 });
    }
    let nan = [1.0, 1.0, 1.0, 1.0, f64::NAN];
    for e in classify_errors(x.view(), &labels, Some(&nan)) {
        assert_eq!(e, LinearError::InvalidSampleWeight { index: 4 });
    }
    let zeros = [0.0; 5];
    for e in regress_errors(x.view(), &y, Some(&zeros)) {
        assert_eq!(e, LinearError::ZeroWeightSum);
    }
    for e in regress_errors(x.view(), &y, Some(&[1.0, 1.0])) {
        assert_eq!(
            e,
            LinearError::LengthMismatch {
                expected: 5,
                found: 2
            }
        );
    }
}

#[test]
fn zero_weights_drop_samples() {
    let (x, y, _) = data();
    let sw = [1.0, 1.0, 1.0, 1.0, 0.0];
    let weighted = LinearRegression::new()
        .fit_weighted(x.view(), &y, Some(&sw))
        .unwrap();
    let first4 = x.select_rows(&[0, 1, 2, 3]).unwrap();
    let plain = LinearRegression::new().fit(first4.view(), &y[..4]).unwrap();
    for (a, b) in weighted.coef().iter().zip(plain.coef()) {
        assert!((a - b).abs() < 1e-10);
    }
}

#[test]
fn rejects_bad_parameters() {
    let (x, y, labels) = data();
    let v = x.view();
    let is_param =
        |e: LinearError| matches!(e, LinearError::Core(MlError::InvalidParameter { .. }));
    assert!(is_param(Ridge::new(-1.0).fit(v, &y).unwrap_err()));
    assert!(is_param(Ridge::new(f64::NAN).fit(v, &y).unwrap_err()));
    assert!(is_param(ElasticNet::new(1.0, 1.5).fit(v, &y).unwrap_err()));
    assert!(is_param(
        ElasticNet::lasso(1.0)
            .with_max_iter(0)
            .fit(v, &y)
            .unwrap_err()
    ));
    assert!(is_param(
        ElasticNet::lasso(1.0)
            .with_tol(f64::NAN)
            .fit(v, &y)
            .unwrap_err()
    ));
    assert!(is_param(
        LogisticRegression::new()
            .with_c(0.0)
            .fit(v, &labels)
            .unwrap_err()
    ));
    assert!(is_param(
        LogisticRegression::new()
            .with_l1_ratio(-0.1)
            .fit(v, &labels)
            .unwrap_err()
    ));
    assert!(is_param(
        SgdRegressor::new().with_eta0(0.0).fit(v, &y).unwrap_err()
    ));
    assert!(is_param(
        SgdClassifier::new()
            .with_alpha(0.0)
            .with_learning_rate(LearningRate::Optimal)
            .fit(v, &labels)
            .unwrap_err()
    ));
    assert!(is_param(
        SgdClassifier::new()
            .with_tol(Some(f64::NAN))
            .fit(v, &labels)
            .unwrap_err()
    ));
    // predict_proba is only defined for probabilistic losses.
    let hinge = SgdClassifier::new().fit(v, &labels).unwrap();
    assert!(is_param(hinge.predict_proba(v).unwrap_err()));
}

#[test]
fn classifiers_need_two_classes() {
    let (x, _, _) = data();
    for e in classify_errors(x.view(), &[1, 1, 1, 1, 1], None) {
        assert_eq!(e, LinearError::TooFewClasses { found: 1 });
    }
}

#[test]
fn sgd_divergence_is_an_error() {
    let x = Matrix::from_rows(&[[1.0], [-1.0]]).unwrap();
    let e = SgdRegressor::new()
        .with_learning_rate(LearningRate::Constant)
        .with_eta0(1e300)
        .with_penalty(rune_linear_model::SgdPenalty::None)
        .fit(x.view(), &[1.0, -1.0])
        .unwrap_err();
    assert!(matches!(e, LinearError::Diverged { .. }));
}

#[test]
fn f32_works_everywhere() {
    let (x, y, labels) = data();
    let x: Matrix<f32> = x.cast();
    let y: Vec<f32> = y.iter().map(|&v| v as f32).collect();
    let v = x.view();
    assert!(
        LinearRegression::new()
            .fit(v, &y)
            .unwrap()
            .score(v, &y)
            .unwrap()
            > 0.9
    );
    assert!(Ridge::new(0.1).fit(v, &y).unwrap().score(v, &y).unwrap() > 0.9);
    assert!(
        ElasticNet::lasso(0.01)
            .fit(v, &y)
            .unwrap()
            .score(v, &y)
            .unwrap()
            > 0.9
    );
    assert!(SgdRegressor::new().with_seed(1).fit(v, &y).unwrap().coef()[0].is_finite());
    let clf = LogisticRegression::new()
        .with_class_weight(ClassWeight::Balanced)
        .fit(v, &labels)
        .unwrap();
    assert_eq!(clf.predict(v).unwrap(), labels);
    let p = clf.predict_proba(v).unwrap();
    assert!(p.rows().all(|r| (r[0] + r[1] - 1.0).abs() < 1e-6));
    let sgd = SgdClassifier::new()
        .with_loss(ClassifierLoss::ModifiedHuber)
        .fit(v, &labels)
        .unwrap();
    assert!(
        sgd.predict_proba(v)
            .unwrap()
            .as_slice()
            .iter()
            .all(|p| (0.0..=1.0).contains(p))
    );
}

#[test]
fn estimators_implement_the_core_traits() {
    use rune_ml_core::{Fit, Predict};
    let (x, y, labels) = data();
    let data = (x.view(), y.as_slice());
    let model = Fit::fit(&Ridge::new(1.0), &data).unwrap();
    assert_eq!(Predict::predict(&model, &x.view()).unwrap().len(), 5);
    let cdata = (x.view(), labels.as_slice());
    let clf = Fit::fit(&LogisticRegression::new(), &cdata).unwrap();
    assert_eq!(Predict::predict(&clf, &x.view()).unwrap(), labels);
}

#[cfg(feature = "serde")]
#[test]
fn models_round_trip_through_serde() {
    // serde_json may round the last digit of an f64, so compare closely.
    let near = |a: &[f64], b: &[f64]| {
        assert_eq!(a.len(), b.len());
        for (u, v) in a.iter().zip(b) {
            assert!((u - v).abs() <= 1e-12 * u.abs().max(1.0), "{u} vs {v}");
        }
    };
    let (x, y, labels) = data();
    let v = x.view();
    let ridge = Ridge::new(1.0).fit(v, &y).unwrap();
    let back: rune_linear_model::LinearModel<f64> =
        serde_json::from_str(&serde_json::to_string(&ridge).unwrap()).unwrap();
    near(back.coef(), ridge.coef());
    near(&[back.intercept()], &[ridge.intercept()]);

    let enet = ElasticNet::lasso(0.1).fit(v, &y).unwrap();
    let back: rune_linear_model::ElasticNetModel<f64> =
        serde_json::from_str(&serde_json::to_string(&enet).unwrap()).unwrap();
    near(&back.predict(v).unwrap(), &enet.predict(v).unwrap());
    assert_eq!(back.n_iter(), enet.n_iter());

    let clf = LogisticRegression::new().fit(v, &labels).unwrap();
    let json = serde_json::to_string(&clf).unwrap();
    let back: rune_linear_model::LogisticModel<f64, u8> = serde_json::from_str(&json).unwrap();
    assert_eq!(back.classes(), clf.classes());
    near(back.coef().as_slice(), clf.coef().as_slice());
    near(
        &back.predict_proba(v).unwrap().into_vec(),
        &clf.predict_proba(v).unwrap().into_vec(),
    );

    // Streaming state survives a round trip: same next update.
    let mut sgd = SgdClassifier::new()
        .partial_fit(v, &labels, &[0, 1], None)
        .unwrap();
    let mut copy: rune_linear_model::SgdClassifierModel<f64, u8> =
        serde_json::from_str(&serde_json::to_string(&sgd).unwrap()).unwrap();
    sgd.partial_fit(v, &labels, None).unwrap();
    copy.partial_fit(v, &labels, None).unwrap();
    near(sgd.coef().as_slice(), copy.coef().as_slice());
    near(sgd.intercept(), copy.intercept());
    assert_eq!(sgd.t(), copy.t());

    // A tampered model is rejected, not a panic.
    let bad = json.replace("\"classes\":[0,1]", "\"classes\":[0,1,2]");
    let tampered: rune_linear_model::LogisticModel<f64, u8> = serde_json::from_str(&bad).unwrap();
    assert!(matches!(
        tampered.predict(v),
        Err(LinearError::InvalidModel(_))
    ));

    let est = SgdRegressor::new().with_alpha(0.5);
    let back: SgdRegressor = serde_json::from_str(&serde_json::to_string(&est).unwrap()).unwrap();
    assert_eq!(back, est);
}

#[test]
fn rejects_values_whose_squares_overflow() {
    let (x, mut y, labels) = data();
    y[0] = 1e200;
    for e in regress_errors(x.view(), &y, None) {
        assert_eq!(e, LinearError::Overflow("y"));
    }
    let big =
        Matrix::from_rows(&[[1e200, 0.0], [0.0, 1.0], [1.0, 1.0], [2.0, 0.0], [1.0, 3.0]]).unwrap();
    for e in classify_errors(big.view(), &labels, None) {
        assert_eq!(e, LinearError::Overflow("x"));
    }
}
