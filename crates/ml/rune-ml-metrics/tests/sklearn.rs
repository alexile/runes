//! Expected values computed with scikit-learn 1.9.1 on the inputs in `data`.
#![allow(
    clippy::float_cmp,
    clippy::cast_possible_truncation,
    reason = "reference values are compared exactly where sklearn gives exact results"
)]

mod data;

use data::*;
use rune_ml_core::{Matrix, MatrixView, Metric};
use rune_ml_metrics::*;

#[track_caller]
fn close(got: f64, want: f64) {
    let tol = 1e-12 * want.abs().max(1.0);
    assert!((got - want).abs() <= tol, "got {got}, want {want}");
}

#[track_caller]
fn close_all(got: &[f64], want: &[f64]) {
    assert_eq!(got.len(), want.len(), "{got:?} vs {want:?}");
    for (&g, &w) in got.iter().zip(want) {
        close(g, w);
    }
}

const ZD: ZeroDivision = ZeroDivision::Zero;

#[test]
fn accuracy_and_balanced() {
    close(accuracy_score(&YT, &YP).unwrap(), 0.675);
    close(
        balanced_accuracy_score(&YT, &YP, false).unwrap(),
        0.676_107_226_107_226_1,
    );
    close(
        balanced_accuracy_score(&YT, &YP, true).unwrap(),
        0.568_142_968_142_968,
    );
}

#[test]
fn averaged_precision_recall_f() {
    let cases = [
        (Average::Micro, [0.675, 0.675, 0.675, 0.675]),
        (
            Average::Macro,
            [
                0.663_690_476_190_476_2,
                0.676_107_226_107_226_1,
                0.665_664_335_664_335_7,
                0.663_473_314_226_163_2,
            ],
        ),
        (
            Average::Weighted,
            [
                0.679_464_285_714_285_6,
                0.675,
                0.673_125_874_125_874_1,
                0.675_935_100_475_368_1,
            ],
        ),
    ];
    for (avg, [p, r, f1, f05]) in cases {
        close(precision_score(&YT, &YP, &avg, ZD).unwrap(), p);
        close(recall_score(&YT, &YP, &avg, ZD).unwrap(), r);
        close(f1_score(&YT, &YP, &avg, ZD).unwrap(), f1);
        close(fbeta_score(&YT, &YP, 0.5, &avg, ZD).unwrap(), f05);
    }
}

#[test]
fn per_class_f2() {
    let s = precision_recall_fscore_support(&YT, &YP, 2.0, ZD).unwrap();
    assert_eq!(s.labels, [0, 1, 2, 3]);
    close_all(
        &s.precision,
        &[
            0.666_666_666_666_666_6,
            0.666_666_666_666_666_6,
            0.571_428_571_428_571_4,
            0.75,
        ],
    );
    close_all(
        &s.recall,
        &[
            0.545_454_545_454_545_4,
            0.8,
            0.666_666_666_666_666_6,
            0.692_307_692_307_692_3,
        ],
    );
    close_all(
        &s.f_score,
        &[
            0.566_037_735_849_056_6,
            0.769_230_769_230_769_3,
            0.645_161_290_322_580_6,
            0.703_125,
        ],
    );
    assert_eq!(s.support, [11, 10, 6, 13]);
}

#[test]
fn binary_average() {
    let (t, p) = ([0, 1, 1, 0, 1], [1, 1, 0, 0, 1]);
    let pos1 = Average::Binary { pos_label: 1 };
    close(
        precision_score(&t, &p, &pos1, ZD).unwrap(),
        0.666_666_666_666_666_6,
    );
    close(
        recall_score(&t, &p, &pos1, ZD).unwrap(),
        0.666_666_666_666_666_6,
    );
    close(
        f1_score(&t, &p, &Average::Binary { pos_label: 0 }, ZD).unwrap(),
        0.5,
    );
    assert_eq!(
        f1_score(&YT, &YP, &pos1, ZD),
        Err(MetricsError::NotBinary { found: 4 })
    );
    assert_eq!(
        f1_score(&t, &p, &Average::Binary { pos_label: 7 }, ZD),
        Err(MetricsError::UnknownPosLabel)
    );
    // One label only, and it is not the positive one: nothing to score.
    assert_eq!(
        f1_score(&[0, 0], &[0, 0], &pos1, ZeroDivision::One).unwrap(),
        1.0
    );
}

#[test]
fn zero_division_modes() {
    // Class 2 is never predicted, so its precision is undefined.
    let (t, p) = ([0, 0, 1, 1, 2], [0, 0, 0, 1, 1]);
    let cases = [
        (ZeroDivision::Zero, 0.388_888_888_888_888_84),
        (ZeroDivision::One, 0.722_222_222_222_222_2),
        (ZeroDivision::Nan, 0.583_333_333_333_333_3),
    ];
    for (zd, prec) in cases {
        close(precision_score(&t, &p, &Average::Macro, zd).unwrap(), prec);
        close(recall_score(&t, &p, &Average::Macro, zd).unwrap(), 0.5);
        close(
            f1_score(&t, &p, &Average::Macro, zd).unwrap(),
            0.433_333_333_333_333_35,
        );
        close(f1_score(&t, &p, &Average::Weighted, zd).unwrap(), 0.52);
    }
    let s = precision_recall_fscore_support(&t, &p, 1.0, ZeroDivision::Nan).unwrap();
    assert!(s.precision[2].is_nan());
}

#[test]
fn confusion() {
    let cm = confusion_matrix(&YT, &YP).unwrap();
    assert_eq!(
        cm.to_rows(),
        [[6, 3, 1, 1], [2, 8, 0, 0], [0, 0, 4, 2], [1, 1, 2, 9]]
    );
    assert_eq!(cm[(3, 3)], 9);
    assert_eq!(cm.get(4, 0), None);
    let cm = confusion_matrix_with_labels(&YT, &YP, &[3, 0]).unwrap();
    assert_eq!(cm.to_rows(), [[9, 1], [1, 6]]);
    assert!(confusion_matrix_with_labels(&YT, &YP, &[3, 3]).is_err());
    assert!(confusion_matrix_with_labels(&YT, &YP, &[9]).is_err());
}

#[test]
fn mcc_and_kappa() {
    close(
        matthews_corrcoef(&YT, &YP).unwrap(),
        0.562_821_580_839_460_2,
    );
    let pred: Vec<bool> = SB.iter().map(|&s| s > 0.4).collect();
    close(
        matthews_corrcoef(&YB, &pred).unwrap(),
        0.764_705_882_352_941_1,
    );
    assert_eq!(matthews_corrcoef(&[1, 1, 1], &[1, 1, 1]).unwrap(), 0.0);
    close(
        cohen_kappa_score(&YT, &YP, KappaWeights::None).unwrap(),
        0.560_439_560_439_560_4,
    );
    close(
        cohen_kappa_score(&YT, &YP, KappaWeights::Linear).unwrap(),
        0.636_015_325_670_498_1,
    );
    close(
        cohen_kappa_score(&YT, &YP, KappaWeights::Quadratic).unwrap(),
        0.681_528_662_420_382_2,
    );
    assert!(
        cohen_kappa_score(&[0, 0, 0], &[0, 0, 0], KappaWeights::None)
            .unwrap()
            .is_nan()
    );
}

#[test]
fn report_matches_sklearn_text() {
    let r = classification_report(&YT, &YP, ZD).unwrap();
    let want2 = "              precision    recall  f1-score   support

           0       0.67      0.55      0.60        11
           1       0.67      0.80      0.73        10
           2       0.57      0.67      0.62         6
           3       0.75      0.69      0.72        13

    accuracy                           0.68        40
   macro avg       0.66      0.68      0.67        40
weighted avg       0.68      0.68      0.67        40
";
    assert_eq!(r.to_string(), want2);
    let want4 = "              precision    recall  f1-score   support

           0     0.6667    0.5455    0.6000        11
           1     0.6667    0.8000    0.7273        10
           2     0.5714    0.6667    0.6154         6
           3     0.7500    0.6923    0.7200        13

    accuracy                         0.6750        40
   macro avg     0.6637    0.6761    0.6657        40
weighted avg     0.6795    0.6750    0.6731        40
";
    assert_eq!(format!("{r:.4}"), want4);
    close(r.weighted_avg.f1, 0.673_125_874_125_874_1);
}

#[test]
fn ranking_curves() {
    let roc = roc_curve(&YB, &SB, true).unwrap();
    close_all(
        &roc.fpr,
        &[
            0.0,
            0.0,
            0.0,
            0.0,
            0.235_294_117_647_058_82,
            0.588_235_294_117_647_1,
            0.764_705_882_352_941_1,
            0.882_352_941_176_470_6,
            1.0,
        ],
    );
    close_all(
        &roc.tpr,
        &[
            0.0,
            0.076_923_076_923_076_93,
            0.384_615_384_615_384_64,
            0.769_230_769_230_769_3,
            1.0,
            1.0,
            1.0,
            1.0,
            1.0,
        ],
    );
    assert_eq!(
        roc.thresholds,
        [f64::INFINITY, 0.9, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.0]
    );
    assert_eq!(roc_curve(&YB, &SB, false).unwrap().fpr.len(), 10);
    close(roc_auc_score(&YB, &SB).unwrap(), 0.972_850_678_733_031_5);

    let pr = precision_recall_curve(&YB, &SB, false).unwrap();
    close_all(
        &pr.precision,
        &[
            0.433_333_333_333_333_35,
            0.448_275_862_068_965_5,
            0.464_285_714_285_714_3,
            0.5,
            0.565_217_391_304_347_8,
            0.764_705_882_352_941_1,
            1.0,
            1.0,
            1.0,
            1.0,
        ],
    );
    close_all(
        &pr.recall,
        &[
            1.0,
            1.0,
            1.0,
            1.0,
            1.0,
            1.0,
            0.769_230_769_230_769_3,
            0.384_615_384_615_384_64,
            0.076_923_076_923_076_93,
            0.0,
        ],
    );
    assert_eq!(pr.thresholds, [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.9]);
    let pr = precision_recall_curve(&YB, &SB, true).unwrap();
    close_all(
        &pr.precision,
        &[
            0.433_333_333_333_333_35,
            0.764_705_882_352_941_1,
            1.0,
            1.0,
            1.0,
            1.0,
        ],
    );
    assert_eq!(pr.thresholds, [0.0, 0.5, 0.6, 0.7, 0.9]);
    close(
        average_precision_score(&YB, &SB).unwrap(),
        0.945_701_357_466_063_3,
    );
}

#[test]
fn ranking_f32_matches_f64() {
    let s32: Vec<f32> = SB.iter().map(|&v| v as f32).collect();
    assert_eq!(
        roc_auc_score(&YB, &s32).unwrap(),
        roc_auc_score(&YB, &SB).unwrap()
    );
}

#[test]
fn probabilities() {
    close(
        brier_score_loss(&YB, &SB).unwrap(),
        0.141_333_333_333_333_34,
    );
    let p = Matrix::from_rows(&P).unwrap();
    close(
        log_loss(&Y3, p.view(), Some(&[0, 1, 2])).unwrap(),
        1.374_540_470_917_224_9,
    );
    // One column: probability of the larger label. Exact 0 and 1 are clipped.
    let pb = [0.0, 0.7, 1.0, 0.2];
    let v = MatrixView::new(&pb, 4, 1).unwrap();
    close(
        log_loss(&[0, 1, 1, 0], v, None).unwrap(),
        0.144_954_623_813_235_65,
    );
    let pb32 = [0.0_f32, 0.7, 1.0, 0.2];
    let v = MatrixView::new(&pb32, 4, 1).unwrap();
    let l32 = log_loss(&[0, 1, 1, 0], v, None).unwrap();
    assert!((l32 - 0.144_954_681_396_484_38).abs() < 1e-6, "{l32}");
    let doc = Matrix::from_rows(&[[0.1, 0.9], [0.9, 0.1], [0.8, 0.2], [0.35, 0.65]]).unwrap();
    close(
        log_loss(&["spam", "ham", "ham", "spam"], doc.view(), None).unwrap(),
        0.216_161_874_680_579_12,
    );
}

#[test]
fn regression() {
    close(
        mean_absolute_error(&A, &B).unwrap(),
        0.816_308_418_125_838_2,
    );
    close(mean_squared_error(&A, &B).unwrap(), 0.866_177_193_016_042);
    close(
        root_mean_squared_error(&A, &B).unwrap(),
        0.930_686_409_601_022_3,
    );
    close(r2_score(&A, &B).unwrap(), 0.892_328_375_715_141_2);
    close(
        explained_variance_score(&A, &B).unwrap(),
        0.895_811_875_562_397,
    );
    close(
        mean_absolute_percentage_error(&A, &B).unwrap(),
        0.591_912_162_550_790_9,
    );
    close(
        median_absolute_error(&A, &B).unwrap(),
        0.844_362_976_401_547,
    );
    close(max_error(&A, &B).unwrap(), 1.929_532_053_816_986);
    // Even count: median of the two middle values.
    assert_eq!(
        median_absolute_error(&[0.0, 0.0, 0.0, 0.0], &[1.0, 2.0, 3.0, 4.0]).unwrap(),
        2.5
    );
}

#[test]
fn regression_constant_target() {
    assert_eq!(r2_score(&[2.0, 2.0], &[2.0, 2.0]).unwrap(), 1.0);
    assert_eq!(r2_score(&[2.0, 2.0], &[2.0, 3.0]).unwrap(), 0.0);
    assert_eq!(
        explained_variance_score(&[2.0, 2.0], &[3.0, 3.0]).unwrap(),
        1.0
    );
}

#[test]
fn clustering_external() {
    close(
        adjusted_rand_score(&LT, &LP).unwrap(),
        0.383_529_776_674_938,
    );
    close(
        mutual_info_score(&LT, &LP).unwrap(),
        0.480_620_809_643_669_27,
    );
    let cases = [
        (
            AverageMethod::Min,
            0.437_640_351_848_609_4,
            0.400_335_937_060_140_4,
        ),
        (
            AverageMethod::Geometric,
            0.405_665_336_473_046_76,
            0.369_296_625_897_359_6,
        ),
        (
            AverageMethod::Arithmetic,
            0.404_500_605_976_500_17,
            0.368_171_630_656_341_5,
        ),
        (
            AverageMethod::Max,
            0.376_026_489_606_509_36,
            0.340_791_333_612_406_6,
        ),
    ];
    for (m, nmi, ami) in cases {
        close(normalized_mutual_info_score(&LT, &LP, m).unwrap(), nmi);
        let got = adjusted_mutual_info_score(&LT, &LP, m).unwrap();
        assert!((got - ami).abs() < 1e-10, "{m:?}: {got} vs {ami}");
    }
    // Different label types on each side.
    let names: Vec<String> = LP.iter().map(|l| format!("c{l}")).collect();
    close(
        adjusted_rand_score(&LT, &names).unwrap(),
        0.383_529_776_674_938,
    );
}

#[test]
fn clustering_external_larger() {
    let t: Vec<usize> = (0..3000).map(|i| (i * 7) % 5).collect();
    let p: Vec<usize> = (0..3000)
        .map(|i| {
            if i % 3 == 0 {
                t[i]
            } else {
                (i * i + 3 * i) % 7
            }
        })
        .collect();
    let ami = adjusted_mutual_info_score(&t, &p, AverageMethod::Arithmetic).unwrap();
    assert!((ami - 0.190_538_670_472_989_8).abs() < 1e-10, "{ami}");
    close(
        normalized_mutual_info_score(&t, &p, AverageMethod::Arithmetic).unwrap(),
        0.192_189_526_974_938_3,
    );
    close(
        adjusted_rand_score(&t, &p).unwrap(),
        0.109_184_098_091_983_94,
    );

    let t: Vec<usize> = (0..20).map(|i| i % 2).collect();
    let p: Vec<usize> = (0..20).map(|i| (i / 2) % 2).collect();
    let ami = adjusted_mutual_info_score(&t, &p, AverageMethod::Arithmetic).unwrap();
    assert!((ami + 0.040_640_679_488_999_604).abs() < 1e-10, "{ami}");
}

#[test]
fn clustering_special_cases() {
    let m = AverageMethod::Arithmetic;
    assert_eq!(
        adjusted_mutual_info_score(&[1, 1], &[2, 2], m).unwrap(),
        1.0
    );
    assert_eq!(
        adjusted_mutual_info_score(&[1, 2], &[2, 2], m).unwrap(),
        0.0
    );
    assert_eq!(
        normalized_mutual_info_score(&[1, 1], &[2, 2], m).unwrap(),
        1.0
    );
    assert_eq!(adjusted_rand_score(&[1, 2, 3], &[4, 5, 6]).unwrap(), 1.0);
    assert_eq!(
        adjusted_rand_score::<u8, u8>(&[], &[]),
        Err(MetricsError::Empty)
    );
}

#[test]
fn clustering_internal() {
    let x = Matrix::from_rows(&X).unwrap();
    for (metric, want) in [
        (Metric::Euclidean, 0.487_728_233_964_400_5),
        (Metric::Manhattan, 0.491_365_230_836_334_27),
        (Metric::Cosine, 0.660_928_642_386_460_1),
    ] {
        close(silhouette_score(x.view(), &LX, metric).unwrap(), want);
    }
    let s = silhouette_samples(x.view(), &LX, Metric::Euclidean).unwrap();
    close_all(
        &s[..5],
        &[
            -0.284_014_595_620_141_6,
            0.553_765_915_391_073_6,
            0.205_846_878_291_827_35,
            0.569_231_739_918_242_2,
            0.512_647_255_591,
        ],
    );
    close(
        davies_bouldin_score(x.view(), &LX).unwrap(),
        0.726_511_874_763_601_8,
    );
    close(
        calinski_harabasz_score(x.view(), &LX).unwrap(),
        32.625_734_197_433_836,
    );

    let x32: Matrix<f32> = x.view().cast();
    let s32 = silhouette_score(x32.view(), &LX, Metric::Euclidean).unwrap();
    assert!((s32 - 0.487_728_233_964_400_5).abs() < 1e-5);
}

#[test]
fn hostile_input() {
    let e = Err(MetricsError::LengthMismatch {
        expected: 2,
        found: 1,
    });
    assert_eq!(accuracy_score(&[1, 2], &[1]), e);
    assert_eq!(mean_squared_error(&[1.0, 2.0], &[1.0]), e);
    assert_eq!(accuracy_score::<u8>(&[], &[]), Err(MetricsError::Empty));
    assert_eq!(
        r2_score(&[1.0, f64::NAN], &[1.0, 2.0]),
        Err(MetricsError::NonFinite { index: 1 })
    );
    assert_eq!(
        roc_auc_score(&[true, false], &[f32::INFINITY, 0.0]),
        Err(MetricsError::NonFinite { index: 0 })
    );
    assert_eq!(
        roc_auc_score(&[true, true], &[0.1, 0.2]),
        Err(MetricsError::MissingClass {
            missing: "negative"
        })
    );
    assert!(average_precision_score(&[false, false], &[0.1, 0.2]).is_err());
    assert_eq!(
        brier_score_loss(&[true], &[1.5]),
        Err(MetricsError::InvalidProbability { index: 0 })
    );
    assert!(r2_score(&[1.0], &[1.0]).is_err());
    assert!(fbeta_score(&[1], &[1], -1.0, &Average::Micro, ZD).is_err());
    assert!(fbeta_score(&[1], &[1], f64::NAN, &Average::Micro, ZD).is_err());

    // log loss: unknown label, single class, wrong column count.
    let p = Matrix::from_rows(&[[0.5, 0.5], [0.5, 0.5]]).unwrap();
    assert_eq!(
        log_loss(&[0, 2], p.view(), Some(&[0, 1])),
        Err(MetricsError::UnknownLabel { index: 1 })
    );
    assert!(log_loss(&[0, 0], p.view(), None).is_err());
    assert!(log_loss(&[0, 1], p.view(), Some(&[0, 1, 2])).is_err());

    // Clustering: label count and non-finite features.
    let x = Matrix::from_rows(&[[0.0], [1.0], [2.0]]).unwrap();
    assert!(silhouette_score(x.view(), &[0, 0, 0], Metric::Euclidean).is_err());
    assert!(silhouette_score(x.view(), &[0, 1, 2], Metric::Euclidean).is_err());
    assert!(davies_bouldin_score(x.view(), &[0, 1]).is_err());
    let bad = Matrix::from_rows(&[[0.0], [f64::NAN], [2.0]]).unwrap();
    assert!(matches!(
        calinski_harabasz_score(bad.view(), &[0, 1, 1]),
        Err(MetricsError::Core(_))
    ));
}

#[test]
fn ties_get_half_credit() {
    // All scores tied: AUC is exactly 0.5.
    assert_eq!(
        roc_auc_score(&[true, false, true, false], &[0.3, 0.3, 0.3, 0.3]).unwrap(),
        0.5
    );
    // Brute-force pair count with ties as 1/2.
    let (t, s) = (&YB, &SB);
    let (mut num, mut den) = (0.0, 0.0);
    for i in 0..t.len() {
        for j in 0..t.len() {
            if t[i] && !t[j] {
                den += 1.0;
                num += if s[i] > s[j] {
                    1.0
                } else if s[i] == s[j] {
                    0.5
                } else {
                    0.0
                };
            }
        }
    }
    close(roc_auc_score(t, s).unwrap(), num / den);
}
