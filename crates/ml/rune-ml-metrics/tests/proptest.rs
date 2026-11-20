//! Invariants on random input.

use proptest::prelude::*;
use rune_ml_core::{MatrixView, Metric};
use rune_ml_metrics::*;

fn brute_auc(t: &[bool], s: &[f64]) -> f64 {
    let (mut num, mut den) = (0.0, 0.0);
    for (ti, si) in t.iter().zip(s) {
        for (tj, sj) in t.iter().zip(s) {
            if *ti && !*tj {
                den += 1.0;
                num += match si.partial_cmp(sj) {
                    Some(core::cmp::Ordering::Greater) => 1.0,
                    Some(core::cmp::Ordering::Equal) => 0.5,
                    _ => 0.0,
                };
            }
        }
    }
    num / den
}

proptest! {
    #[test]
    fn auc_is_pairwise_probability(
        v in prop::collection::vec((any::<bool>(), 0u8..6), 2..60)
    ) {
        let t: Vec<bool> = v.iter().map(|x| x.0).collect();
        let s: Vec<f64> = v.iter().map(|x| f64::from(x.1)).collect();
        match roc_auc_score(&t, &s) {
            Ok(auc) => prop_assert!((auc - brute_auc(&t, &s)).abs() < 1e-12),
            Err(e) => {
                let missing = matches!(e, MetricsError::MissingClass { .. });
                prop_assert!(missing);
            }
        }
        if let Ok(ap) = average_precision_score(&t, &s) {
            prop_assert!((0.0..=1.0).contains(&ap));
        }
    }

    #[test]
    fn classification_scores_are_bounded(
        v in prop::collection::vec((0u8..5, 0u8..5), 1..80)
    ) {
        let (t, p): (Vec<u8>, Vec<u8>) = v.into_iter().unzip();
        let acc = accuracy_score(&t, &p).unwrap();
        // Micro precision, recall and F1 all equal accuracy for single-label data.
        let f = f1_score(&t, &p, &Average::Micro, ZeroDivision::Zero).unwrap();
        prop_assert!((f - acc).abs() < 1e-12);
        for avg in [Average::Macro, Average::Weighted] {
            for zd in [ZeroDivision::Zero, ZeroDivision::One] {
                let f = fbeta_score(&t, &p, 0.7, &avg, zd).unwrap();
                prop_assert!((0.0..=1.0).contains(&f));
            }
        }
        let m = matthews_corrcoef(&t, &p).unwrap();
        prop_assert!((-1.0 - 1e-12..=1.0 + 1e-12).contains(&m));
        let k = cohen_kappa_score(&t, &p, KappaWeights::Linear).unwrap();
        prop_assert!(k.is_nan() || k <= 1.0 + 1e-12);
        let cm = confusion_matrix(&t, &p).unwrap();
        prop_assert_eq!(cm.as_slice().iter().sum::<usize>(), t.len());
        let report = classification_report(&t, &p, ZeroDivision::Zero).unwrap();
        prop_assert!(!report.to_string().is_empty());
    }

    #[test]
    fn external_cluster_scores_ignore_names(
        v in prop::collection::vec((0u8..4, 0u8..4), 2..80)
    ) {
        let (t, p): (Vec<u8>, Vec<u8>) = v.into_iter().unzip();
        let renamed: Vec<u8> = p.iter().map(|x| 9 - x).collect();
        let ari = adjusted_rand_score(&t, &p).unwrap();
        prop_assert!((ari - adjusted_rand_score(&t, &renamed).unwrap()).abs() < 1e-12);
        prop_assert!((ari - adjusted_rand_score(&p, &t).unwrap()).abs() < 1e-12);
        prop_assert!((adjusted_rand_score(&t, &t).unwrap() - 1.0).abs() < 1e-12);
        let m = AverageMethod::Arithmetic;
        let nmi = normalized_mutual_info_score(&t, &p, m).unwrap();
        prop_assert!((-1e-12..=1.0 + 1e-12).contains(&nmi));
        let ami = adjusted_mutual_info_score(&t, &p, m).unwrap();
        prop_assert!(ami.is_finite() && ami <= 1.0 + 1e-9);
    }

    #[test]
    fn internal_cluster_scores_do_not_panic(
        pts in prop::collection::vec((-1e3f64..1e3, -1e3f64..1e3, 0u8..3), 3..40)
    ) {
        let flat: Vec<f64> = pts.iter().flat_map(|p| [p.0, p.1]).collect();
        let labels: Vec<u8> = pts.iter().map(|p| p.2).collect();
        let x = MatrixView::new(&flat, pts.len(), 2).unwrap();
        if let Ok(s) = silhouette_score(x, &labels, Metric::Euclidean) {
            prop_assert!((-1.0 - 1e-12..=1.0 + 1e-12).contains(&s));
        }
        if let Ok(d) = davies_bouldin_score(x, &labels) {
            prop_assert!(d >= 0.0);
        }
        if let Ok(c) = calinski_harabasz_score(x, &labels) {
            prop_assert!(c >= 0.0);
        }
    }

    #[test]
    fn regression_identities(v in prop::collection::vec((-1e6f64..1e6, -1e6f64..1e6), 2..50)) {
        let (t, p): (Vec<f64>, Vec<f64>) = v.into_iter().unzip();
        let mse = mean_squared_error(&t, &p).unwrap();
        prop_assert!((root_mean_squared_error(&t, &p).unwrap() - mse.sqrt()).abs() <= 1e-9 * mse.sqrt().max(1.0));
        prop_assert!(mean_absolute_error(&t, &p).unwrap() <= max_error(&t, &p).unwrap() + 1e-9);
        prop_assert!(median_absolute_error(&t, &p).unwrap() <= max_error(&t, &p).unwrap());
        prop_assert!(r2_score(&t, &p).unwrap() <= explained_variance_score(&t, &p).unwrap() + 1e-9);
        prop_assert!((r2_score(&t, &t).unwrap() - 1.0).abs() < 1e-12);
    }
}
