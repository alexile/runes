//! Known-dataset quality tests and property tests for `rune-umap`.

#![allow(
    clippy::unwrap_used,
    clippy::cast_precision_loss,
    reason = "test code: failures should abort, indices are small"
)]

use proptest::prelude::*;
use rune_umap::{KnnMethod, Metric, Umap, UmapError, trustworthiness};

/// Small deterministic LCG so the datasets need no extra dependency.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 11) as f64 / (1u64 << 53) as f64) - 0.5
    }
}

/// `n_clusters` isotropic Gaussian-ish blobs in `dim` dimensions, centres 10 apart.
fn blobs(n_clusters: usize, per: usize, dim: usize, seed: u64) -> (Vec<Vec<f64>>, Vec<i64>) {
    let mut rng = Lcg(seed);
    let mut pts = Vec::new();
    let mut labels = Vec::new();
    for c in 0..n_clusters {
        let centre: Vec<f64> = (0..dim)
            .map(|d| if d % n_clusters == c { 10.0 } else { 0.0 })
            .collect();
        for _ in 0..per {
            pts.push(centre.iter().map(|x| x + rng.next() + rng.next()).collect());
            labels.push(i64::try_from(c).unwrap());
        }
    }
    (pts, labels)
}

/// A swiss roll: a 2D sheet rolled up in 3D.
fn swiss_roll(n: usize, seed: u64) -> Vec<Vec<f64>> {
    let mut rng = Lcg(seed);
    (0..n)
        .map(|_| {
            let t = 1.5 * std::f64::consts::PI * 2.0f64.mul_add(rng.next() + 0.5, 1.0);
            let h = 20.0 * (rng.next() + 0.5);
            vec![t * t.cos(), h, t * t.sin()]
        })
        .collect()
}

fn centroid(rows: &[Vec<f64>]) -> Vec<f64> {
    let d = rows[0].len();
    (0..d)
        .map(|j| rows.iter().map(|r| r[j]).sum::<f64>() / rows.len() as f64)
        .collect()
}

fn dist(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

#[test]
fn blobs_are_trustworthy_and_separated() {
    let (pts, _) = blobs(3, 40, 8, 1);
    let fitted = Umap::new()
        .n_neighbors(10)
        .n_epochs(200)
        .try_fit(&pts)
        .unwrap();
    let t = trustworthiness(&pts, &fitted.embedding, 10, Metric::Euclidean).unwrap();
    assert!(t > 0.9, "trustworthiness {t:.3}");

    // Every point is closer to its own cluster centroid than to any other.
    let cents: Vec<Vec<f64>> = fitted.embedding.chunks(40).map(centroid).collect();
    for (i, p) in fitted.embedding.iter().enumerate() {
        let own = i / 40;
        let nearest = (0..3)
            .min_by(|&a, &b| dist(p, &cents[a]).total_cmp(&dist(p, &cents[b])))
            .unwrap();
        assert_eq!(nearest, own, "point {i} landed in the wrong cluster");
    }
}

#[test]
fn swiss_roll_is_trustworthy() {
    let pts = swiss_roll(300, 7);
    let fitted = Umap::new()
        .n_neighbors(12)
        .n_epochs(200)
        .try_fit(&pts)
        .unwrap();
    let t = trustworthiness(&pts, &fitted.embedding, 10, Metric::Euclidean).unwrap();
    assert!(t > 0.9, "trustworthiness {t:.3}");
}

#[test]
fn nn_descent_matches_exact_quality() {
    let (pts, _) = blobs(3, 60, 6, 3);
    let fitted = Umap::new()
        .n_neighbors(10)
        .n_epochs(150)
        .knn_method(KnnMethod::NnDescent)
        .try_fit(&pts)
        .unwrap();
    let t = trustworthiness(&pts, &fitted.embedding, 10, Metric::Euclidean).unwrap();
    assert!(t > 0.9, "trustworthiness {t:.3}");
}

#[test]
fn every_metric_produces_finite_output() {
    let (pts, _) = blobs(2, 15, 5, 5);
    for m in Metric::ALL {
        let f = Umap::new()
            .n_neighbors(5)
            .n_epochs(50)
            .metric(m)
            .try_fit(&pts)
            .unwrap();
        assert!(f.embedding.iter().flatten().all(|x| x.is_finite()), "{m}");
    }
}

#[test]
fn transform_places_points_near_their_cluster() {
    let (pts, _) = blobs(2, 30, 4, 9);
    let fitted = Umap::new()
        .n_neighbors(8)
        .n_epochs(150)
        .try_fit(&pts)
        .unwrap();
    let cents: Vec<Vec<f64>> = fitted.embedding.chunks(30).map(centroid).collect();
    let (new, _) = blobs(2, 5, 4, 99);
    let out = fitted.try_transform(&new).unwrap();
    for (i, p) in out.iter().enumerate() {
        let own = i / 5;
        assert!(
            dist(p, &cents[own]) < dist(p, &cents[1 - own]),
            "new point {i}"
        );
    }
    assert_eq!(fitted.try_transform(&[]).unwrap(), Vec::<Vec<f64>>::new());
}

#[test]
fn supervised_and_semi_supervised() {
    let (pts, labels) = blobs(2, 20, 4, 11);
    let f = Umap::new()
        .n_neighbors(5)
        .n_epochs(80)
        .try_fit_supervised(&pts, &labels)
        .unwrap();
    assert_eq!(f.embedding.len(), 40);
    let partial: Vec<Option<i64>> = labels
        .iter()
        .enumerate()
        .map(|(i, &l)| (i % 3 == 0).then_some(l))
        .collect();
    let f = Umap::new()
        .n_neighbors(5)
        .n_epochs(80)
        .fit_semi_supervised(&pts, &partial)
        .unwrap();
    assert_eq!(f.embedding.len(), 40);
    assert!(matches!(
        Umap::new()
            .n_neighbors(5)
            .try_fit_supervised(&pts, &labels[..3]),
        Err(UmapError::LabelLengthMismatch {
            labels: 3,
            points: 40
        })
    ));
}

#[test]
fn input_validation() {
    let u = Umap::new().n_neighbors(2);
    assert_eq!(u.try_fit(&[]).unwrap_err(), UmapError::Empty);
    assert_eq!(
        u.try_fit(&[vec![], vec![], vec![]]).unwrap_err(),
        UmapError::NoFeatures
    );
    assert!(matches!(
        u.try_fit(&[vec![1.0], vec![2.0], vec![f64::INFINITY]]),
        Err(UmapError::NonFinite { row: 2, col: 0, .. })
    ));
    assert!(matches!(
        u.try_fit(&[vec![1.0], vec![2.0]]),
        Err(UmapError::TooFewSamples {
            n_neighbors: 2,
            n_samples: 2
        })
    ));
    assert!(matches!(
        Umap::new().min_dist(f64::NAN).try_fit(&[vec![1.0]]),
        Err(UmapError::InvalidParameter {
            name: "min_dist",
            ..
        })
    ));
    let fitted = u
        .n_epochs(10)
        .try_fit(&[vec![1.0], vec![2.0], vec![3.0], vec![4.0]])
        .unwrap();
    assert!(matches!(
        fitted.try_transform(&[vec![f64::NAN]]),
        Err(UmapError::NonFinite { .. })
    ));
}

#[test]
fn duplicates_and_extreme_values_stay_finite() {
    let mut pts = vec![vec![1.0, 1.0]; 10];
    pts.extend((0..10).map(|i| vec![f64::from(i) * 1e300, -1e300]));
    let f = Umap::new()
        .n_neighbors(4)
        .n_epochs(50)
        .try_fit(&pts)
        .unwrap();
    assert!(f.embedding.iter().flatten().all(|x| x.is_finite()));
}

#[test]
fn tiny_input_with_many_components() {
    let pts = vec![vec![0.0], vec![1.0], vec![2.0]];
    let f = Umap::new()
        .n_neighbors(2)
        .n_components(5)
        .n_epochs(20)
        .try_fit(&pts)
        .unwrap();
    assert!(f.embedding.iter().all(|r| r.len() == 5));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn fit_is_total_and_deterministic(
        rows in prop::collection::vec(prop::collection::vec(-1e3f64..1e3, 3), 4..30),
        k in 2usize..6,
        nc in 1usize..4,
        seed in any::<u64>(),
        metric in prop::sample::select(Metric::ALL.to_vec()),
    ) {
        let umap = Umap::new().n_neighbors(k).n_components(nc).n_epochs(20).metric(metric).random_seed(seed);
        match umap.try_fit(&rows) {
            Ok(a) => {
                prop_assert!(k < rows.len());
                prop_assert_eq!(a.embedding.len(), rows.len());
                prop_assert!(a.embedding.iter().all(|r| r.len() == nc && r.iter().all(|x| x.is_finite())));
                let b = umap.try_fit(&rows).unwrap();
                prop_assert_eq!(&a.embedding, &b.embedding);
                let t = a.try_transform(&rows[..2]).unwrap();
                prop_assert!(t.iter().flatten().all(|x| x.is_finite()));
            }
            Err(e) => prop_assert!(matches!(e, UmapError::TooFewSamples { .. }), "{e}"),
        }
    }

    #[test]
    fn trustworthiness_in_unit_interval(
        rows in prop::collection::vec(prop::collection::vec(-10f64..10.0, 2), 8..25),
        perm_seed in any::<u64>(),
    ) {
        let mut rng = Lcg(perm_seed);
        let low: Vec<Vec<f64>> = rows.iter().map(|_| vec![rng.next(), rng.next()]).collect();
        let t = trustworthiness(&rows, &low, 3, Metric::Euclidean).unwrap();
        prop_assert!((-1e-12..=1.0 + 1e-12).contains(&t), "{t}");
    }
}
