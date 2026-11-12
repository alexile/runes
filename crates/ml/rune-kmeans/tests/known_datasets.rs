//! Known-dataset and seeded-determinism tests for `rune-kmeans`.

use rune_kmeans::{KMeans, Metric};

/// Plus-shaped blob of five points: the centre and the centre ± `r` on each
/// axis. Its mean is exactly the centre and its inertia about the centre is `4 r²`.
fn plus_blob(cx: f64, cy: f64, r: f64) -> Vec<Vec<f64>> {
    vec![
        vec![cx, cy],
        vec![cx + r, cy],
        vec![cx - r, cy],
        vec![cx, cy + r],
        vec![cx, cy - r],
    ]
}

const CENTRES: [(f64, f64); 3] = [(0.0, 0.0), (20.0, 0.0), (10.0, 30.0)];
const RADIUS: f64 = 1.5;

/// Three well-separated plus blobs, points interleaved so blob membership is
/// not simply contiguous in the input.
fn three_blobs() -> (Vec<Vec<f64>>, Vec<usize>) {
    let blobs: Vec<Vec<Vec<f64>>> = CENTRES
        .iter()
        .map(|&(x, y)| plus_blob(x, y, RADIUS))
        .collect();
    let mut points = Vec::new();
    let mut truth = Vec::new();
    for i in 0..5 {
        for (b, blob) in blobs.iter().enumerate() {
            points.push(blob[i].clone());
            truth.push(b);
        }
    }
    (points, truth)
}

/// Labels describe the same partition up to renaming.
fn same_partition(a: &[usize], b: &[usize]) -> bool {
    a.len() == b.len()
        && (0..a.len()).all(|i| (0..a.len()).all(|j| (a[i] == a[j]) == (b[i] == b[j])))
}

#[test]
fn three_blobs_recover_exact_centres_and_inertia() {
    let (points, truth) = three_blobs();
    let result = KMeans::new(3).tol(1e-12).random_seed(42).fit(&points);

    assert!(
        same_partition(&result.labels, &truth),
        "{:?}",
        result.labels
    );

    for (i, &blob) in truth.iter().enumerate() {
        let c = &result.centroids[result.labels[i]];
        let (cx, cy) = CENTRES[blob];
        assert!(
            (c[0] - cx).abs() < 1e-9 && (c[1] - cy).abs() < 1e-9,
            "{c:?}"
        );
    }
    let want_inertia = 3.0 * 4.0 * RADIUS * RADIUS;
    assert!(
        (result.inertia - want_inertia).abs() < 1e-9,
        "inertia {} want {want_inertia}",
        result.inertia
    );
}

#[test]
fn manhattan_metric_finds_the_same_partition() {
    let (points, truth) = three_blobs();
    let result = KMeans::new(3)
        .metric(Metric::Manhattan)
        .random_seed(5)
        .fit(&points);
    assert!(same_partition(&result.labels, &truth));
    // Manhattan inertia sums squared L1 distances: 4 points at distance r per blob.
    let want = 3.0 * 4.0 * RADIUS * RADIUS;
    assert!((result.inertia - want).abs() < 1e-9);
}

#[test]
fn same_seed_is_bit_identical() {
    let (points, _) = three_blobs();
    for seed in [0, 1, 42, u64::MAX] {
        let a = KMeans::new(3).n_init(3).random_seed(seed).fit(&points);
        let b = KMeans::new(3).n_init(3).random_seed(seed).fit(&points);
        assert_eq!(a.labels, b.labels);
        assert_eq!(a.centroids, b.centroids);
        assert_eq!(a.inertia.to_bits(), b.inertia.to_bits());
        assert_eq!(a.iterations, b.iterations);
    }
}

#[test]
fn every_seed_finds_the_global_optimum_on_separable_blobs() {
    let (points, truth) = three_blobs();
    for seed in 0..50 {
        let result = KMeans::new(3).random_seed(seed).fit(&points);
        assert!(same_partition(&result.labels, &truth), "seed {seed}");
    }
}

#[test]
fn single_cluster_centroid_is_the_mean() {
    let points = vec![
        vec![1.0, 2.0],
        vec![3.0, -4.0],
        vec![5.0, 8.0],
        vec![-1.0, 2.0],
    ];
    let result = KMeans::new(1).fit(&points);
    assert_eq!(result.labels, vec![0; 4]);
    assert!((result.centroids[0][0] - 2.0).abs() < 1e-12);
    assert!((result.centroids[0][1] - 2.0).abs() < 1e-12);
    // Σ‖p − (2, 2)‖² = 1 + 37 + 45 + 9.
    assert!((result.inertia - 92.0).abs() < 1e-9);
}

#[test]
fn k_equal_to_n_has_zero_inertia() {
    let points = vec![vec![0.0], vec![5.0], vec![9.0]];
    let result = KMeans::new(3).fit(&points);
    assert!(result.inertia.abs() < 1e-12);
    assert!(same_partition(&result.labels, &[0, 1, 2]));
}

#[test]
fn single_point() {
    let result = KMeans::new(1).fit(&[vec![3.0, 4.0]]);
    assert_eq!(result.labels, vec![0]);
    assert_eq!(result.centroids, vec![vec![3.0, 4.0]]);
    assert!(result.inertia.abs() < 1e-12);
}

/// Regression: `KMeans::new(0).fit(..)` used to index past an empty
/// per-cluster accumulator and panic.
#[test]
fn zero_k_is_treated_as_one_cluster() {
    let points = vec![vec![0.0], vec![2.0]];
    let result = KMeans::new(0).fit(&points);
    assert_eq!(result.labels, vec![0, 0]);
    assert_eq!(result.centroids.len(), 1);
    assert!((result.centroids[0][0] - 1.0).abs() < 1e-12);
}
