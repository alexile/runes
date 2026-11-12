//! Known-dataset and determinism tests for `rune-hdbscan`.

use rune_hdbscan::{Hdbscan, Metric};

/// Deterministic xorshift64* stream in `[0, 1)`, so the fixtures need no RNG crate.
struct Stream(u64);

impl Stream {
    #[allow(clippy::cast_precision_loss, reason = "53-bit value is exact in f64")]
    fn next(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Three dense blobs of 40 points (uniform in a radius-1 square) plus four
/// isolated far-away points. Returns the points and the ground-truth label
/// (`-1` for the isolated points).
fn blobs_with_noise() -> (Vec<Vec<f64>>, Vec<i32>) {
    let centres = [(0.0, 0.0), (12.0, 0.0), (6.0, 10.0)];
    let mut rng = Stream(0x5DEE_CE66_D1CE_4E5B);
    let mut points = Vec::new();
    let mut truth = Vec::new();
    for _ in 0..40 {
        for (label, &(cx, cy)) in (0i32..).zip(&centres) {
            points.push(vec![
                cx + 2.0f64.mul_add(rng.next(), -1.0),
                cy + 2.0f64.mul_add(rng.next(), -1.0),
            ]);
            truth.push(label);
        }
    }
    for p in [[-30.0, -30.0], [40.0, -25.0], [-20.0, 45.0], [50.0, 50.0]] {
        points.push(p.to_vec());
        truth.push(-1);
    }
    (points, truth)
}

/// Same clustering up to label renaming, with noise (`-1`) matching exactly.
fn same_labelling(a: &[i32], b: &[i32]) -> bool {
    a.len() == b.len()
        && (0..a.len()).all(|i| {
            (a[i] == -1) == (b[i] == -1) && (0..a.len()).all(|j| (a[i] == a[j]) == (b[i] == b[j]))
        })
}

#[test]
fn three_blobs_and_isolated_noise() {
    let (points, truth) = blobs_with_noise();
    let result = Hdbscan::new(10).fit(&points);
    assert_eq!(result.num_clusters, 3);
    assert!(
        same_labelling(&result.labels, &truth),
        "{:?}",
        result.labels
    );
    for (&label, &p) in result.labels.iter().zip(&result.probabilities) {
        assert!((0.0..=1.0).contains(&p));
        if label == -1 {
            assert!(p.abs() < f64::EPSILON);
        }
    }
    // Labels are contiguous from 0.
    let mut seen: Vec<i32> = result.labels.iter().copied().filter(|&l| l >= 0).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen, vec![0, 1, 2]);
}

#[test]
fn manhattan_metric_recovers_the_same_clusters() {
    let (points, truth) = blobs_with_noise();
    let result = Hdbscan::new(10).metric(Metric::Manhattan).fit(&points);
    assert!(same_labelling(&result.labels, &truth));
}

#[test]
fn repeated_runs_are_bit_identical() {
    let (points, _) = blobs_with_noise();
    let a = Hdbscan::new(10).min_samples(5).fit(&points);
    for _ in 0..5 {
        let b = Hdbscan::new(10).min_samples(5).fit(&points);
        assert_eq!(a.labels, b.labels);
        assert_eq!(a.num_clusters, b.num_clusters);
        for (x, y) in a.probabilities.iter().zip(&b.probabilities) {
            assert_eq!(x.to_bits(), y.to_bits());
        }
    }
}

#[test]
fn input_order_does_not_change_the_clustering() {
    let (points, _) = blobs_with_noise();
    let forward = Hdbscan::new(10).fit(&points);
    let reversed_points: Vec<Vec<f64>> = points.iter().rev().cloned().collect();
    let mut reversed = Hdbscan::new(10).fit(&reversed_points).labels;
    reversed.reverse();
    assert!(same_labelling(&forward.labels, &reversed));
}

#[test]
fn fewer_points_than_min_cluster_size_is_all_noise() {
    let result = Hdbscan::new(5).fit(&[vec![0.0], vec![0.1], vec![0.2]]);
    assert_eq!(result.labels, vec![-1; 3]);
    assert_eq!(result.num_clusters, 0);
}

/// Regression: `fit(&[])` used to panic.
#[test]
fn empty_input_yields_empty_result() {
    let result = Hdbscan::new(5).fit(&[]);
    assert_eq!(result.labels, Vec::<i32>::new());
    assert_eq!(result.probabilities, Vec::<f64>::new());
    assert_eq!(result.num_clusters, 0);
}
