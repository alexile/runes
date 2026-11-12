use rayon::prelude::*;

/// Distance metric used to measure similarity between points.
#[derive(Clone, Debug, Default)]
pub enum Metric {
    /// Straight-line distance: `sqrt(Σ (aᵢ - bᵢ)²)`.
    #[default]
    Euclidean,
    /// City-block distance: `Σ |aᵢ - bᵢ|`.
    Manhattan,
    /// Angular distance: `1 - cosine_similarity(a, b)`, in `[0, 2]`.
    Cosine,
}

/// Distance between two points under the given metric.
pub fn point_distance(metric: &Metric, a: &[f64], b: &[f64]) -> f64 {
    match metric {
        Metric::Euclidean => euclidean(a, b),
        Metric::Manhattan => manhattan(a, b),
        Metric::Cosine => cosine_distance(a, b),
    }
}

/// For each point, the distance to its `k`-th nearest neighbour (1-indexed, excluding self).
///
/// Uses `select_nth_unstable` (O(n) average) instead of a full sort, and computes
/// all points in parallel.
pub fn core_distances(points: &[Vec<f64>], metric: &Metric, k: usize) -> Vec<f64> {
    let n = points.len();
    let k_idx = k.min(n - 1).max(1) - 1;

    points
        .par_iter()
        .enumerate()
        .map(|(i, pt)| {
            let mut dists: Vec<f64> = points
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, other)| point_distance(metric, pt, other))
                .collect();
            *dists
                .select_nth_unstable_by(k_idx, |a, b| {
                    a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
                })
                .1
        })
        .collect()
}

fn euclidean(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

fn manhattan(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y).abs()).sum()
}

fn cosine_distance(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let norm_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        return 1.0;
    }
    (1.0 - dot / (norm_a * norm_b)).clamp(0.0, 2.0)
}
