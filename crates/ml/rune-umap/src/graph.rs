use std::collections::HashMap;

use rayon::prelude::*;

use crate::distance::Metric;

/// Builds the symmetrized fuzzy simplicial set from a k-NN graph.
///
/// Returns a list of undirected edges `(i, j, weight)` with `i < j`,
/// where weight is the fuzzy union of the two directed memberships.
pub fn build(knn: &[Vec<(usize, f64)>], k: usize, n: usize) -> Vec<(usize, usize, f64)> {
    let (sigmas, rhos) = smooth_knn_distances(knn, k);
    let directed = directed_weights(knn, &sigmas, &rhos, n);
    symmetrize(directed)
}

/// Computes the per-point bandwidth `σᵢ` (and nearest-neighbour distance `ρᵢ`)
/// via binary search so that the fuzzy membership sums to `log₂(k)`.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn smooth_knn_distances(knn: &[Vec<(usize, f64)>], k: usize) -> (Vec<f64>, Vec<f64>) {
    let target = (k as f64).log2();
    knn.iter()
        .map(|neighbors| {
            let rho = local_rho(neighbors);
            let dists: Vec<f64> = neighbors.iter().map(|(_, d)| *d).collect();
            let sigma = find_sigma(&dists, rho, target);
            (sigma, rho)
        })
        .unzip()
}

/// Distance to the nearest neighbour at a strictly positive distance
/// (`local_connectivity = 1` in the reference implementation), so that exact
/// duplicates do not collapse the bandwidth of every other edge.
fn local_rho(neighbors: &[(usize, f64)]) -> f64 {
    neighbors
        .iter()
        .map(|&(_, d)| d)
        .find(|&d| d > 0.0)
        .unwrap_or(0.0)
}

/// Binary-searches `σ` such that `Σ exp(-max(d−ρ, 0) / σ) ≈ target`.
pub fn find_sigma(dists: &[f64], rho: f64, target: f64) -> f64 {
    let mut lo = 0.0f64;
    let mut hi = f64::INFINITY;
    let mut sigma = 1.0f64;

    for _ in 0..64 {
        let psum: f64 = dists
            .iter()
            .map(|&d| {
                let gap = d - rho;
                if gap <= 0.0 {
                    1.0
                } else {
                    (-gap / sigma).exp()
                }
            })
            .sum();

        if (psum - target).abs() < 1e-5 {
            break;
        }

        if psum < target {
            lo = sigma;
            sigma = if hi == f64::INFINITY {
                sigma * 2.0
            } else {
                f64::midpoint(lo, hi)
            };
        } else {
            hi = sigma;
            sigma = f64::midpoint(lo, hi);
        }
    }

    sigma.max(1e-8)
}

/// Computes the directed membership weight for each k-NN edge:
/// `w(i→j) = exp(-max(d(i,j) − ρᵢ, 0) / σᵢ)`.
fn directed_weights(
    knn: &[Vec<(usize, f64)>],
    sigmas: &[f64],
    rhos: &[f64],
    n: usize,
) -> Vec<(usize, usize, f64)> {
    let mut edges = Vec::with_capacity(n * knn.first().map_or(0, Vec::len));
    for i in 0..n {
        for &(j, d) in &knn[i] {
            let gap = (d - rhos[i]).max(0.0);
            let w = if gap == 0.0 {
                1.0
            } else {
                (-gap / sigmas[i]).exp()
            };
            edges.push((i, j, w));
        }
    }
    edges
}

/// k nearest neighbours from `new_points` into `train_points`.
///
/// Returns `Vec<Vec<(train_index, distance)>>` of length `n_new`, sorted ascending.
pub fn knn_to_train(
    new_points: &[Vec<f64>],
    train_points: &[Vec<f64>],
    k: usize,
    metric: Metric,
) -> Vec<Vec<(usize, f64)>> {
    let k = k.min(train_points.len());
    new_points
        .par_iter()
        .map(|new_pt| crate::nnd::knn_of(new_pt, train_points, None, metric, k))
        .collect()
}

/// Builds directed weighted edges from new points into training points,
/// using per-new-point σ computed against training neighbours.
///
/// Returns `(i_new, j_train, weight)` edges for use in `optimize_transform`.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
pub fn transform_edges(knn: &[Vec<(usize, f64)>], k: usize) -> Vec<(usize, usize, f64)> {
    let target = (k as f64).log2();
    let mut edges = Vec::new();

    for (i, neighbors) in knn.iter().enumerate() {
        if neighbors.is_empty() {
            continue;
        }
        let rho = local_rho(neighbors);
        let dists: Vec<f64> = neighbors.iter().map(|(_, d)| *d).collect();
        let sigma = find_sigma(&dists, rho, target);

        for &(j, d) in neighbors {
            let gap = (d - rho).max(0.0);
            let w = if gap == 0.0 {
                1.0
            } else {
                (-gap / sigma).exp()
            };
            if w > 0.0 {
                edges.push((i, j, w));
            }
        }
    }

    edges
}

/// Symmetrizes the directed graph via fuzzy union:
/// `sym(i,j) = w(i→j) + w(j→i) − w(i→j)·w(j→i)`.
fn symmetrize(directed: Vec<(usize, usize, f64)>) -> Vec<(usize, usize, f64)> {
    // Canonical key: (min_idx, max_idx) → (w_min→max, w_max→min)
    let mut weights: HashMap<(usize, usize), (f64, f64)> = HashMap::new();

    for (i, j, w) in directed {
        let (key, is_forward) = if i < j {
            ((i, j), true)
        } else {
            ((j, i), false)
        };
        let entry = weights.entry(key).or_insert((0.0, 0.0));
        if is_forward {
            entry.0 = w;
        } else {
            entry.1 = w;
        }
    }

    weights
        .into_iter()
        .filter_map(|((i, j), (w_ij, w_ji))| {
            let sym = f64::mul_add(w_ij, -w_ji, w_ij + w_ji);
            if sym > 0.0 { Some((i, j, sym)) } else { None }
        })
        .collect()
}
