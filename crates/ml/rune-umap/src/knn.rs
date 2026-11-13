//! Standalone k-nearest-neighbour graphs: exact search and NN-Descent.
//!
//! This is the neighbour search UMAP itself uses, exposed so other code can
//! build a kNN graph without fitting an embedding (density clustering,
//! Barnes-Hut neighbour lists for t-SNE, graph-based label propagation, …).
//!
//! | Function | What it does |
//! |----------|--------------|
//! | [`knn_graph`] | Exact search up to [`EXACT_MAX_POINTS`] points, NN-Descent above |
//! | [`knn_graph_with`] | Same, with an explicit [`KnnMethod`] and iteration count |
//! | [`exact`] | Brute-force search, O(n²·d) |
//! | [`nn_descent`] | Approximate NN-Descent (Dong et al., 2011), roughly O(n·k²·iters) |
//! | [`recall`] | Fraction of the exact neighbours an approximate graph found |
//!
//! Every function returns one row per point: its `k` neighbours as
//! `(index, distance)` pairs, nearest first, ties broken by the lower index,
//! never including the point itself. Work is spread over rayon's thread pool
//! and the output does not depend on the number of threads.
//!
//! # Example
//!
//! ```rust
//! use rune_umap::Metric;
//! use rune_umap::knn::{exact, knn_graph, recall};
//!
//! let points: Vec<Vec<f64>> = (0..40)
//!     .map(|i| vec![f64::from(i % 8), f64::from(i / 8)])
//!     .collect();
//! let graph = knn_graph(&points, 4, Metric::Euclidean, 7)?;
//! assert_eq!(graph.len(), 40);
//! assert!(graph.iter().all(|row| row.len() == 4));
//! assert_eq!(graph[0][0].1, 1.0); // nearest neighbour of (0, 0) is one step away
//!
//! // Small inputs are searched exactly, so recall against `exact` is 1.
//! let truth = exact(&points, 4, Metric::Euclidean)?;
//! assert_eq!(recall(&graph, &truth), 1.0);
//! # Ok::<(), rune_umap::UmapError>(())
//! ```

use crate::distance::Metric;
use crate::error::UmapError;
use crate::rng::Rng;
use crate::{KnnMethod, nnd, quality};

/// Neighbour lists, one per point: `(index, distance)` pairs, nearest first.
pub type KnnGraph = Vec<Vec<(usize, f64)>>;

/// Inputs up to this many points are searched exactly under [`KnnMethod::Auto`].
pub const EXACT_MAX_POINTS: usize = 4096;

/// Default number of NN-Descent refinement rounds used by [`knn_graph`].
///
/// NN-Descent usually converges well before this and stops early.
pub const DEFAULT_NND_ITERS: usize = 10;

/// k-nearest-neighbour graph of `data`, choosing the method automatically.
///
/// Uses exact search for at most [`EXACT_MAX_POINTS`] points and NN-Descent
/// with [`DEFAULT_NND_ITERS`] rounds above that. `seed` only matters for
/// NN-Descent's random starting graph; the same seed always gives the same
/// graph.
///
/// # Errors
///
/// Returns [`UmapError`] when `data` is empty, has no features, is ragged or
/// holds a non-finite value, when `k` is `0`, or when `k ≥ data.len()`.
///
/// # Example
///
/// ```rust
/// use rune_umap::{knn::knn_graph, Metric};
///
/// let pts = vec![vec![0.0], vec![1.0], vec![5.0], vec![6.0]];
/// let g = knn_graph(&pts, 1, Metric::Euclidean, 0)?;
/// assert_eq!(g[0], vec![(1, 1.0)]);
/// assert_eq!(g[2], vec![(3, 1.0)]);
/// # Ok::<(), rune_umap::UmapError>(())
/// ```
pub fn knn_graph(
    data: &[Vec<f64>],
    k: usize,
    metric: Metric,
    seed: u64,
) -> Result<KnnGraph, UmapError> {
    knn_graph_with(data, k, metric, KnnMethod::Auto, DEFAULT_NND_ITERS, seed)
}

/// k-nearest-neighbour graph of `data` with an explicit search method.
///
/// `n_iters` caps the NN-Descent refinement rounds (zero is treated as one)
/// and is ignored by exact search. With [`KnnMethod::NnDescent`] and the
/// same `n_iters` and `seed`, this returns exactly the graph that
/// [`Umap`](crate::Umap) builds with `knn_method(KnnMethod::NnDescent)` and
/// `random_seed(seed)`.
///
/// # Errors
///
/// Same as [`knn_graph`].
///
/// # Example
///
/// ```rust
/// use rune_umap::{knn::knn_graph_with, KnnMethod, Metric};
///
/// let pts: Vec<Vec<f64>> = (0..30).map(|i| vec![f64::from(i)]).collect();
/// let g = knn_graph_with(&pts, 2, Metric::Manhattan, KnnMethod::NnDescent, 20, 3)?;
/// assert_eq!(g[10].len(), 2);
/// # Ok::<(), rune_umap::UmapError>(())
/// ```
pub fn knn_graph_with(
    data: &[Vec<f64>],
    k: usize,
    metric: Metric,
    method: KnnMethod,
    n_iters: usize,
    seed: u64,
) -> Result<KnnGraph, UmapError> {
    validate(data, k)?;
    let use_exact = match method {
        KnnMethod::Exact => true,
        KnnMethod::NnDescent => false,
        KnnMethod::Auto => data.len() <= EXACT_MAX_POINTS,
    };
    Ok(if use_exact {
        nnd::exact(data, metric, k)
    } else {
        nnd::build(data, metric, k, n_iters.max(1), &mut Rng::new(seed))
    })
}

/// Exact k-nearest neighbours by brute force: O(n²·d) time, parallel over
/// points.
///
/// # Errors
///
/// Same as [`knn_graph`].
///
/// # Example
///
/// ```rust
/// use rune_umap::{knn::exact, Metric};
///
/// let pts = vec![vec![0.0, 0.0], vec![0.0, 2.0], vec![3.0, 0.0]];
/// let g = exact(&pts, 2, Metric::Euclidean)?;
/// assert_eq!(g[0], vec![(1, 2.0), (2, 3.0)]);
/// # Ok::<(), rune_umap::UmapError>(())
/// ```
pub fn exact(data: &[Vec<f64>], k: usize, metric: Metric) -> Result<KnnGraph, UmapError> {
    validate(data, k)?;
    Ok(nnd::exact(data, metric, k))
}

/// Approximate k-nearest neighbours via NN-Descent (Dong et al., 2011).
///
/// Starts from a random graph drawn from `seed` and repeatedly checks
/// neighbours-of-neighbours (forward and reverse edges) until fewer than
/// 0.1 % of the entries change in a round, or `n_iters` rounds have run.
/// Recall against [`exact`] is typically above 95 % on low-dimensional data
/// with the default 10 rounds. For a few thousand points or fewer [`exact`]
/// is usually just as fast; [`knn_graph`] picks between them for you.
///
/// # Errors
///
/// Same as [`knn_graph`].
///
/// # Example
///
/// ```rust
/// use rune_umap::{knn::{exact, nn_descent, recall}, Metric};
///
/// let pts: Vec<Vec<f64>> = (0..200)
///     .map(|i| vec![f64::from(i % 20), f64::from(i / 20)])
///     .collect();
/// let approx = nn_descent(&pts, 5, Metric::Euclidean, 20, 1)?;
/// let truth = exact(&pts, 5, Metric::Euclidean)?;
/// assert!(recall(&approx, &truth) > 0.9);
/// # Ok::<(), rune_umap::UmapError>(())
/// ```
pub fn nn_descent(
    data: &[Vec<f64>],
    k: usize,
    metric: Metric,
    n_iters: usize,
    seed: u64,
) -> Result<KnnGraph, UmapError> {
    validate(data, k)?;
    Ok(nnd::build(
        data,
        metric,
        k,
        n_iters.max(1),
        &mut Rng::new(seed),
    ))
}

/// Fraction of the true neighbours that `approx` found, in `[0, 1]`.
///
/// For each point, an approximate neighbour counts as a hit when its
/// distance is no larger than the farthest exact neighbour's, so tied
/// neighbours at the boundary are not counted as misses. Rows are paired up
/// in order; extra rows in either graph are ignored. Returns `1.0` when
/// `exact` has no neighbours at all.
///
/// # Example
///
/// ```rust
/// use rune_umap::knn::recall;
///
/// let truth = vec![vec![(1, 1.0), (2, 2.0)], vec![(0, 1.0), (2, 1.0)]];
/// let approx = vec![vec![(1, 1.0), (3, 5.0)], vec![(2, 1.0), (0, 1.0)]];
/// assert_eq!(recall(&approx, &truth), 0.75);
/// ```
#[must_use]
#[allow(
    clippy::cast_precision_loss,
    reason = "neighbour counts stay far below 2^52, so the f64 conversion is exact"
)]
pub fn recall(approx: &[Vec<(usize, f64)>], exact: &[Vec<(usize, f64)>]) -> f64 {
    let mut hits = 0usize;
    let mut total = 0usize;
    for (a, e) in approx.iter().zip(exact) {
        let Some(&(_, worst)) = e.last() else {
            continue;
        };
        let tol = worst.abs().mul_add(1e-12, 1e-12);
        hits += a
            .iter()
            .take(e.len())
            .filter(|&&(_, d)| d <= worst + tol)
            .count();
        total += e.len();
    }
    if total == 0 {
        1.0
    } else {
        hits as f64 / total as f64
    }
}

fn validate(data: &[Vec<f64>], k: usize) -> Result<(), UmapError> {
    quality::validate_matrix(data)?;
    if k == 0 {
        return Err(UmapError::InvalidParameter {
            name: "k",
            value: 0.0,
            reason: "must be at least 1",
        });
    }
    if k >= data.len() {
        return Err(UmapError::TooFewSamples {
            n_neighbors: k,
            n_samples: data.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::cast_precision_loss, reason = "small test indices")]
    fn cloud(n: usize) -> Vec<Vec<f64>> {
        (0..n)
            .map(|i| {
                let f = i as f64;
                vec![
                    (f * 0.37).sin() * 4.0,
                    (f * 0.11).cos() * 3.0,
                    (f * 0.73).sin(),
                ]
            })
            .collect()
    }

    #[test]
    fn nn_descent_recall_vs_exact() {
        let pts = cloud(500);
        for metric in [Metric::Euclidean, Metric::Cosine] {
            let truth = exact(&pts, 8, metric).unwrap();
            let approx = nn_descent(&pts, 8, metric, DEFAULT_NND_ITERS, 5).unwrap();
            let r = recall(&approx, &truth);
            assert!(r > 0.95, "{metric}: recall {r:.3}");
        }
    }

    #[test]
    fn auto_is_exact_for_small_inputs() {
        let pts = cloud(120);
        let auto = knn_graph(&pts, 6, Metric::Manhattan, 9).unwrap();
        assert_eq!(auto, exact(&pts, 6, Metric::Manhattan).unwrap());
    }

    #[test]
    fn deterministic_for_a_seed() {
        let pts = cloud(150);
        let a = nn_descent(&pts, 5, Metric::Euclidean, 5, 11).unwrap();
        let b = nn_descent(&pts, 5, Metric::Euclidean, 5, 11).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rows_are_sorted_and_exclude_self() {
        let pts = cloud(80);
        let g = nn_descent(&pts, 7, Metric::Correlation, 10, 2).unwrap();
        for (i, row) in g.iter().enumerate() {
            assert_eq!(row.len(), 7);
            assert!(row.iter().all(|&(j, _)| j != i && j < pts.len()));
            assert!(row.windows(2).all(|w| w[0].1 <= w[1].1));
        }
    }

    #[test]
    fn rejects_bad_input() {
        let pts = cloud(5);
        assert!(matches!(
            knn_graph(&pts, 0, Metric::Euclidean, 0),
            Err(UmapError::InvalidParameter { name: "k", .. })
        ));
        assert!(matches!(
            exact(&pts, 5, Metric::Euclidean),
            Err(UmapError::TooFewSamples { .. })
        ));
        assert!(matches!(
            nn_descent(&[], 1, Metric::Euclidean, 1, 0),
            Err(UmapError::Empty)
        ));
        let nan = vec![vec![0.0], vec![f64::NAN]];
        assert!(matches!(
            exact(&nan, 1, Metric::Euclidean),
            Err(UmapError::NonFinite { .. })
        ));
    }

    #[test]
    fn recall_edge_cases() {
        assert_eq!(recall(&[], &[]), 1.0);
        let truth = vec![vec![(1, 1.0)], vec![(0, 1.0)]];
        assert_eq!(recall(&truth, &truth), 1.0);
        assert_eq!(recall(&[vec![(1, 9.0)], vec![]], &truth), 0.0);
    }
}
