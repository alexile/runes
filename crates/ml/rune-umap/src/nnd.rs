use std::cmp::Ordering;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

use rayon::prelude::*;

use crate::distance::{Metric, point_distance};
use crate::rng::Rng;

/// Convergence threshold: stop when fewer than `delta × n × k` updates occur per iteration.
const DELTA: f64 = 0.001;

/// Orders `(index, distance)` pairs by distance, breaking ties by index so the
/// result never depends on sort stability or thread scheduling.
pub fn by_dist(a: &(usize, f64), b: &(usize, f64)) -> Ordering {
    a.1.total_cmp(&b.1).then(a.0.cmp(&b.0))
}

/// Exact k-nearest neighbours by brute force: O(n² · d), parallel over points.
///
/// Returns `Vec<Vec<(index, distance)>>` sorted ascending by distance (ties by index).
pub fn exact(points: &[Vec<f64>], metric: Metric, k: usize) -> Vec<Vec<(usize, f64)>> {
    let n = points.len();
    let k = k.min(n.saturating_sub(1));
    (0..n)
        .into_par_iter()
        .map(|i| knn_of(&points[i], points, Some(i), metric, k))
        .collect()
}

/// The `k` nearest entries of `pool` to `query` (excluding index `skip`), sorted.
pub fn knn_of(
    query: &[f64],
    pool: &[Vec<f64>],
    skip: Option<usize>,
    metric: Metric,
    k: usize,
) -> Vec<(usize, f64)> {
    let mut dists: Vec<(usize, f64)> = pool
        .iter()
        .enumerate()
        .filter(|&(j, _)| Some(j) != skip)
        .map(|(j, p)| (j, point_distance(metric, query, p)))
        .collect();
    if k == 0 {
        return Vec::new();
    }
    if dists.len() > k {
        dists.select_nth_unstable_by(k - 1, by_dist);
        dists.truncate(k);
    }
    dists.sort_unstable_by(by_dist);
    dists
}

/// Approximate k-nearest-neighbours via NN-Descent (Dong et al., 2011).
///
/// Starts from a random k-NN graph and iteratively improves it by exploring
/// neighbours-of-neighbours in both directions (forward and reverse edges).
/// Complexity is roughly O(n · k² · iters) — far cheaper than the O(n²) exact
/// approach for large n.
///
/// Returns `Vec<Vec<(index, distance)>>` sorted ascending by distance.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
pub fn build(
    points: &[Vec<f64>],
    metric: Metric,
    k: usize,
    n_iters: usize,
    rng: &mut Rng,
) -> Vec<Vec<(usize, f64)>> {
    let n = points.len();
    let k = k.min(n.saturating_sub(1));
    if k == 0 {
        return vec![Vec::new(); n];
    }

    // Initialise with random neighbours (sequential — preserves determinism with seed).
    let mut neighbors: Vec<Vec<(usize, f64)>> = (0..n)
        .map(|i| random_neighbors(i, n, k, points, metric, rng))
        .collect();

    let threshold = ((DELTA * (n * k) as f64) as usize).max(1);

    for _ in 0..n_iters {
        // Reverse neighbour lists, capped at k entries each (deterministic order).
        let mut reverse: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, nbrs) in neighbors.iter().enumerate() {
            for &(j, _) in nbrs {
                if reverse[j].len() < k {
                    reverse[j].push(i);
                }
            }
        }

        // Phase 1 — read-only snapshot: collect candidate neighbours-of-neighbours in parallel.
        let snap = &neighbors;
        let rev = &reverse;
        let candidates: Vec<Vec<(usize, f64)>> = (0..n)
            .into_par_iter()
            .map(|i| explore_candidates(i, snap, rev, points, metric))
            .collect();

        // Phase 2 — independent per-point writes: update each neighbour list in parallel.
        let update_count = AtomicUsize::new(0);
        neighbors
            .par_iter_mut()
            .zip(candidates.par_iter())
            .for_each(|(nbrs, cands)| {
                let mut local = 0usize;
                for &(c, d) in cands {
                    if try_insert(nbrs, c, d, k) {
                        local += 1;
                    }
                }
                if local > 0 {
                    update_count.fetch_add(local, AtomicOrdering::Relaxed);
                }
            });

        if update_count.load(AtomicOrdering::Relaxed) <= threshold {
            break;
        }
    }

    neighbors
}

/// Collects candidate neighbours for point `i` from the forward and reverse
/// neighbour lists of `i`'s forward and reverse neighbours, returning a
/// deduplicated list sorted ascending by distance.
fn explore_candidates(
    i: usize,
    neighbors: &[Vec<(usize, f64)>],
    reverse: &[Vec<usize>],
    points: &[Vec<f64>],
    metric: Metric,
) -> Vec<(usize, f64)> {
    let mut ids: Vec<usize> = Vec::new();
    let hop1 = neighbors[i]
        .iter()
        .map(|&(j, _)| j)
        .chain(reverse[i].iter().copied());
    for j in hop1 {
        ids.push(j);
        ids.extend(neighbors[j].iter().map(|&(c, _)| c));
        ids.extend(reverse[j].iter().copied());
    }
    ids.sort_unstable();
    ids.dedup();

    let mut cands: Vec<(usize, f64)> = ids
        .into_iter()
        .filter(|&c| c != i)
        .map(|c| (c, point_distance(metric, &points[i], &points[c])))
        .collect();
    cands.sort_unstable_by(by_dist);
    cands
}

/// Attempts to insert `(candidate, dist)` into the sorted neighbour list `nbrs`.
///
/// Insertion succeeds when the candidate is not already present and either the list
/// has fewer than `k` entries or `dist` is less than the current worst distance.
/// Returns `true` on success.
fn try_insert(nbrs: &mut Vec<(usize, f64)>, candidate: usize, dist: f64, k: usize) -> bool {
    if nbrs.iter().any(|&(j, _)| j == candidate) {
        return false;
    }

    let pos = nbrs.partition_point(|e| by_dist(e, &(candidate, dist)) == Ordering::Less);

    if nbrs.len() < k {
        nbrs.insert(pos, (candidate, dist));
        return true;
    }

    if pos < k {
        nbrs.pop();
        nbrs.insert(pos, (candidate, dist));
        return true;
    }

    false
}

/// Initialises point `i`'s neighbour list with `k` random distinct points.
fn random_neighbors(
    i: usize,
    n: usize,
    k: usize,
    points: &[Vec<f64>],
    metric: Metric,
    rng: &mut Rng,
) -> Vec<(usize, f64)> {
    let mut seen = std::collections::HashSet::with_capacity(k + 1);
    seen.insert(i);

    let mut nbrs: Vec<(usize, f64)> = Vec::with_capacity(k);
    while nbrs.len() < k {
        let j = rng.next_usize(n);
        if seen.insert(j) {
            nbrs.push((j, point_distance(metric, &points[i], &points[j])));
        }
    }

    nbrs.sort_unstable_by(by_dist);
    nbrs
}

#[cfg(test)]
#[allow(
    clippy::cast_precision_loss,
    reason = "small test counts, exact in f64"
)]
mod tests {
    use super::*;

    #[allow(
        clippy::cast_precision_loss,
        reason = "small test indices, exact in f64"
    )]
    fn grid(n: usize) -> Vec<Vec<f64>> {
        (0..n)
            .map(|i| vec![(i % 17) as f64, (i / 17) as f64, ((i * 7) % 5) as f64 * 0.3])
            .collect()
    }

    #[test]
    fn nn_descent_recall_is_high() {
        let pts = grid(600);
        let k = 10;
        let exact = exact(&pts, Metric::Euclidean, k);
        let approx = build(&pts, Metric::Euclidean, k, 20, &mut Rng::new(3));
        let mut hits = 0usize;
        for (e, a) in exact.iter().zip(&approx) {
            // Compare by distance to tolerate ties on the grid.
            let worst = e[k - 1].1;
            hits += a.iter().filter(|&&(_, d)| d <= worst + 1e-12).count();
        }
        let recall = hits as f64 / (pts.len() * k) as f64;
        assert!(recall > 0.95, "NN-descent recall too low: {recall:.3}");
    }

    #[test]
    fn exact_is_sorted_and_excludes_self() {
        let pts = grid(50);
        for (i, row) in exact(&pts, Metric::Manhattan, 5).iter().enumerate() {
            assert_eq!(row.len(), 5);
            assert!(row.iter().all(|&(j, _)| j != i));
            assert!(row.windows(2).all(|w| w[0].1 <= w[1].1));
        }
    }
}
