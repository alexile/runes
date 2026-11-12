use rayon::prelude::*;

use crate::distance::{Metric, point_distance};

pub struct MstEdge {
    pub u: usize,
    pub v: usize,
    pub weight: f64,
}

/// Builds a minimum spanning tree on the mutual reachability graph using Prim's algorithm.
///
/// Mutual reachability distance: `max(core_dist[a], core_dist[b], dist(a, b))`.
/// Distances are computed on-the-fly — no O(n²) matrix is stored.
/// The per-node update step runs in parallel across all out-of-tree nodes.
pub fn build(points: &[Vec<f64>], metric: &Metric, core_dists: &[f64]) -> Vec<MstEdge> {
    let n = points.len();
    let mut in_tree = vec![false; n];
    let mut nearest_weight = vec![f64::INFINITY; n];
    let mut nearest_node = vec![0usize; n];
    let mut edges = Vec::with_capacity(n - 1);

    in_tree[0] = true;

    // Initialise distances from node 0 (parallel; index 0 stays at INFINITY).
    nearest_weight[1..]
        .par_iter_mut()
        .enumerate()
        .for_each(|(idx, w)| {
            *w = mrd(points, metric, core_dists, 0, idx + 1);
        });

    for _ in 0..n - 1 {
        // Find the minimum-weight out-of-tree node (sequential — O(1) per comparison).
        let Some((next, w)) = nearest_weight
            .iter()
            .enumerate()
            .filter(|&(i, _)| !in_tree[i])
            .map(|(i, &w)| (i, w))
            .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        else {
            // Every node is already in the tree.
            break;
        };

        edges.push(MstEdge {
            u: nearest_node[next],
            v: next,
            weight: w,
        });
        in_tree[next] = true;

        // Update nearest-weight and nearest-node for all out-of-tree nodes (parallel).
        // Each index is written by exactly one thread; in_tree is read-only here.
        let in_tree_ref = &in_tree;
        nearest_weight
            .par_iter_mut()
            .zip(nearest_node.par_iter_mut())
            .enumerate()
            .for_each(|(j, (w, node))| {
                if !in_tree_ref[j] {
                    let candidate = mrd(points, metric, core_dists, next, j);
                    if candidate < *w {
                        *w = candidate;
                        *node = next;
                    }
                }
            });
    }

    edges
}

#[inline]
fn mrd(points: &[Vec<f64>], metric: &Metric, core_dists: &[f64], a: usize, b: usize) -> f64 {
    point_distance(metric, &points[a], &points[b])
        .max(core_dists[a])
        .max(core_dists[b])
}
