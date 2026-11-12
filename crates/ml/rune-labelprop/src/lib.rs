//! Label propagation — semi-supervised node classification via iterative neighbourhood smoothing.
//!
//! Implements the algorithm from Zhu & Ghahramani (2002): known (seed) nodes hold fixed
//! one-hot label distributions; unknown nodes start with a uniform distribution and are
//! iteratively updated by averaging their neighbours' distributions. The process repeats
//! until convergence or a maximum iteration count is reached.
//!
//! This is the canonical approach for propagating sparse labels across a graph — useful
//! wherever a small fraction of nodes are known and you want to classify the rest using
//! graph connectivity, such as community detection, citation networks, social graphs, and
//! fraud ring detection.
//!
//! # Features
//!
//! - Weighted edges — edge weights act as propagation strength
//! - Configurable convergence tolerance and iteration cap
//! - Isolated nodes with no path to any seed retain label `-1`
//! - Self-loops are ignored during propagation
//! - Pure Rust, no unsafe, no external dependencies in the library
//!
//! # Quick Start
//!
//! ```rust
//! use rune_labelprop::LabelProp;
//!
//! // Four nodes: 0 and 3 are seeds; 1 and 2 are unknown.
//! // Graph: 0 -- 1 -- 2 -- 3
//! let edges = vec![
//!     (0, 1, 1.0),
//!     (1, 2, 1.0),
//!     (2, 3, 1.0),
//! ];
//! let seed_labels = vec![0, -1, -1, 1];
//!
//! let result = LabelProp::new().propagate(4, &edges, &seed_labels);
//! assert_eq!(result.labels[0], 0);
//! assert_eq!(result.labels[3], 1);
//! assert!(result.converged);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-labelprop --edges edges.txt --labels labels.txt
//! cat edges.txt | rune-labelprop --edges - --labels labels.txt
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::vec;
use alloc::vec::Vec;

/// Builder for configuring and running label propagation.
///
/// Construct with [`LabelProp::new`], chain optional parameters, then call
/// [`LabelProp::propagate`].
///
/// # Example
///
/// ```rust
/// use rune_labelprop::LabelProp;
///
/// let lp = LabelProp::new().max_iter(200).tol(1e-6);
/// ```
pub struct LabelProp {
    max_iter: usize,
    tol: f64,
}

impl Default for LabelProp {
    fn default() -> Self {
        Self::new()
    }
}

impl LabelProp {
    /// Creates a new `LabelProp` with default settings: `max_iter = 100`, `tol = 1e-4`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_labelprop::LabelProp;
    ///
    /// let lp = LabelProp::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_iter: 100,
            tol: 1e-4,
        }
    }

    /// Sets the maximum number of propagation iterations.
    ///
    /// The algorithm stops early if convergence is detected before reaching this
    /// limit. Increase this value for large, sparsely connected graphs where labels
    /// need many hops to reach distant nodes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_labelprop::LabelProp;
    ///
    /// let lp = LabelProp::new().max_iter(500);
    /// ```
    #[must_use]
    pub const fn max_iter(mut self, n: usize) -> Self {
        self.max_iter = n;
        self
    }

    /// Sets the convergence tolerance.
    ///
    /// Iteration stops when the maximum change in any node's label distribution
    /// across a single iteration falls below this threshold. Smaller values produce
    /// more precise results at the cost of additional iterations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_labelprop::LabelProp;
    ///
    /// let lp = LabelProp::new().tol(1e-6);
    /// ```
    #[must_use]
    pub const fn tol(mut self, t: f64) -> Self {
        self.tol = t;
        self
    }

    /// Runs label propagation and returns the final classification for every node.
    ///
    /// Seed nodes hold their labels fixed throughout iteration. Unknown nodes
    /// (`seed_labels[i] == -1`) receive the weighted average of their neighbours'
    /// current distributions each iteration. Nodes with no path to any seed node
    /// end up with label `-1`.
    ///
    /// # Arguments
    ///
    /// - `n_nodes` — total number of nodes, addressed as `0..n_nodes`.
    /// - `edges` — undirected weighted edges as `(u, v, weight)`; both `u` and `v`
    ///   must be less than `n_nodes`. Weights should be positive. Self-loops are
    ///   ignored.
    /// - `seed_labels` — length must equal `n_nodes`; `≥ 0` identifies the known
    ///   class, `-1` marks an unknown node.
    ///
    /// # Panics
    ///
    /// Panics if `seed_labels.len() != n_nodes` or if any edge endpoint is
    /// `>= n_nodes`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_labelprop::LabelProp;
    ///
    /// // Line graph: seed 0 (class 0) — unknown — unknown — seed 3 (class 1)
    /// let edges = vec![(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0)];
    /// let seeds  = vec![0, -1, -1, 1];
    ///
    /// let result = LabelProp::new().propagate(4, &edges, &seeds);
    /// assert_eq!(result.labels[0], 0);
    /// assert_eq!(result.labels[3], 1);
    /// assert!(result.converged);
    /// ```
    #[must_use]
    pub fn propagate(
        &self,
        n_nodes: usize,
        edges: &[(usize, usize, f64)],
        seed_labels: &[i32],
    ) -> PropResult {
        assert_eq!(
            seed_labels.len(),
            n_nodes,
            "seed_labels length must equal n_nodes"
        );
        for &(u, v, _) in edges {
            assert!(u < n_nodes, "edge endpoint {u} out of range");
            assert!(v < n_nodes, "edge endpoint {v} out of range");
        }

        if n_nodes == 0 {
            return PropResult {
                labels: Vec::new(),
                iterations: 0,
                converged: true,
            };
        }

        let n_classes = infer_class_count(seed_labels);

        if n_classes == 0 {
            return PropResult {
                labels: vec![-1; n_nodes],
                iterations: 0,
                converged: true,
            };
        }

        let adjacency = build_adjacency(n_nodes, edges);
        let mut distributions = initial_distributions(n_nodes, n_classes, seed_labels);
        let is_seed: Vec<bool> = seed_labels.iter().map(|&l| l >= 0).collect();

        let mut iterations = 0;
        let mut converged = false;

        for _ in 0..self.max_iter {
            iterations += 1;
            let max_change =
                propagate_once(n_nodes, n_classes, &adjacency, &mut distributions, &is_seed);
            if max_change < self.tol {
                converged = true;
                break;
            }
        }

        let labels = distributions
            .chunks_exact(n_classes)
            .zip(&is_seed)
            .zip(seed_labels)
            .map(|((dist, &seed), &orig)| {
                if seed {
                    return orig;
                }
                argmax_label(dist)
            })
            .collect();

        PropResult {
            labels,
            iterations,
            converged,
        }
    }
}

/// Result of a completed label propagation run.
pub struct PropResult {
    /// Predicted class label for each node.
    ///
    /// Seed nodes retain their original label. Unknown nodes reachable from at least
    /// one seed carry the class with the highest propagated probability. Nodes with no
    /// path to any seed retain `-1`.
    pub labels: Vec<i32>,

    /// Number of iterations performed before convergence or the iteration cap.
    pub iterations: usize,

    /// Whether the algorithm converged before reaching `max_iter`.
    ///
    /// If `false`, the labels are still usable but may not have fully settled.
    pub converged: bool,
}

/// Infers the number of classes from the maximum seed label present.
#[allow(
    clippy::cast_sign_loss,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
fn infer_class_count(seed_labels: &[i32]) -> usize {
    seed_labels
        .iter()
        .filter(|&&l| l >= 0)
        .map(|&l| l as usize)
        .max()
        .map_or(0, |m| m + 1)
}

/// Builds a compact adjacency list: `adjacency[v]` is a list of `(neighbour, weight)`.
///
/// Self-loops are silently dropped. Each undirected edge is stored in both directions.
fn build_adjacency(n_nodes: usize, edges: &[(usize, usize, f64)]) -> Vec<Vec<(usize, f64)>> {
    let mut adjacency: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n_nodes];
    for &(u, v, weight) in edges {
        if u == v {
            continue;
        }
        adjacency[u].push((v, weight));
        adjacency[v].push((u, weight));
    }
    adjacency
}

/// Initialises label distributions for all nodes.
///
/// Seed nodes get a one-hot distribution. Unknown nodes start at all-zeros so that
/// nodes unreachable from every seed remain zero throughout iteration and are
/// classified as `-1`. The result is a flat array of length `n_nodes * n_classes`,
/// with node `v`'s distribution at `[v * n_classes .. (v+1) * n_classes]`.
#[allow(
    clippy::cast_sign_loss,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
fn initial_distributions(n_nodes: usize, n_classes: usize, seed_labels: &[i32]) -> Vec<f64> {
    let mut distributions = vec![0.0_f64; n_nodes * n_classes];
    for (node, &label) in seed_labels.iter().enumerate() {
        if label >= 0 {
            distributions[node * n_classes + label as usize] = 1.0;
        }
    }
    distributions
}

/// Performs one round of label propagation and returns the maximum distribution change.
///
/// Each unknown node is replaced by the weighted average of its neighbours' current
/// distributions. Seed nodes are re-clamped to their one-hot distributions after the
/// update step so they cannot drift.
fn propagate_once(
    n_nodes: usize,
    n_classes: usize,
    adjacency: &[Vec<(usize, f64)>],
    distributions: &mut [f64],
    is_seed: &[bool],
) -> f64 {
    let previous = distributions.to_owned();
    let mut max_change: f64 = 0.0;

    for node in 0..n_nodes {
        if is_seed[node] {
            continue;
        }

        let neighbours = &adjacency[node];
        if neighbours.is_empty() {
            continue;
        }

        let total_weight: f64 = neighbours.iter().map(|&(_, w)| w).sum();
        if total_weight == 0.0 {
            continue;
        }

        let node_offset = node * n_classes;
        for class in 0..n_classes {
            let new_value: f64 = neighbours
                .iter()
                .map(|&(neighbour, weight)| weight * previous[neighbour * n_classes + class])
                .sum::<f64>()
                / total_weight;

            let change = (new_value - previous[node_offset + class]).abs();
            if change > max_change {
                max_change = change;
            }
            distributions[node_offset + class] = new_value;
        }
    }

    max_change
}

/// Returns the class index with the highest probability, or `-1` if all are zero.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
fn argmax_label(distribution: &[f64]) -> i32 {
    let total: f64 = distribution.iter().sum();
    if total == 0.0 {
        return -1;
    }
    distribution
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal))
        .map_or(-1, |(i, _)| i as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_blobs_connected_by_bridge() {
        // Blob A: nodes 0,1,2 — seed label 0 at node 0
        // Blob B: nodes 4,5,6 — seed label 1 at node 6
        // Bridge: node 3 connects blob A to blob B
        //
        // 0 -- 1 -- 2 -- 3 -- 4 -- 5 -- 6
        let edges: Vec<(usize, usize, f64)> = vec![
            (0, 1, 1.0),
            (1, 2, 1.0),
            (2, 3, 1.0),
            (3, 4, 1.0),
            (4, 5, 1.0),
            (5, 6, 1.0),
        ];
        let seeds = vec![0, -1, -1, -1, -1, -1, 1];
        let result = LabelProp::new().max_iter(500).propagate(7, &edges, &seeds);

        assert_eq!(result.labels[0], 0, "seed node 0 must stay class 0");
        assert_eq!(result.labels[6], 1, "seed node 6 must stay class 1");
        assert_eq!(result.labels[1], 0, "node 1 near seed 0 should be class 0");
        assert_eq!(result.labels[5], 1, "node 5 near seed 1 should be class 1");
    }

    #[test]
    fn isolated_node_stays_unknown() {
        // Node 2 is completely isolated — no edges touch it.
        let edges: Vec<(usize, usize, f64)> = vec![(0, 1, 1.0)];
        let seeds = vec![0, -1, -1];
        let result = LabelProp::new().propagate(3, &edges, &seeds);

        assert_eq!(result.labels[0], 0, "seed node must keep its label");
        assert_eq!(result.labels[2], -1, "isolated unknown node must remain -1");
    }

    #[test]
    fn fully_labelled_graph_converges_immediately() {
        // All nodes are seeds — no propagation work is needed.
        let edges: Vec<(usize, usize, f64)> = vec![(0, 1, 1.0), (1, 2, 1.0)];
        let seeds = vec![0, 1, 0];
        let result = LabelProp::new().propagate(3, &edges, &seeds);

        assert_eq!(result.labels, vec![0, 1, 0]);
        assert!(result.converged);
        assert_eq!(
            result.iterations, 1,
            "fully labelled graph must converge in 1 iteration"
        );
    }

    #[test]
    fn single_seed_propagates_to_connected_component_only() {
        // Two components: 0-1-2 (seed 0 at node 0) and 3-4 (no seeds).
        let edges: Vec<(usize, usize, f64)> = vec![(0, 1, 1.0), (1, 2, 1.0), (3, 4, 1.0)];
        let seeds = vec![0, -1, -1, -1, -1];
        let result = LabelProp::new().propagate(5, &edges, &seeds);

        assert_eq!(result.labels[0], 0);
        assert_eq!(
            result.labels[1], 0,
            "connected to seed — should receive label 0"
        );
        assert_eq!(
            result.labels[2], 0,
            "connected to seed — should receive label 0"
        );
        assert_eq!(result.labels[3], -1, "disconnected component must stay -1");
        assert_eq!(result.labels[4], -1, "disconnected component must stay -1");
    }

    #[test]
    fn no_seeds_returns_all_unknown() {
        let edges: Vec<(usize, usize, f64)> = vec![(0, 1, 1.0)];
        let seeds = vec![-1, -1];
        let result = LabelProp::new().propagate(2, &edges, &seeds);
        assert!(result.labels.iter().all(|&l| l == -1));
    }

    #[test]
    fn self_loops_are_ignored() {
        // Adding self-loops must not change the outcome.
        let edges_clean: Vec<(usize, usize, f64)> = vec![(0, 1, 1.0), (1, 2, 1.0)];
        let edges_loopy: Vec<(usize, usize, f64)> = vec![
            (0, 0, 5.0),
            (0, 1, 1.0),
            (1, 1, 5.0),
            (1, 2, 1.0),
            (2, 2, 5.0),
        ];
        let seeds = vec![0, -1, 1];

        let r_clean = LabelProp::new().propagate(3, &edges_clean, &seeds);
        let r_loopy = LabelProp::new().propagate(3, &edges_loopy, &seeds);

        assert_eq!(r_clean.labels, r_loopy.labels);
    }

    #[test]
    fn weighted_edges_bias_propagation() {
        // Node 1 is unknown, connected to seed 0 (class 0) with weight 10.0
        // and to seed 2 (class 1) with weight 1.0.
        // It should end up as class 0 due to stronger weight.
        let edges: Vec<(usize, usize, f64)> = vec![(0, 1, 10.0), (1, 2, 1.0)];
        let seeds = vec![0, -1, 1];
        let result = LabelProp::new().propagate(3, &edges, &seeds);
        assert_eq!(
            result.labels[1], 0,
            "heavy weight toward class 0 must dominate"
        );
    }

    #[test]
    fn empty_graph_returns_empty() {
        let result = LabelProp::new().propagate(0, &[], &[]);
        assert_eq!(result.labels, [] as [i32; 0]);
        assert!(result.converged);
    }
}
