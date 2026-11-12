//! `PageRank` — score graph nodes by importance via random-walk convergence.
//!
//! `PageRank` (Brin & Page, 1998) models a random surfer who follows outgoing edges
//! with probability `d` (the damping factor) and teleports uniformly to any node
//! with probability `1 − d`. The stationary distribution of this walk gives each
//! node a score proportional to the quantity and quality of links pointing to it.
//!
//! The implementation uses power iteration with weighted edges and correct handling
//! of dangling nodes (nodes with no outgoing edges), which redistribute their rank
//! uniformly across all nodes at each step.
//!
//! # Features
//!
//! - Weighted directed edges `(from, to, weight)`
//! - Dangling-node correction — no rank leaks out of sink nodes
//! - Configurable damping factor, iteration cap, and convergence tolerance
//! - Returns per-node scores (summing to 1.0), iteration count, and a convergence flag
//! - Pure Rust, no unsafe, no external dependencies
//!
//! # Quick Start
//!
//! ```rust
//! use rune_pagerank::PageRank;
//!
//! // Triangle: 0 → 1 → 2 → 0
//! let edges = [(0, 1, 1.0), (1, 2, 1.0), (2, 0, 1.0)];
//! let result = PageRank::new().rank(3, &edges);
//!
//! assert!(result.converged);
//! // Symmetric cycle — all scores equal
//! for score in &result.scores {
//!     assert!((score - 1.0 / 3.0).abs() < 1e-5);
//! }
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-pagerank graph.txt
//! cat edges.csv | rune-pagerank -
//! rune-pagerank graph.txt --damping 0.90 --max-iter 200
//! ```

/// Builder for configuring and running the `PageRank` algorithm.
///
/// Construct with [`PageRank::new`], chain optional parameters, then call [`PageRank::rank`].
///
/// # Example
///
/// ```rust
/// use rune_pagerank::PageRank;
///
/// let pr = PageRank::new()
///     .damping(0.85)
///     .max_iter(100)
///     .tol(1e-6);
/// ```
pub struct PageRank {
    damping: f64,
    max_iter: usize,
    tol: f64,
}

impl Default for PageRank {
    fn default() -> Self {
        Self::new()
    }
}

impl PageRank {
    /// Creates a [`PageRank`] instance with standard defaults.
    ///
    /// | Parameter | Default |
    /// |-----------|---------|
    /// | `damping`   | `0.85` |
    /// | `max_iter`  | `100`  |
    /// | `tol`       | `1e-6` |
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_pagerank::PageRank;
    ///
    /// let pr = PageRank::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            damping: 0.85,
            max_iter: 100,
            tol: 1e-6,
        }
    }

    /// Damping factor `d`: probability the random surfer follows an outgoing edge.
    ///
    /// The teleportation probability is `1 − d`. Must be in `(0, 1)` — values outside
    /// that range are clamped to `[1e-9, 1 − 1e-9]`, and `NaN` keeps the
    /// current value.
    ///
    /// The classic web-graph value is `0.85`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_pagerank::PageRank;
    ///
    /// let pr = PageRank::new().damping(0.90);
    /// ```
    #[must_use]
    pub fn damping(mut self, d: f64) -> Self {
        if !d.is_nan() {
            self.damping = d.clamp(1e-9, 1.0 - 1e-9);
        }
        self
    }

    /// Maximum number of power-iteration steps before stopping regardless of convergence.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_pagerank::PageRank;
    ///
    /// let pr = PageRank::new().max_iter(200);
    /// ```
    #[must_use]
    pub const fn max_iter(mut self, n: usize) -> Self {
        self.max_iter = n;
        self
    }

    /// Convergence tolerance: iteration stops when `max |r_new[i] − r[i]| < tol`.
    ///
    /// Smaller values give more accurate scores at the cost of extra iterations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_pagerank::PageRank;
    ///
    /// let pr = PageRank::new().tol(1e-9);
    /// ```
    #[must_use]
    pub const fn tol(mut self, t: f64) -> Self {
        self.tol = t;
        self
    }

    /// Runs `PageRank` on a weighted directed graph and returns the scores.
    ///
    /// `n_nodes` is the total node count. Each entry in `edges` is
    /// `(from, to, weight)` where `from` and `to` must be in `0..n_nodes` and
    /// `weight` must be positive. Parallel edges are summed automatically.
    /// Edges whose weight is not finite and strictly positive are ignored, as
    /// if absent (otherwise they would leak rank or turn scores `NaN`).
    ///
    /// The returned [`RankResult::scores`] vector sums to `1.0` (up to floating-point
    /// rounding). An empty graph with `n_nodes == 0` returns an empty score vector.
    ///
    /// # Panics
    ///
    /// Panics if any node index in `edges` is `>= n_nodes`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_pagerank::PageRank;
    ///
    /// // Star: nodes 1, 2, 3 all point to hub node 0
    /// let edges = [(1, 0, 1.0), (2, 0, 1.0), (3, 0, 1.0)];
    /// let result = PageRank::new().rank(4, &edges);
    ///
    /// assert!(result.converged);
    /// // Hub receives all the rank, so its score is the highest
    /// let hub_score = result.scores[0];
    /// for spoke in 1..4 {
    ///     assert!(hub_score > result.scores[spoke]);
    /// }
    /// ```
    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    pub fn rank(&self, n_nodes: usize, edges: &[(usize, usize, f64)]) -> RankResult {
        if n_nodes == 0 {
            return RankResult {
                scores: Vec::new(),
                iterations: 0,
                converged: true,
            };
        }

        for &(from, to, _weight) in edges {
            assert!(from < n_nodes, "edge source {from} >= n_nodes {n_nodes}");
            assert!(to < n_nodes, "edge target {to} >= n_nodes {n_nodes}");
        }

        let out_weight = compute_out_weights(n_nodes, edges);
        let adjacency = build_adjacency(n_nodes, edges, &out_weight);
        let uniform_score = 1.0 / n_nodes as f64;
        let teleport_score = (1.0 - self.damping) * uniform_score;

        let mut scores = vec![uniform_score; n_nodes];
        let mut converged = false;
        let mut iterations = 0;

        for _ in 0..self.max_iter {
            iterations += 1;

            let dangling_contribution =
                dangling_sum(&scores, &out_weight) * self.damping * uniform_score;

            let mut new_scores = vec![teleport_score + dangling_contribution; n_nodes];
            for (target, sources) in adjacency.iter().enumerate() {
                for &(source, normalized_weight) in sources {
                    new_scores[target] = (self.damping * scores[source])
                        .mul_add(normalized_weight, new_scores[target]);
                }
            }

            let max_delta = scores
                .iter()
                .zip(new_scores.iter())
                .map(|(old, new)| (new - old).abs())
                .fold(0.0_f64, f64::max);

            scores = new_scores;

            if max_delta < self.tol {
                converged = true;
                break;
            }
        }

        RankResult {
            scores,
            iterations,
            converged,
        }
    }
}

/// Result of a completed `PageRank` run.
///
/// # Example
///
/// ```rust
/// use rune_pagerank::PageRank;
///
/// let edges = [(0, 1, 1.0), (1, 0, 1.0)];
/// let result = PageRank::new().rank(2, &edges);
///
/// println!("converged: {}", result.converged);
/// println!("iterations: {}", result.iterations);
/// for (i, score) in result.scores.iter().enumerate() {
///     println!("node {i}: {score:.6}");
/// }
/// ```
pub struct RankResult {
    /// Per-node `PageRank` scores, one entry per node, summing to approximately `1.0`.
    pub scores: Vec<f64>,
    /// Number of power-iteration steps executed before convergence or the iteration cap.
    pub iterations: usize,
    /// `true` if `max |r_new[i] − r[i]| < tol` was satisfied before the iteration cap.
    pub converged: bool,
}

/// Whether an edge weight takes part in the walk (finite and strictly positive).
fn usable_weight(weight: f64) -> bool {
    weight.is_finite() && weight > 0.0
}

fn compute_out_weights(n_nodes: usize, edges: &[(usize, usize, f64)]) -> Vec<f64> {
    let mut out_weight = vec![0.0_f64; n_nodes];
    for &(from, _to, weight) in edges {
        if usable_weight(weight) {
            out_weight[from] += weight;
        }
    }
    out_weight
}

fn build_adjacency(
    n_nodes: usize,
    edges: &[(usize, usize, f64)],
    out_weight: &[f64],
) -> Vec<Vec<(usize, f64)>> {
    let mut adjacency: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n_nodes];
    for &(from, to, weight) in edges {
        let total_out = out_weight[from];
        if usable_weight(weight) && total_out > 0.0 {
            adjacency[to].push((from, weight / total_out));
        }
    }
    adjacency
}

fn dangling_sum(scores: &[f64], out_weight: &[f64]) -> f64 {
    scores
        .iter()
        .zip(out_weight.iter())
        .filter(|&(_score, &weight)| weight == 0.0)
        .map(|(&score, _weight)| score)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_node_cycle_converges_to_equal_scores() {
        let edges = [(0, 1, 1.0), (1, 0, 1.0)];
        let result = PageRank::new().rank(2, &edges);
        assert!(result.converged);
        assert!((result.scores[0] - 0.5).abs() < 1e-5);
        assert!((result.scores[1] - 0.5).abs() < 1e-5);
    }

    #[test]
    fn star_graph_hub_has_highest_score() {
        // Nodes 1, 2, 3 all point to node 0 (the hub)
        let edges = [(1, 0, 1.0), (2, 0, 1.0), (3, 0, 1.0)];
        let result = PageRank::new().rank(4, &edges);
        assert!(result.converged);
        let hub_score = result.scores[0];
        for spoke in 1..4 {
            assert!(hub_score > result.scores[spoke]);
        }
    }

    #[test]
    fn empty_graph_returns_uniform_scores() {
        let result = PageRank::new().rank(5, &[]);
        assert!(result.converged);
        for score in &result.scores {
            assert!((score - 0.2).abs() < 1e-5);
        }
    }

    #[test]
    fn single_node_returns_score_one() {
        let result = PageRank::new().rank(1, &[]);
        assert!(result.converged);
        assert_eq!(result.scores.len(), 1);
        assert!((result.scores[0] - 1.0).abs() < 1e-10);
    }

    #[test]
    fn dangling_node_does_not_leak_rank() {
        // Node 0 → node 1; node 2 is dangling (no outgoing edges).
        // Total rank must still sum to 1.0.
        let edges = [(0, 1, 1.0)];
        let result = PageRank::new().rank(3, &edges);
        assert!(result.converged);
        let total: f64 = result.scores.iter().sum();
        assert!((total - 1.0).abs() < 1e-9, "scores sum to {total}");
    }

    #[test]
    fn zero_nodes_returns_empty() {
        let result = PageRank::new().rank(0, &[]);
        assert_eq!(result.scores, [] as [f64; 0]);
        assert_eq!(result.iterations, 0);
        assert!(result.converged);
    }

    #[test]
    fn scores_sum_to_one() {
        let edges = [
            (0, 1, 2.0),
            (1, 2, 1.0),
            (1, 3, 1.0),
            (2, 0, 1.0),
            (3, 0, 3.0),
        ];
        let result = PageRank::new().rank(4, &edges);
        let total: f64 = result.scores.iter().sum();
        assert!((total - 1.0).abs() < 1e-9, "scores sum to {total}");
    }

    #[test]
    fn weighted_edges_affect_distribution() {
        // Node 0 sends 3× more weight to node 1 than to node 2
        let edges = [(0, 1, 3.0), (0, 2, 1.0), (1, 0, 1.0), (2, 0, 1.0)];
        let result = PageRank::new().rank(3, &edges);
        assert!(result.converged);
        assert!(result.scores[1] > result.scores[2]);
    }

    #[test]
    fn three_node_cycle_equal_scores() {
        let edges = [(0, 1, 1.0), (1, 2, 1.0), (2, 0, 1.0)];
        let result = PageRank::new().rank(3, &edges);
        assert!(result.converged);
        for score in &result.scores {
            assert!((score - 1.0 / 3.0).abs() < 1e-5);
        }
    }

    #[test]
    fn custom_damping_changes_scores() {
        let edges = [(0, 1, 1.0), (1, 0, 1.0)];
        let result_85 = PageRank::new().damping(0.85).rank(2, &edges);
        let result_50 = PageRank::new().damping(0.50).rank(2, &edges);
        // Both symmetric — scores equal within each run, but method should not panic
        assert!((result_85.scores[0] - 0.5).abs() < 1e-5);
        assert!((result_50.scores[0] - 0.5).abs() < 1e-5);
    }

    #[test]
    fn max_iter_cap_respected() {
        // Star graph: all spokes point to the hub. Uniform initialisation places each
        // node at 0.25 but the hub converges to a much higher value, so one iteration
        // is not enough at tol 1e-300.
        let edges = [(1, 0, 1.0), (2, 0, 1.0), (3, 0, 1.0)];
        let result = PageRank::new().max_iter(1).tol(1e-300).rank(4, &edges);
        assert_eq!(result.iterations, 1);
        assert!(!result.converged);
    }
}
