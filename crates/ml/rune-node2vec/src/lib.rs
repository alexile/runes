//! `Node2Vec` — graph node embeddings via biased random walks and skip-gram.
//!
//! `Node2Vec` (Grover & Leskovec, 2016) learns a continuous vector representation for
//! every node in an undirected graph. It generalises `DeepWalk` by introducing two
//! hyperparameters (`p` and `q`) that bias the random walk to explore either the
//! local neighbourhood (BFS-like) or the wider graph (DFS-like), letting the
//! embedding capture both structural equivalence and community membership.
//!
//! The algorithm has two phases:
//!
//! 1. **Biased random walks** — for each node, generate `num_walks` walks of length
//!    `walk_length`. At each step the transition probability is weighted by `1/p`
//!    (return to previous), `1.0` (common neighbour), or `1/q` (exploration), and
//!    sampled in O(1) with the alias method.
//!
//! 2. **Skip-gram with negative sampling** — treats each walk as a sentence, pairs
//!    each node with its context window, and optimises embeddings with SGD. Negative
//!    nodes are drawn proportional to `degree^(3/4)`.
//!
//! # Features
//!
//! - Pure Rust — no unsafe code, no dependencies beyond the library itself
//! - Deterministic output via `random_seed`
//! - Supports isolated nodes (walk length 1; embedding is random-initialised)
//! - p=1, q=1 reproduces standard `DeepWalk` behaviour
//! - Fluent builder API matching the rest of the `rune-*` family
//!
//! # Quick Start
//!
//! ```rust
//! use rune_node2vec::Node2Vec;
//!
//! // A triangle: nodes 0-1-2-0
//! let edges = vec![(0, 1), (1, 2), (2, 0)];
//! let result = Node2Vec::new()
//!     .embedding_dim(8)
//!     .n_epochs(5)
//!     .fit(3, &edges);
//!
//! assert_eq!(result.embeddings.len(), 3);
//! assert_eq!(result.embeddings[0].len(), 8);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-node2vec graph.edgelist --dim 64 --epochs 5
//! cat graph.edgelist | rune-node2vec -
//! ```

mod alias;
mod rng;
mod sgd;
mod walks;

/// Builder for configuring and running the `Node2Vec` algorithm.
///
/// Construct with [`Node2Vec::new`], chain optional parameters, then call [`Node2Vec::fit`].
///
/// # Example
///
/// ```rust
/// use rune_node2vec::Node2Vec;
///
/// let model = Node2Vec::new()
///     .embedding_dim(64)
///     .walk_length(40)
///     .num_walks(5)
///     .p(1.0)
///     .q(0.5)
///     .n_epochs(3)
///     .random_seed(7);
/// ```
#[derive(Clone)]
pub struct Node2Vec {
    embedding_dim: usize,
    walk_length: usize,
    num_walks: usize,
    window_size: usize,
    p: f64,
    q: f64,
    n_epochs: usize,
    learning_rate: f64,
    neg_samples: usize,
    random_seed: u64,
}

impl Default for Node2Vec {
    fn default() -> Self {
        Self::new()
    }
}

impl Node2Vec {
    /// Creates a new `Node2Vec` instance with sensible defaults.
    ///
    /// | Parameter | Default |
    /// |---|---|
    /// | `embedding_dim` | 128 |
    /// | `walk_length` | 80 |
    /// | `num_walks` | 10 |
    /// | `window_size` | 10 |
    /// | `p` | 1.0 |
    /// | `q` | 1.0 |
    /// | `n_epochs` | 1 |
    /// | `learning_rate` | 0.025 |
    /// | `neg_samples` | 5 |
    /// | `random_seed` | 42 |
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// let model = Node2Vec::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            embedding_dim: 128,
            walk_length: 80,
            num_walks: 10,
            window_size: 10,
            p: 1.0,
            q: 1.0,
            n_epochs: 1,
            learning_rate: 0.025,
            neg_samples: 5,
            random_seed: 42,
        }
    }

    /// Dimensionality of each output embedding vector. Defaults to `128`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// let model = Node2Vec::new().embedding_dim(64);
    /// ```
    #[must_use]
    pub fn embedding_dim(mut self, d: usize) -> Self {
        self.embedding_dim = d.max(1);
        self
    }

    /// Number of nodes in each random walk. Defaults to `80`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// let model = Node2Vec::new().walk_length(40);
    /// ```
    #[must_use]
    pub fn walk_length(mut self, l: usize) -> Self {
        self.walk_length = l.max(1);
        self
    }

    /// Number of walks generated from each node. Defaults to `10`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// let model = Node2Vec::new().num_walks(5);
    /// ```
    #[must_use]
    pub fn num_walks(mut self, n: usize) -> Self {
        self.num_walks = n.max(1);
        self
    }

    /// Skip-gram context window half-width. Defaults to `10`.
    ///
    /// Each centre node is paired with all nodes within `window_size` positions
    /// on either side in the walk.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// let model = Node2Vec::new().window_size(5);
    /// ```
    #[must_use]
    pub fn window_size(mut self, w: usize) -> Self {
        self.window_size = w.max(1);
        self
    }

    /// Return parameter controlling the likelihood of revisiting a node. Defaults to `1.0`.
    ///
    /// Low `p` encourages the walk to backtrack; high `p` pushes the walk forward.
    /// Clamped to a minimum of `1e-9`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// let model = Node2Vec::new().p(0.5);
    /// ```
    #[must_use]
    pub const fn p(mut self, p: f64) -> Self {
        self.p = p.max(1e-9);
        self
    }

    /// In-out parameter controlling the walk's tendency to explore. Defaults to `1.0`.
    ///
    /// Low `q` favours DFS-like exploration of the graph; high `q` favours BFS-like
    /// local neighbourhood traversal. Clamped to a minimum of `1e-9`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// let model = Node2Vec::new().q(2.0);
    /// ```
    #[must_use]
    pub const fn q(mut self, q: f64) -> Self {
        self.q = q.max(1e-9);
        self
    }

    /// Number of training epochs over all walks. Defaults to `1`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// let model = Node2Vec::new().n_epochs(5);
    /// ```
    #[must_use]
    pub fn n_epochs(mut self, n: usize) -> Self {
        self.n_epochs = n.max(1);
        self
    }

    /// Initial SGD learning rate; decays linearly to `0.0001 × initial_lr`. Defaults to `0.025`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// let model = Node2Vec::new().learning_rate(0.01);
    /// ```
    #[must_use]
    pub const fn learning_rate(mut self, lr: f64) -> Self {
        self.learning_rate = lr.max(1e-9);
        self
    }

    /// Number of negative samples drawn per positive (centre, context) pair. Defaults to `5`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// let model = Node2Vec::new().neg_samples(10);
    /// ```
    #[must_use]
    pub fn neg_samples(mut self, n: usize) -> Self {
        self.neg_samples = n.max(1);
        self
    }

    /// Seed for the internal Xorshift64 PRNG. Identical seeds produce identical embeddings.
    /// Defaults to `42`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// let model = Node2Vec::new().random_seed(123);
    /// ```
    #[must_use]
    pub const fn random_seed(mut self, s: u64) -> Self {
        self.random_seed = s;
        self
    }

    /// Computes `Node2Vec` embeddings for an undirected graph.
    ///
    /// `n_nodes` is the total number of nodes (indices `0..n_nodes`). `edges` is a
    /// slice of undirected `(u, v)` pairs; each edge is added in both directions.
    /// Self-loops are ignored.
    ///
    /// Every node receives an embedding regardless of whether it has any edges.
    /// Isolated nodes are not visited during walk training and keep their random
    /// initial embedding.
    ///
    /// # Panics
    ///
    /// Panics if any node index in `edges` is `≥ n_nodes`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_node2vec::Node2Vec;
    ///
    /// // Two connected triangles sharing no edge.
    /// let edges = vec![
    ///     (0, 1), (1, 2), (2, 0),
    ///     (3, 4), (4, 5), (5, 3),
    /// ];
    /// let result = Node2Vec::new()
    ///     .embedding_dim(16)
    ///     .num_walks(5)
    ///     .walk_length(20)
    ///     .n_epochs(3)
    ///     .random_seed(42)
    ///     .fit(6, &edges);
    ///
    /// assert_eq!(result.embeddings.len(), 6);
    /// assert!(result.embeddings.iter().all(|e| e.len() == 16));
    /// ```
    #[must_use]
    pub fn fit(&self, n_nodes: usize, edges: &[(usize, usize)]) -> EmbedResult {
        for &(u, v) in edges {
            assert!(u < n_nodes, "edge node {u} >= n_nodes {n_nodes}");
            assert!(v < n_nodes, "edge node {v} >= n_nodes {n_nodes}");
        }

        let adjacency = build_adjacency(n_nodes, edges);
        let degrees: Vec<usize> = adjacency.iter().map(std::vec::Vec::len).collect();

        let mut rng = rng::Rng::new(self.random_seed);

        let mut flat = init_embeddings(n_nodes, self.embedding_dim, &mut rng);

        let all_walks = walks::generate_walks(
            &adjacency,
            self.walk_length,
            self.num_walks,
            self.p,
            self.q,
            &mut rng,
        );

        let noise = sgd::build_noise_distribution(&degrees);

        sgd::train(
            &mut flat,
            &sgd::TrainParams {
                n_nodes,
                dim: self.embedding_dim,
                walks: &all_walks,
                window_size: self.window_size,
                neg_samples: self.neg_samples,
                n_epochs: self.n_epochs,
                initial_lr: self.learning_rate,
                noise: noise.as_ref(),
            },
            &mut rng,
        );

        let embeddings = (0..n_nodes)
            .map(|i| flat[i * self.embedding_dim..(i + 1) * self.embedding_dim].to_vec())
            .collect();

        EmbedResult { embeddings }
    }
}

/// The output of a completed `Node2Vec` run.
pub struct EmbedResult {
    /// One embedding vector per node, each of length `embedding_dim`.
    pub embeddings: Vec<Vec<f64>>,
}

/// Builds a sorted adjacency list from undirected edges (self-loops excluded).
fn build_adjacency(n_nodes: usize, edges: &[(usize, usize)]) -> Vec<Vec<usize>> {
    let mut adjacency = vec![Vec::new(); n_nodes];
    for &(u, v) in edges {
        if u != v {
            adjacency[u].push(v);
            adjacency[v].push(u);
        }
    }
    for nb in &mut adjacency {
        nb.sort_unstable();
        nb.dedup();
    }
    adjacency
}

/// Initialises embeddings uniformly in `[-0.5/dim, 0.5/dim]`.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn init_embeddings(n_nodes: usize, dim: usize, rng: &mut rng::Rng) -> Vec<f64> {
    let half_range = 0.5 / dim as f64;
    (0..n_nodes * dim)
        .map(|_| (rng.next_f64() - 0.5) * 2.0 * half_range)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_cliques() -> (usize, Vec<(usize, usize)>) {
        // Clique A: nodes 0-4, Clique B: nodes 5-9.
        let mut edges = Vec::new();
        for i in 0..5 {
            for j in (i + 1)..5 {
                edges.push((i, j));
            }
        }
        for i in 5..10 {
            for j in (i + 1)..10 {
                edges.push((i, j));
            }
        }
        (10, edges)
    }

    fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
        let dot: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
        let norm_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
        let norm_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }
        dot / (norm_a * norm_b)
    }

    #[test]
    fn output_shape() {
        let edges = vec![(0, 1), (1, 2), (2, 0)];
        let result = Node2Vec::new()
            .embedding_dim(16)
            .num_walks(2)
            .walk_length(10)
            .n_epochs(1)
            .fit(3, &edges);
        assert_eq!(result.embeddings.len(), 3);
        assert!(result.embeddings.iter().all(|e| e.len() == 16));
    }

    #[test]
    fn isolated_node_gets_embedding() {
        // Node 0 has no edges.
        let edges = vec![(1, 2), (2, 3), (3, 1)];
        let result = Node2Vec::new().embedding_dim(8).n_epochs(1).fit(4, &edges);
        assert_eq!(result.embeddings.len(), 4);
        // Isolated node should have a finite (non-NaN, non-inf) embedding.
        for value in &result.embeddings[0] {
            assert!(
                value.is_finite(),
                "isolated node embedding contains non-finite value"
            );
        }
    }

    #[test]
    fn deterministic_with_same_seed() {
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 0)];
        let r1 = Node2Vec::new()
            .embedding_dim(8)
            .n_epochs(2)
            .random_seed(77)
            .fit(4, &edges);
        let r2 = Node2Vec::new()
            .embedding_dim(8)
            .n_epochs(2)
            .random_seed(77)
            .fit(4, &edges);
        for (a, b) in r1.embeddings.iter().zip(&r2.embeddings) {
            for (x, y) in a.iter().zip(b) {
                assert!((x - y).abs() < 1e-12, "embeddings differ with same seed");
            }
        }
    }

    #[test]
    fn uniform_walks_produce_finite_embeddings() {
        // p=1, q=1 is standard DeepWalk.
        let edges = vec![(0, 1), (1, 2), (2, 0), (0, 3)];
        let result = Node2Vec::new()
            .embedding_dim(8)
            .p(1.0)
            .q(1.0)
            .n_epochs(2)
            .fit(4, &edges);
        for embedding in &result.embeddings {
            for value in embedding {
                assert!(value.is_finite(), "non-finite value in p=1,q=1 embedding");
            }
        }
    }

    #[test]
    fn same_clique_more_similar_than_across() {
        let (n_nodes, edges) = two_cliques();
        let result = Node2Vec::new()
            .embedding_dim(32)
            .num_walks(10)
            .walk_length(20)
            .n_epochs(10)
            .random_seed(42)
            .fit(n_nodes, &edges);

        // Average intra-clique cosine similarity.
        let intra_sim: f64 = {
            let mut total = 0.0;
            let mut count = 0;
            for clique in [0..5usize, 5..10usize] {
                let nodes: Vec<usize> = clique.collect();
                for i in 0..nodes.len() {
                    for j in (i + 1)..nodes.len() {
                        total += cosine_similarity(
                            &result.embeddings[nodes[i]],
                            &result.embeddings[nodes[j]],
                        );
                        count += 1;
                    }
                }
            }
            total / f64::from(count)
        };

        // Average inter-clique cosine similarity.
        let inter_sim: f64 = {
            let mut total = 0.0;
            let mut count = 0;
            for i in 0..5 {
                for j in 5..10 {
                    total += cosine_similarity(&result.embeddings[i], &result.embeddings[j]);
                    count += 1;
                }
            }
            total / f64::from(count)
        };

        assert!(
            intra_sim > inter_sim,
            "intra-clique similarity ({intra_sim:.4}) should exceed inter-clique ({inter_sim:.4})"
        );
    }
}
