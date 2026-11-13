//! Leiden and Louvain community detection — find densely-connected clusters in
//! weighted graphs.
//!
//! Both algorithms partition the nodes of a weighted undirected graph into
//! communities that maximise a quality function. The default is Newman–Girvan
//! modularity with a resolution parameter `γ`:
//!
//! ```text
//! Q = (1/2m) × Σ_{ij} [A_ij − γ × k_i × k_j / (2m)] × δ(c_i, c_j)
//! ```
//!
//! where `m` is the total edge weight, `k_i` the weighted degree of node `i` and
//! `δ` the Kronecker delta. The Constant Potts Model ([`Quality::Cpm`]) is
//! available as an alternative that does not suffer from the resolution limit.
//!
//! - [`Leiden`] (Traag, Waltman & van Eck, 2019, "From Louvain to Leiden:
//!   guaranteeing well-connected communities", *Sci. Rep.* 9:5233) uses fast
//!   local moving, a randomised refinement step and aggregation of the refined
//!   partition. Every community it returns is connected (in fact
//!   γ-connected), and it usually reaches higher quality than Louvain.
//! - [`Louvain`] (Blondel et al., 2008) is the classic multi-level method.
//!
//! # Features
//!
//! - Weighted undirected graphs (parallel edges are summed, self-loops ignored)
//! - Modularity or CPM objective, configurable resolution `γ`
//! - Hierarchical output: one partition per aggregation level
//! - Standalone [`modularity`] and [`cpm`] functions to score any partition
//! - Deterministic via `random_seed`; Leiden's refinement randomness `θ` is
//!   configurable
//! - Validated entry points returning [`Error`]
//! - Pure Rust, no unsafe, no dependencies
//!
//! # Quick Start
//!
//! ```rust
//! use rune_leiden::Leiden;
//!
//! // Two triangles connected by a single bridge edge
//! let edges = vec![
//!     (0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0),
//!     (3, 4, 1.0), (4, 5, 1.0), (3, 5, 1.0),
//!     (2, 3, 0.01),
//! ];
//!
//! let result = Leiden::new().fit(6, &edges);
//! assert_eq!(result.n_communities, 2);
//! assert!(result.modularity >= 0.0);
//! assert_eq!(result.communities(), vec![vec![0, 1, 2], vec![3, 4, 5]]);
//! ```
//!
//! # Input rules
//!
//! [`Leiden::try_fit`], [`Louvain`] and the hierarchy methods reject an empty
//! graph, out-of-range node indices, negative or non-finite weights, and a
//! negative or non-finite resolution. Self-loops are accepted and ignored by
//! every entry point, including [`modularity`] and [`cpm`]. [`Leiden::fit`]
//! keeps its original contract: it panics on out-of-range indices and does not
//! check weights.
//!
//! # CLI
//!
//! ```bash
//! rune-leiden edges.txt
//! rune-leiden edges.txt --resolution 0.5 --seed 123
//! rune-leiden edges.txt --algorithm louvain
//! rune-leiden edges.txt --quality cpm --resolution 0.1
//! cat edges.txt | rune-leiden -
//! ```

mod engine;
mod error;
mod graph;
mod louvain;
mod quality;
mod rng;

pub use error::Error;
pub use louvain::Louvain;
pub use quality::{Quality, cpm, modularity};

use engine::{Algorithm, Settings};

/// Builder for configuring and running the Leiden community-detection algorithm.
///
/// Construct with [`Leiden::new`], chain optional parameters, then call
/// [`Leiden::try_fit`] or [`Leiden::fit`].
///
/// The algorithm follows Traag, Waltman & van Eck (2019). Each iteration
/// starts from the current partition `P` and repeats, level by level:
///
/// 1. **Fast local moving.** Nodes wait in a queue (random initial order).
///    A node moves to the neighbouring or empty community with the largest
///    positive gain; when it moves, its neighbours outside its new community
///    are queued again.
/// 2. If every community is a single node, the iteration ends.
/// 3. **Refinement.** Inside each community `S`, nodes start alone. A node
///    still alone and well connected to `S` may join a neighbouring
///    sub-community that is itself well connected to the rest of `S`, chosen
///    at random with probability `∝ exp(ΔH / θ)` among the non-negative
///    gains (see [`Leiden::randomness`]).
/// 4. **Aggregation.** Each refined sub-community becomes a node; the next
///    level starts from `P`, not from singletons.
///
/// Iterations repeat until one leaves the partition unchanged. Every
/// returned community is connected. It is also γ-connected: it can be built
/// by repeatedly merging two parts `A`, `B` joined by at least the weight the
/// objective expects between them (`γ·K_A·K_B / 2m` for modularity,
/// `γ·n_A·n_B` for CPM). No two returned communities are worth merging.
/// Identical settings and seed give identical results.
///
/// # Example
///
/// ```rust
/// use rune_leiden::Leiden;
///
/// let leiden = Leiden::new()
///     .resolution(1.0)
///     .max_iter(100)
///     .random_seed(42);
/// ```
#[derive(Debug, Clone)]
pub struct Leiden {
    resolution: f64,
    max_iter: usize,
    random_seed: u64,
    quality: Quality,
    randomness: f64,
}

impl Default for Leiden {
    fn default() -> Self {
        Self::new()
    }
}

impl Leiden {
    /// Creates a new `Leiden` instance with default parameters.
    ///
    /// | Parameter | Default |
    /// |---|---|
    /// | `resolution` | `1.0` |
    /// | `max_iter` | `100` |
    /// | `random_seed` | `42` |
    /// | `quality` | [`Quality::Modularity`] |
    /// | `randomness` | `0.01` |
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Leiden;
    ///
    /// let leiden = Leiden::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            resolution: 1.0,
            max_iter: 100,
            random_seed: 42,
            quality: Quality::Modularity,
            randomness: 0.01,
        }
    }

    /// Sets the resolution parameter `γ`.
    ///
    /// Higher values produce more, smaller communities; lower values produce fewer,
    /// larger communities. `1.0` corresponds to standard Newman–Girvan modularity.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Leiden;
    ///
    /// let leiden = Leiden::new().resolution(0.5);
    /// ```
    #[must_use]
    pub const fn resolution(mut self, r: f64) -> Self {
        self.resolution = r;
        self
    }

    /// Sets the maximum number of local-moving passes, counted over every
    /// aggregation level of every Leiden iteration.
    ///
    /// Leiden repeats its move–refine–aggregate iteration until one leaves the
    /// partition unchanged, which normally happens long before the cap.
    /// Defaults to `100`. If the cap cuts a run short, any disconnected
    /// community is split into its connected components before returning.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Leiden;
    ///
    /// let leiden = Leiden::new().max_iter(50);
    /// ```
    #[must_use]
    pub const fn max_iter(mut self, n: usize) -> Self {
        self.max_iter = n;
        self
    }

    /// Sets the seed for the internal PRNG. Identical seeds produce identical partitions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Leiden;
    ///
    /// let leiden = Leiden::new().random_seed(123);
    /// ```
    #[must_use]
    pub const fn random_seed(mut self, s: u64) -> Self {
        self.random_seed = s;
        self
    }

    /// Sets the objective to maximise. Defaults to [`Quality::Modularity`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::{Leiden, Quality};
    ///
    /// let leiden = Leiden::new().quality(Quality::Cpm).resolution(0.1);
    /// ```
    #[must_use]
    pub const fn quality(mut self, quality: Quality) -> Self {
        self.quality = quality;
        self
    }

    /// Sets the randomness `θ` of the refinement step. Defaults to `0.01`,
    /// the value used by Traag, Waltman & van Eck (2019).
    ///
    /// During refinement a node joins one of the eligible neighbouring
    /// sub-communities (or stays alone) with probability proportional to
    /// `exp(ΔH / θ)`, where `ΔH` is the quality gain in edge-weight units
    /// (`ΔH = w(v, C) − γ·k_v·K_C / 2m` for modularity,
    /// `w(v, C) − γ·n_v·n_C` for CPM). Small values are close to greedy,
    /// larger values explore more; `0` makes refinement fully greedy. The
    /// draw uses the seeded PRNG, so results stay reproducible.
    ///
    /// The value is relative to the edge weights: if you scale every weight
    /// by `k`, scale `θ` by `k` for the same behaviour.
    ///
    /// [`Leiden::try_fit`] and [`Leiden::fit_hierarchy`] reject a negative or
    /// non-finite value; [`Leiden::fit`] treats one as `0`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Leiden;
    ///
    /// let leiden = Leiden::new().randomness(0.05);
    /// ```
    #[must_use]
    pub const fn randomness(mut self, theta: f64) -> Self {
        self.randomness = theta;
        self
    }

    /// Partitions `n_nodes` nodes into communities by maximising the
    /// configured objective (modularity by default).
    ///
    /// `edges` is a list of undirected weighted edges `(u, v, weight)`. All node
    /// indices must be in `0..n_nodes`. Parallel edges with the same `(u, v)` pair
    /// are summed. Self-loops are ignored. Weights are not checked: use
    /// [`Leiden::try_fit`] to reject negative or non-finite weights.
    ///
    /// Returns a [`CommunityResult`] with one community id per node, contiguous from `0`.
    ///
    /// # Panics
    ///
    /// Panics if any node index in `edges` is `≥ n_nodes`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Leiden;
    ///
    /// // Two fully-connected triangles joined by a weak bridge
    /// let edges = vec![
    ///     (0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0),
    ///     (3, 4, 1.0), (4, 5, 1.0), (3, 5, 1.0),
    ///     (2, 3, 0.01),
    /// ];
    ///
    /// let result = Leiden::new().fit(6, &edges);
    /// assert_eq!(result.n_communities, 2);
    /// assert!(result.communities[0] == result.communities[1]);
    /// assert!(result.communities[0] != result.communities[3]);
    /// ```
    #[must_use]
    pub fn fit(&self, n_nodes: usize, edges: &[(usize, usize, f64)]) -> CommunityResult {
        for &(u, v, _) in edges {
            assert!(
                u < n_nodes,
                "node index {u} out of range (n_nodes = {n_nodes})"
            );
            assert!(
                v < n_nodes,
                "node index {v} out of range (n_nodes = {n_nodes})"
            );
        }

        if n_nodes <= 1 {
            return trivial_result(n_nodes);
        }
        fit_unchecked(&self.settings(), n_nodes, edges)
    }

    /// Like [`Leiden::fit`], but validates the input and returns an error
    /// instead of panicking or producing a meaningless partition.
    ///
    /// Edges must have finite, non-negative weights and in-range endpoints,
    /// the graph must have at least one node, and the resolution and
    /// [randomness](Leiden::randomness) must be finite and non-negative. Self-loops are accepted and ignored; parallel
    /// edges are summed. Zero-weight edges are allowed.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyGraph`], [`Error::NodeOutOfRange`],
    /// [`Error::InvalidWeight`], [`Error::InvalidResolution`] or
    /// [`Error::InvalidRandomness`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::{Error, Leiden};
    ///
    /// let edges = [(0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0)];
    /// let result = Leiden::new().try_fit(3, &edges)?;
    /// assert_eq!(result.n_communities, 1);
    ///
    /// assert_eq!(Leiden::new().try_fit(0, &[]).unwrap_err(), Error::EmptyGraph);
    /// # Ok::<(), Error>(())
    /// ```
    pub fn try_fit(
        &self,
        n_nodes: usize,
        edges: &[(usize, usize, f64)],
    ) -> Result<CommunityResult, Error> {
        validate(n_nodes, edges, self.resolution)?;
        error::validate_randomness(self.randomness)?;
        if n_nodes == 1 {
            return Ok(trivial_result(1));
        }
        Ok(fit_unchecked(&self.settings(), n_nodes, edges))
    }

    /// Runs Leiden and returns the partition reached after every local-moving
    /// pass, in order.
    ///
    /// Leiden collapses the refined sub-communities rather than the
    /// communities themselves, and repeats whole iterations, so a later level
    /// is not always a coarsening of the previous one. Quality does not
    /// decrease from one level to the next. Only the last level is
    /// guaranteed to have connected communities; it is also
    /// [`Hierarchy::best`], the partition [`Leiden::fit`] returns. Input rules
    /// are those of [`Leiden::try_fit`].
    ///
    /// # Errors
    ///
    /// Same as [`Leiden::try_fit`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Leiden;
    ///
    /// let edges = [
    ///     (0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0),
    ///     (3, 4, 1.0), (4, 5, 1.0), (3, 5, 1.0),
    ///     (2, 3, 0.01),
    /// ];
    /// let hierarchy = Leiden::new().fit_hierarchy(6, &edges)?;
    /// assert!(!hierarchy.levels.is_empty());
    /// assert_eq!(hierarchy.best().n_communities, 2);
    /// # Ok::<(), rune_leiden::Error>(())
    /// ```
    pub fn fit_hierarchy(
        &self,
        n_nodes: usize,
        edges: &[(usize, usize, f64)],
    ) -> Result<Hierarchy, Error> {
        validate(n_nodes, edges, self.resolution)?;
        error::validate_randomness(self.randomness)?;
        Ok(hierarchy_unchecked(&self.settings(), n_nodes, edges))
    }

    const fn settings(&self) -> Settings {
        Settings {
            algorithm: Algorithm::Leiden,
            quality: self.quality,
            resolution: self.resolution,
            max_iter: self.max_iter,
            seed: self.random_seed,
            randomness: self.randomness,
        }
    }
}

/// Checks a graph and resolution before a validated run.
fn validate(n_nodes: usize, edges: &[(usize, usize, f64)], resolution: f64) -> Result<(), Error> {
    error::validate_graph(n_nodes, edges)?;
    error::validate_resolution(resolution)
}

/// Result for graphs with zero or one node.
fn trivial_result(n_nodes: usize) -> CommunityResult {
    CommunityResult {
        communities: vec![0; n_nodes],
        n_communities: n_nodes,
        modularity: 0.0,
    }
}

/// Runs the engine and keeps the best level. Needs `n_nodes ≥ 1` and
/// in-range edges.
fn fit_unchecked(
    settings: &Settings,
    n_nodes: usize,
    edges: &[(usize, usize, f64)],
) -> CommunityResult {
    let (levels, best) = engine::run(settings, n_nodes, edges);
    let level = levels
        .into_iter()
        .nth(best)
        .unwrap_or_else(|| engine::RawLevel {
            partition: (0..n_nodes).collect(),
            quality: 0.0,
        });
    let communities = level.partition;
    let n_communities = communities.iter().copied().max().map_or(0, |m| m + 1);
    let modularity = match settings.quality {
        Quality::Modularity => level.quality,
        Quality::Cpm => graph::modularity(&graph::Graph::new(n_nodes, edges), &communities, 1.0),
    }
    .max(0.0);
    CommunityResult {
        communities,
        n_communities,
        modularity,
    }
}

/// Runs the engine and keeps every level. Needs `n_nodes ≥ 1` and in-range
/// edges.
fn hierarchy_unchecked(
    settings: &Settings,
    n_nodes: usize,
    edges: &[(usize, usize, f64)],
) -> Hierarchy {
    let (levels, best) = engine::run(settings, n_nodes, edges);
    let levels = levels
        .into_iter()
        .map(|raw| Level {
            n_communities: raw.partition.iter().copied().max().map_or(0, |m| m + 1),
            communities: raw.partition,
            quality: raw.quality,
        })
        .collect();
    Hierarchy { levels, best }
}

/// Groups node ids by community id: entry `c` lists the members of community
/// `c` in ascending order.
fn group(communities: &[usize], n_communities: usize) -> Vec<Vec<usize>> {
    let mut groups = vec![Vec::new(); n_communities];
    for (node, &c) in communities.iter().enumerate() {
        if let Some(members) = groups.get_mut(c) {
            members.push(node);
        }
    }
    groups
}

/// Result of a completed community-detection run.
#[derive(Debug, Clone, PartialEq)]
pub struct CommunityResult {
    /// Community id for each input node. Ids are contiguous integers starting at `0`.
    pub communities: Vec<usize>,
    /// Number of distinct communities found.
    pub n_communities: usize,
    /// Final modularity score `Q`, guaranteed `≥ 0.0`.
    ///
    /// With [`Quality::Modularity`] this is the objective at the configured
    /// resolution. With [`Quality::Cpm`] it is standard modularity (`γ = 1`)
    /// of the CPM partition; use [`cpm`] for the CPM value itself.
    pub modularity: f64,
}

impl CommunityResult {
    /// Members of each community: entry `c` lists the nodes in community `c`,
    /// in ascending order.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Leiden;
    ///
    /// let edges = [(0, 1, 1.0), (2, 3, 1.0)];
    /// let result = Leiden::new().fit(4, &edges);
    /// let mut groups = result.communities();
    /// groups.sort();
    /// assert_eq!(groups, vec![vec![0, 1], vec![2, 3]]);
    /// ```
    #[must_use]
    pub fn communities(&self) -> Vec<Vec<usize>> {
        group(&self.communities, self.n_communities)
    }
}

/// Partitions found at successive aggregation levels of a run.
///
/// Returned by [`Leiden::fit_hierarchy`] and [`Louvain::fit_hierarchy`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Hierarchy {
    /// One partition of the original nodes per level, finest first.
    /// Consecutive duplicates are dropped, so the list is never empty and
    /// every level differs from the one before it.
    pub levels: Vec<Level>,
    best: usize,
}

impl Hierarchy {
    /// The level with the highest quality (the first one on ties). For
    /// Leiden this is always the last level.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Louvain;
    ///
    /// let edges = [(0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0)];
    /// let hierarchy = Louvain::new().fit_hierarchy(3, &edges)?;
    /// assert_eq!(hierarchy.best().n_communities, 1);
    /// # Ok::<(), rune_leiden::Error>(())
    /// ```
    #[must_use]
    pub fn best(&self) -> &Level {
        &self.levels[self.best]
    }

    /// The last (coarsest) level.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Louvain;
    ///
    /// let hierarchy = Louvain::new().fit_hierarchy(2, &[(0, 1, 1.0)])?;
    /// assert_eq!(hierarchy.last().communities, vec![0, 0]);
    /// # Ok::<(), rune_leiden::Error>(())
    /// ```
    #[must_use]
    pub fn last(&self) -> &Level {
        &self.levels[self.levels.len() - 1]
    }
}

/// One level of a [`Hierarchy`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Level {
    /// Community id for each original node, contiguous from `0`.
    pub communities: Vec<usize>,
    /// Number of distinct communities at this level.
    pub n_communities: usize,
    /// Value of the run's objective for this partition: modularity at the
    /// configured resolution, or the CPM value. Not clamped.
    pub quality: f64,
}

impl Level {
    /// Members of each community at this level; see
    /// [`CommunityResult::communities()`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Louvain;
    ///
    /// let hierarchy = Louvain::new().fit_hierarchy(3, &[(0, 1, 1.0)])?;
    /// assert_eq!(hierarchy.best().communities().len(), 2);
    /// # Ok::<(), rune_leiden::Error>(())
    /// ```
    #[must_use]
    pub fn communities(&self) -> Vec<Vec<usize>> {
        group(&self.communities, self.n_communities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_blob_edges() -> Vec<(usize, usize, f64)> {
        let mut edges = Vec::new();
        for i in 0..5usize {
            for j in (i + 1)..5 {
                edges.push((i, j, 1.0));
            }
        }
        for i in 5..10usize {
            for j in (i + 1)..10 {
                edges.push((i, j, 1.0));
            }
        }
        // Thin bridge
        edges.push((4, 5, 0.01));
        edges
    }

    #[test]
    fn two_blobs_produce_two_communities() {
        let edges = two_blob_edges();
        let result = Leiden::new().fit(10, &edges);
        assert_eq!(
            result.n_communities, 2,
            "expected 2 communities, got {}",
            result.n_communities
        );
        let c0 = result.communities[0];
        let c5 = result.communities[5];
        assert_ne!(c0, c5, "blobs should be in different communities");
        for i in 0..5 {
            assert_eq!(
                result.communities[i], c0,
                "node {i} should be in blob-0 community"
            );
        }
        for i in 5..10 {
            assert_eq!(
                result.communities[i], c5,
                "node {i} should be in blob-1 community"
            );
        }
    }

    #[test]
    fn single_node_produces_one_community() {
        let result = Leiden::new().fit(1, &[]);
        assert_eq!(result.n_communities, 1);
        assert_eq!(result.communities, vec![0]);
    }

    #[test]
    fn complete_graph_produces_one_community() {
        let edges: Vec<(usize, usize, f64)> = (0..5usize)
            .flat_map(|i| (i + 1..5).map(move |j| (i, j, 1.0)))
            .collect();
        let result = Leiden::new().fit(5, &edges);
        assert_eq!(result.n_communities, 1);
    }

    #[test]
    fn triangle_produces_one_community() {
        let edges = vec![(0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0)];
        let result = Leiden::new().fit(3, &edges);
        assert_eq!(result.n_communities, 1);
    }

    #[test]
    fn n_communities_matches_distinct_values() {
        let edges = two_blob_edges();
        let result = Leiden::new().fit(10, &edges);
        let distinct: std::collections::HashSet<usize> =
            result.communities.iter().copied().collect();
        assert_eq!(distinct.len(), result.n_communities);
    }

    #[test]
    fn modularity_finite_and_nonnegative_for_structured_graph() {
        let edges = two_blob_edges();
        let result = Leiden::new().fit(10, &edges);
        assert!(result.modularity.is_finite(), "modularity must be finite");
        assert!(
            result.modularity >= 0.0,
            "modularity must be ≥ 0 for structured graph"
        );
    }

    #[test]
    fn deterministic_with_same_seed() {
        let edges = two_blob_edges();
        let r1 = Leiden::new().random_seed(7).fit(10, &edges);
        let r2 = Leiden::new().random_seed(7).fit(10, &edges);
        assert_eq!(r1.communities, r2.communities);
        assert_eq!(r1.n_communities, r2.n_communities);
    }

    #[test]
    fn communities_are_contiguous_from_zero() {
        let edges = two_blob_edges();
        let result = Leiden::new().fit(10, &edges);
        let mut sorted: Vec<usize> = result.communities.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, (0..result.n_communities).collect::<Vec<_>>());
    }

    #[test]
    fn isolated_nodes_each_get_own_community() {
        let result = Leiden::new().fit(4, &[]);
        assert_eq!(result.n_communities, 4);
    }
}
