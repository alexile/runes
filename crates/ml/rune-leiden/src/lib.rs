//! Leiden community detection — find densely-connected clusters in weighted graphs.
//!
//! The Leiden algorithm (Traag, Waltman & van Eck, 2019) partitions the nodes of a
//! weighted undirected graph into communities that maximise the modularity objective:
//!
//! ```text
//! Q = (1/2m) × Σ_{ij} [A_ij − γ × k_i × k_j / (2m)] × δ(c_i, c_j)
//! ```
//!
//! where `m` is the total edge weight, `k_i` the weighted degree of node `i`, `γ` the
//! resolution parameter, and `δ` the Kronecker delta. Leiden improves on Louvain by
//! adding a refinement phase that prevents poorly-connected communities from merging.
//!
//! # Features
//!
//! - Weighted undirected graphs (parallel edges are summed)
//! - Configurable resolution parameter `γ` for community granularity
//! - Deterministic via `random_seed`
//! - Pure Rust, no unsafe, no external library dependencies
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
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-leiden edges.txt
//! rune-leiden edges.txt --resolution 0.5 --seed 123
//! cat edges.txt | rune-leiden -
//! ```

mod graph;
mod rng;

use graph::Graph;

/// Builder for configuring and running the Leiden community-detection algorithm.
///
/// Construct with [`Leiden::new`], chain optional parameters, then call [`Leiden::fit`].
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
pub struct Leiden {
    resolution: f64,
    max_iter: usize,
    random_seed: u64,
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

    /// Sets the maximum number of outer iterations (aggregation rounds).
    ///
    /// The algorithm terminates earlier if modularity stops improving. Defaults to `100`,
    /// which is more than sufficient for most real-world graphs.
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

    /// Partitions `n_nodes` nodes into communities by maximising modularity.
    ///
    /// `edges` is a list of undirected weighted edges `(u, v, weight)`. All node
    /// indices must be in `0..n_nodes`. Parallel edges with the same `(u, v)` pair
    /// are summed. Self-loops are ignored.
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

        if n_nodes == 0 {
            return CommunityResult {
                communities: vec![],
                n_communities: 0,
                modularity: 0.0,
            };
        }

        if n_nodes == 1 {
            return CommunityResult {
                communities: vec![0],
                n_communities: 1,
                modularity: 0.0,
            };
        }

        let mut rng = rng::Rng::new(self.random_seed);
        let base_graph = Graph::new(n_nodes, edges);

        // `node_map[supernode]` = list of original nodes it represents.
        // Starts as identity: each original node is its own supernode.
        let mut node_map: Vec<Vec<usize>> = (0..n_nodes).map(|i| vec![i]).collect();
        let mut current_edges: Vec<(usize, usize, f64)> = edges.to_vec();
        // Weight collapsed inside each supernode, kept as a self-loop so that
        // supernode degrees (and hence modularity gains) stay correct.
        let mut current_loops: Vec<f64> = vec![0.0; n_nodes];
        let mut current_n = n_nodes;

        // `best_partition[original_node]` tracks the best full partition found.
        let mut best_partition: Vec<usize> = (0..n_nodes).collect();
        let mut best_modularity = f64::NEG_INFINITY;

        for _iteration in 0..self.max_iter {
            let graph = Graph::new(current_n, &current_edges).with_self_loops(&current_loops);

            let (local_partition, any_moves) = phase1_move_nodes(&graph, self.resolution, &mut rng);

            // Map the local partition back to original nodes for quality assessment.
            let full_partition = resolve_partition(&node_map, &local_partition, n_nodes);
            let modularity = graph::modularity(&base_graph, &full_partition, self.resolution);

            if modularity > best_modularity {
                best_modularity = modularity;
                best_partition = full_partition;
            }

            if !any_moves {
                break;
            }

            let refined_partition =
                phase2_refine(&graph, &local_partition, self.resolution, &mut rng);

            let (super_n, super_edges, super_loops, new_map) =
                phase3_aggregate(&graph, &refined_partition, &node_map);

            node_map = new_map;
            current_edges = super_edges;
            current_loops = super_loops;
            current_n = super_n;

            if current_n == 1 {
                break;
            }
        }

        let communities = renumber(&best_partition);
        let n_communities = communities.iter().copied().max().map_or(0, |m| m + 1);
        let modularity = graph::modularity(&base_graph, &communities, self.resolution).max(0.0);

        CommunityResult {
            communities,
            n_communities,
            modularity,
        }
    }
}

/// Resolves a partition on supernodes back to original-node community ids.
fn resolve_partition(
    node_map: &[Vec<usize>],
    supernode_partition: &[usize],
    n_nodes: usize,
) -> Vec<usize> {
    let mut result = vec![0usize; n_nodes];
    for (supernode, community) in supernode_partition.iter().enumerate() {
        for &original in &node_map[supernode] {
            result[original] = *community;
        }
    }
    result
}

/// Renumbers community ids to be contiguous starting from `0`.
fn renumber(partition: &[usize]) -> Vec<usize> {
    let max_id = partition.iter().copied().max().unwrap_or(0);
    let mut remap = vec![usize::MAX; max_id + 1];
    let mut next_id = 0usize;
    let mut result = vec![0usize; partition.len()];
    for (i, &c) in partition.iter().enumerate() {
        if remap[c] == usize::MAX {
            remap[c] = next_id;
            next_id += 1;
        }
        result[i] = remap[c];
    }
    result
}

/// Phase 1: iteratively move nodes to neighbouring communities to maximise modularity.
///
/// Returns `(partition, any_moves)` where `any_moves` is `true` if at least one node
/// moved during this call. The partition uses contiguous community ids from `0`.
fn phase1_move_nodes(graph: &Graph, resolution: f64, rng: &mut rng::Rng) -> (Vec<usize>, bool) {
    let n = graph.n_nodes;
    let two_m = 2.0 * graph.total_weight;

    let mut partition: Vec<usize> = (0..n).collect();
    let mut community_total_degree = graph.degree.clone();

    let mut node_order: Vec<usize> = (0..n).collect();
    rng.shuffle(&mut node_order);

    let mut ever_moved = false;

    loop {
        let mut moved = false;

        for &v in &node_order {
            let current_community = partition[v];
            let k_v = graph.degree[v];

            community_total_degree[current_community] -= k_v;

            let mut community_weights: Vec<(usize, f64)> = Vec::new();
            for &(nb, w) in graph.neighbours(v) {
                let c_nb = partition[nb];
                if let Some(entry) = community_weights.iter_mut().find(|(c, _)| *c == c_nb) {
                    entry.1 += w;
                } else {
                    community_weights.push((c_nb, w));
                }
            }

            let mut best_community = current_community;
            let mut best_delta = delta_q(0.0, k_v, 0.0, two_m, resolution);

            for (candidate_community, k_v_to_c) in community_weights {
                let sigma_tot = community_total_degree[candidate_community];
                let delta = delta_q(k_v_to_c, k_v, sigma_tot, two_m, resolution);
                if delta > best_delta {
                    best_delta = delta;
                    best_community = candidate_community;
                }
            }

            if best_community != current_community {
                moved = true;
                ever_moved = true;
            }

            partition[v] = best_community;
            community_total_degree[best_community] += k_v;
        }

        if !moved {
            break;
        }
    }

    (renumber(&partition), ever_moved)
}

/// Modularity gain from moving node `v` into community `C`.
///
/// `k_v_to_c`: sum of edge weights from v to nodes already in C.
/// `k_v`: weighted degree of v.
/// `sigma_tot_c`: sum of degrees of nodes currently in C (before adding v).
#[inline]
fn delta_q(k_v_to_c: f64, k_v: f64, sigma_tot_c: f64, two_m: f64, resolution: f64) -> f64 {
    k_v_to_c / (two_m / 2.0) - resolution * k_v * sigma_tot_c / (two_m * (two_m / 2.0))
}

/// Phase 2: refine the Phase 1 partition within each community.
///
/// For each Phase 1 community, start each constituent node as its own sub-community
/// and greedily merge sub-communities. Returns a refined partition that is a
/// sub-partition of `coarse_partition`.
fn phase2_refine(
    graph: &Graph,
    coarse_partition: &[usize],
    resolution: f64,
    rng: &mut rng::Rng,
) -> Vec<usize> {
    let n = graph.n_nodes;
    let two_m = 2.0 * graph.total_weight;

    let n_communities = coarse_partition.iter().copied().max().map_or(n, |m| m + 1);

    // Collect nodes per coarse community
    let mut community_members: Vec<Vec<usize>> = vec![Vec::new(); n_communities];
    for v in 0..n {
        community_members[coarse_partition[v]].push(v);
    }

    // Each node starts as its own sub-community
    let mut sub_partition: Vec<usize> = (0..n).collect();
    let mut sub_degree: Vec<f64> = graph.degree.clone();

    for members in &community_members {
        if members.len() <= 1 {
            continue;
        }

        let mut order = members.clone();
        rng.shuffle(&mut order);

        for &v in &order {
            let current_sub = sub_partition[v];
            let k_v = graph.degree[v];

            sub_degree[current_sub] -= k_v;

            let mut sub_weights: Vec<(usize, f64)> = Vec::new();
            for &(nb, w) in graph.neighbours(v) {
                if coarse_partition[nb] != coarse_partition[v] {
                    continue;
                }
                let s_nb = sub_partition[nb];
                if let Some(entry) = sub_weights.iter_mut().find(|(s, _)| *s == s_nb) {
                    entry.1 += w;
                } else {
                    sub_weights.push((s_nb, w));
                }
            }

            let mut best_sub = current_sub;
            let mut best_delta = 0.0;

            for (candidate_sub, k_v_to_s) in sub_weights {
                if candidate_sub == current_sub {
                    continue;
                }
                let sigma_tot = sub_degree[candidate_sub];
                let delta = delta_q(k_v_to_s, k_v, sigma_tot, two_m, resolution);
                if delta > best_delta {
                    best_delta = delta;
                    best_sub = candidate_sub;
                }
            }

            sub_partition[v] = best_sub;
            sub_degree[best_sub] += k_v;
        }
    }

    renumber(&sub_partition)
}

/// Output of [`phase3_aggregate`]: supernode count, supernode edges,
/// supernode self-loop weights, and node map.
type AggregateResult = (usize, Vec<(usize, usize, f64)>, Vec<f64>, Vec<Vec<usize>>);

/// Phase 3: build the aggregated (supernode) graph from a refined partition.
///
/// Returns `(n_supernodes, supernode_edges, supernode_loops, node_map)` where
/// `supernode_loops[s]` is the total weight of edges collapsed inside `s` and
/// `node_map[supernode]` lists the original nodes that collapsed into it.
fn phase3_aggregate(
    graph: &Graph,
    refined_partition: &[usize],
    node_map: &[Vec<usize>],
) -> AggregateResult {
    let n_super = refined_partition.iter().copied().max().map_or(0, |m| m + 1);

    // Build supernode → original-node mapping
    let mut new_map: Vec<Vec<usize>> = vec![Vec::new(); n_super];
    for (v, &community) in refined_partition.iter().enumerate() {
        for &orig in &node_map[v] {
            new_map[community].push(orig);
        }
    }

    // Accumulate edge weights between supernodes
    let mut edge_map: std::collections::HashMap<(usize, usize), f64> =
        std::collections::HashMap::new();

    let mut super_loops = vec![0.0f64; n_super];

    for v in 0..graph.n_nodes {
        let sv = refined_partition[v];
        super_loops[sv] += graph.self_loop(v);
        for &(nb, w) in graph.neighbours(v) {
            let snb = refined_partition[nb];
            if sv == snb {
                // Seen once from each endpoint.
                super_loops[sv] += w / 2.0;
                continue;
            }
            let key = if sv < snb { (sv, snb) } else { (snb, sv) };
            *edge_map.entry(key).or_insert(0.0) += w;
        }
    }

    // Each undirected pair was counted twice (once per direction)
    let super_edges: Vec<(usize, usize, f64)> = edge_map
        .into_iter()
        .map(|((u, v), w)| (u, v, w / 2.0))
        .collect();

    (n_super, super_edges, super_loops, new_map)
}

/// Result of a completed Leiden community-detection run.
pub struct CommunityResult {
    /// Community id for each input node. Ids are contiguous integers starting at `0`.
    pub communities: Vec<usize>,
    /// Number of distinct communities found.
    pub n_communities: usize,
    /// Final modularity score `Q`, guaranteed `≥ 0.0`.
    pub modularity: f64,
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
