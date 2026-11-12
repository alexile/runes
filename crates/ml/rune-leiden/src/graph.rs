/// Compact adjacency representation for a weighted undirected graph.
///
/// Edges are stored as CSR (compressed sparse row) so neighbour iteration is
/// cache-friendly. Parallel edges supplied at construction time are summed.
pub struct Graph {
    /// Number of nodes.
    pub(crate) n_nodes: usize,
    /// Total weight of all edges (each undirected edge counted once).
    pub(crate) total_weight: f64,
    /// Weighted degree of each node: `degree[v] = Σ w(v, u) + 2 · self_loop[v]`.
    pub(crate) degree: Vec<f64>,
    /// Self-loop weight per node. Always zero for caller-supplied graphs (their
    /// self-loops are ignored); aggregated supernode graphs use it to keep the
    /// weight of the edges collapsed inside each supernode.
    self_loop: Vec<f64>,
    /// Number of original nodes each node stands for. All ones for
    /// caller-supplied graphs; supernodes carry the size of their group. Only
    /// the CPM objective reads it.
    pub(crate) node_size: Vec<f64>,
    /// CSR row-start offsets into `neighbours`; length `n_nodes + 1`.
    row_start: Vec<usize>,
    /// `(neighbour_index, edge_weight)` pairs, sorted by source node.
    neighbours: Vec<(usize, f64)>,
}

impl Graph {
    /// Builds a graph from an undirected edge list.
    ///
    /// `n_nodes` must be strictly greater than every node index in `edges`.
    /// Parallel edges (same `u`, `v` pair) are summed into a single edge.
    pub(crate) fn new(n_nodes: usize, edges: &[(usize, usize, f64)]) -> Self {
        let mut adjacency: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n_nodes];

        for &(u, v, w) in edges {
            if u == v {
                continue;
            }
            adjacency[u].push((v, w));
            adjacency[v].push((u, w));
        }

        for adj in &mut adjacency {
            adj.sort_unstable_by_key(|&(nb, _)| nb);
            let mut merged: Vec<(usize, f64)> = Vec::with_capacity(adj.len());
            for (nb, w) in adj.drain(..) {
                if let Some(last) = merged.last_mut()
                    && last.0 == nb
                {
                    last.1 += w;
                    continue;
                }
                merged.push((nb, w));
            }
            *adj = merged;
        }

        let mut degree = vec![0.0f64; n_nodes];
        let mut total_weight = 0.0f64;
        let mut row_start = vec![0usize; n_nodes + 1];
        let mut neighbours = Vec::new();

        for (v, adj) in adjacency.iter().enumerate() {
            for &(nb, w) in adj {
                degree[v] += w;
                if nb > v {
                    total_weight += w;
                }
                neighbours.push((nb, w));
            }
            row_start[v + 1] = neighbours.len();
        }

        Self {
            n_nodes,
            total_weight,
            degree,
            self_loop: vec![0.0; n_nodes],
            node_size: vec![1.0; n_nodes],
            row_start,
            neighbours,
        }
    }

    /// Adds a self-loop of weight `loops[v]` to each node `v`.
    ///
    /// A self-loop counts once towards the total weight and twice towards its
    /// node's degree, matching the adjacency-matrix convention `A_vv = 2w` used
    /// by modularity.
    pub(crate) fn with_self_loops(mut self, loops: &[f64]) -> Self {
        for ((slot, degree), &w) in self.self_loop.iter_mut().zip(&mut self.degree).zip(loops) {
            *slot += w;
            *degree = 2.0f64.mul_add(w, *degree);
            self.total_weight += w;
        }
        self
    }

    /// Replaces the node sizes (used for aggregated supernode graphs).
    pub(crate) fn with_node_sizes(mut self, sizes: Vec<f64>) -> Self {
        self.node_size = sizes;
        self
    }

    /// Self-loop weight of node `v`.
    pub(crate) fn self_loop(&self, v: usize) -> f64 {
        self.self_loop[v]
    }

    /// Returns an iterator over `(neighbour, weight)` pairs for node `v`.
    pub(crate) fn neighbours(&self, v: usize) -> &[(usize, f64)] {
        &self.neighbours[self.row_start[v]..self.row_start[v + 1]]
    }
}

/// Computes modularity Q for a partition with contiguous community ids.
///
/// `Q = (1/2m) × Σ_{ij} [A_ij − γ × k_i × k_j / (2m)] × δ(c_i, c_j)`
pub fn modularity(graph: &Graph, partition: &[usize], resolution: f64) -> f64 {
    if graph.total_weight == 0.0 {
        return 0.0;
    }
    let two_m = 2.0 * graph.total_weight;

    let n_communities = partition.iter().copied().max().map_or(0, |m| m + 1);
    let mut internal_weight = vec![0.0f64; n_communities];
    let mut community_degree = vec![0.0f64; n_communities];

    for v in 0..graph.n_nodes {
        let cv = partition[v];
        community_degree[cv] += graph.degree[v];
        internal_weight[cv] += graph.self_loop[v];
        for &(nb, w) in graph.neighbours(v) {
            if partition[nb] == cv && nb > v {
                internal_weight[cv] += w;
            }
        }
    }

    let mut q = 0.0f64;
    for c in 0..n_communities {
        let sigma = community_degree[c];
        // (1/2m)·[2·L_c − γ·Σ_c²/(2m)] = (1/m)·[L_c − γ·Σ_c²/(4m)].
        q += internal_weight[c] - resolution * sigma * sigma / (2.0 * two_m);
    }
    q / (two_m / 2.0)
}

/// Computes the Constant Potts Model quality for a partition with contiguous
/// community ids: `H = Σ_c [e_c − γ × n_c (n_c − 1) / 2]`, where `e_c` is the
/// edge weight inside community `c` and `n_c` the total node size in it.
pub fn cpm(graph: &Graph, partition: &[usize], resolution: f64) -> f64 {
    let n_communities = partition.iter().copied().max().map_or(0, |m| m + 1);
    let mut internal_weight = vec![0.0f64; n_communities];
    let mut size = vec![0.0f64; n_communities];

    for v in 0..graph.n_nodes {
        let cv = partition[v];
        size[cv] += graph.node_size[v];
        internal_weight[cv] += graph.self_loop[v];
        for &(nb, w) in graph.neighbours(v) {
            if partition[nb] == cv && nb > v {
                internal_weight[cv] += w;
            }
        }
    }

    internal_weight
        .iter()
        .zip(&size)
        .map(|(&e, &n)| (resolution * n).mul_add(-(n - 1.0) / 2.0, e))
        .sum()
}
