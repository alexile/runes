//! Multi-level local-moving engine shared by Leiden and Louvain.
//!
//! Both algorithms repeat the same loop: move nodes greedily between
//! neighbouring communities, collapse each community into a supernode, and
//! start again on the smaller graph. Leiden adds a refinement step between
//! moving and collapsing, and collapses the refined (always connected)
//! sub-communities instead of the raw ones.

use std::collections::HashMap;

use crate::Quality;
use crate::graph::{self, Graph};
use crate::rng::Rng;

/// Which of the two algorithms the engine runs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Leiden,
    Louvain,
}

/// Settings for one run of the engine.
pub struct Settings {
    pub algorithm: Algorithm,
    pub quality: Quality,
    pub resolution: f64,
    pub max_iter: usize,
    pub seed: u64,
}

/// One recorded level: a partition of the original nodes and its quality.
pub struct RawLevel {
    pub partition: Vec<usize>,
    pub quality: f64,
}

/// The objective being optimised, with its resolution.
#[derive(Clone, Copy)]
struct Objective {
    quality: Quality,
    resolution: f64,
}

impl Objective {
    /// Per-node "mass" that enters the penalty term: weighted degree for
    /// modularity, node size for CPM.
    fn masses(self, graph: &Graph) -> Vec<f64> {
        match self.quality {
            Quality::Modularity => graph.degree.clone(),
            Quality::Cpm => graph.node_size.clone(),
        }
    }

    /// Gain from moving an isolated node of mass `mass_v` into a community of
    /// mass `mass_c` to which it is joined by edge weight `k_v_to_c`.
    #[inline]
    fn gain(self, k_v_to_c: f64, mass_v: f64, mass_c: f64, two_m: f64) -> f64 {
        match self.quality {
            Quality::Modularity => delta_q(k_v_to_c, mass_v, mass_c, two_m, self.resolution),
            Quality::Cpm => (self.resolution * mass_v).mul_add(-mass_c, k_v_to_c),
        }
    }

    /// Quality of a contiguous partition of the original graph.
    fn evaluate(self, base: &Graph, partition: &[usize]) -> f64 {
        match self.quality {
            Quality::Modularity => graph::modularity(base, partition, self.resolution),
            Quality::Cpm => graph::cpm(base, partition, self.resolution),
        }
    }
}

/// Runs the engine on a graph with at least one node and in-range indices.
///
/// Returns every distinct level in order (finest first) and the index of the
/// best one. The level list is never empty.
pub fn run(
    settings: &Settings,
    n_nodes: usize,
    edges: &[(usize, usize, f64)],
) -> (Vec<RawLevel>, usize) {
    let objective = Objective {
        quality: settings.quality,
        resolution: settings.resolution,
    };
    let mut rng = Rng::new(settings.seed);
    let base_graph = Graph::new(n_nodes, edges);

    // `node_map[supernode]` = list of original nodes it represents.
    let mut node_map: Vec<Vec<usize>> = (0..n_nodes).map(|i| vec![i]).collect();
    let mut current_edges: Vec<(usize, usize, f64)> = edges.to_vec();
    // Weight collapsed inside each supernode, kept as a self-loop so that
    // supernode degrees (and hence modularity gains) stay correct.
    let mut current_loops: Vec<f64> = vec![0.0; n_nodes];
    let mut current_sizes: Vec<f64> = vec![1.0; n_nodes];
    let mut current_n = n_nodes;

    let mut levels: Vec<RawLevel> = Vec::new();
    let mut best = 0usize;
    let mut best_quality = f64::NEG_INFINITY;

    for _iteration in 0..settings.max_iter {
        let graph = Graph::new(current_n, &current_edges)
            .with_self_loops(&current_loops)
            .with_node_sizes(std::mem::take(&mut current_sizes));

        let (local_partition, any_moves) = move_nodes(&graph, objective, &mut rng);

        let full_partition = renumber(&resolve_partition(&node_map, &local_partition, n_nodes));
        if levels
            .last()
            .is_none_or(|last| last.partition != full_partition)
        {
            let quality = objective.evaluate(&base_graph, &full_partition);
            if quality > best_quality {
                best_quality = quality;
                best = levels.len();
            }
            levels.push(RawLevel {
                partition: full_partition,
                quality,
            });
        }

        if !any_moves {
            break;
        }

        let collapse_by = match settings.algorithm {
            Algorithm::Leiden => refine(&graph, &local_partition, objective, &mut rng),
            Algorithm::Louvain => local_partition,
        };

        let aggregate = aggregate(&graph, &collapse_by, &node_map);
        node_map = aggregate.node_map;
        current_edges = aggregate.edges;
        current_loops = aggregate.loops;
        current_sizes = aggregate.sizes;
        current_n = aggregate.n_nodes;

        if current_n == 1 {
            break;
        }
    }

    if levels.is_empty() {
        let partition: Vec<usize> = (0..n_nodes).collect();
        let quality = objective.evaluate(&base_graph, &partition);
        levels.push(RawLevel { partition, quality });
    }

    (levels, best)
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

/// Renumbers community ids to be contiguous from `0`, in order of first
/// appearance. Ids may be arbitrary `usize` values.
pub fn renumber(partition: &[usize]) -> Vec<usize> {
    let mut remap: HashMap<usize, usize> = HashMap::new();
    partition
        .iter()
        .map(|&c| {
            let next = remap.len();
            *remap.entry(c).or_insert(next)
        })
        .collect()
}

/// Local moving: repeatedly move each node to the neighbouring community with
/// the largest positive gain until no node moves.
///
/// Returns `(partition, any_moves)` where `any_moves` is `true` if at least one
/// node moved. The partition uses contiguous community ids from `0`.
fn move_nodes(graph: &Graph, objective: Objective, rng: &mut Rng) -> (Vec<usize>, bool) {
    let n = graph.n_nodes;
    let two_m = 2.0 * graph.total_weight;
    let mass = objective.masses(graph);

    let mut partition: Vec<usize> = (0..n).collect();
    let mut community_mass = mass.clone();

    let mut node_order: Vec<usize> = (0..n).collect();
    rng.shuffle(&mut node_order);

    let mut ever_moved = false;

    loop {
        let mut moved = false;

        for &v in &node_order {
            let current_community = partition[v];
            let m_v = mass[v];

            community_mass[current_community] -= m_v;

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
            let mut best_delta = objective.gain(0.0, m_v, 0.0, two_m);

            for (candidate_community, k_v_to_c) in community_weights {
                let delta =
                    objective.gain(k_v_to_c, m_v, community_mass[candidate_community], two_m);
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
            community_mass[best_community] += m_v;
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

/// Leiden refinement: within each community of `coarse_partition`, start every
/// node as its own sub-community and greedily merge it into a neighbouring
/// sub-community of the same coarse community when that strictly improves the
/// objective. Every refined sub-community is therefore connected.
fn refine(
    graph: &Graph,
    coarse_partition: &[usize],
    objective: Objective,
    rng: &mut Rng,
) -> Vec<usize> {
    let n = graph.n_nodes;
    let two_m = 2.0 * graph.total_weight;
    let mass = objective.masses(graph);

    let n_communities = coarse_partition.iter().copied().max().map_or(n, |m| m + 1);

    let mut community_members: Vec<Vec<usize>> = vec![Vec::new(); n_communities];
    for v in 0..n {
        community_members[coarse_partition[v]].push(v);
    }

    let mut sub_partition: Vec<usize> = (0..n).collect();
    let mut sub_mass: Vec<f64> = mass.clone();

    for members in &community_members {
        if members.len() <= 1 {
            continue;
        }

        let mut order = members.clone();
        rng.shuffle(&mut order);

        for &v in &order {
            let current_sub = sub_partition[v];
            let m_v = mass[v];

            sub_mass[current_sub] -= m_v;

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
                let delta = objective.gain(k_v_to_s, m_v, sub_mass[candidate_sub], two_m);
                if delta > best_delta {
                    best_delta = delta;
                    best_sub = candidate_sub;
                }
            }

            sub_partition[v] = best_sub;
            sub_mass[best_sub] += m_v;
        }
    }

    renumber(&sub_partition)
}

/// The collapsed graph produced by [`aggregate`].
struct Aggregate {
    n_nodes: usize,
    edges: Vec<(usize, usize, f64)>,
    /// Weight of the edges collapsed inside each supernode.
    loops: Vec<f64>,
    /// Number of original nodes inside each supernode.
    sizes: Vec<f64>,
    /// Original nodes inside each supernode.
    node_map: Vec<Vec<usize>>,
}

/// Collapses every community of `partition` into one supernode.
fn aggregate(graph: &Graph, partition: &[usize], node_map: &[Vec<usize>]) -> Aggregate {
    let n_super = partition.iter().copied().max().map_or(0, |m| m + 1);

    let mut new_map: Vec<Vec<usize>> = vec![Vec::new(); n_super];
    let mut sizes = vec![0.0f64; n_super];
    for (v, &community) in partition.iter().enumerate() {
        new_map[community].extend_from_slice(&node_map[v]);
        sizes[community] += graph.node_size[v];
    }

    let mut edge_map: HashMap<(usize, usize), f64> = HashMap::new();
    let mut loops = vec![0.0f64; n_super];

    for v in 0..graph.n_nodes {
        let sv = partition[v];
        loops[sv] += graph.self_loop(v);
        for &(nb, w) in graph.neighbours(v) {
            let snb = partition[nb];
            if sv == snb {
                // Seen once from each endpoint.
                loops[sv] += w / 2.0;
                continue;
            }
            let key = if sv < snb { (sv, snb) } else { (snb, sv) };
            *edge_map.entry(key).or_insert(0.0) += w;
        }
    }

    // Each undirected pair was counted twice (once per direction).
    let edges: Vec<(usize, usize, f64)> = edge_map
        .into_iter()
        .map(|((u, v), w)| (u, v, w / 2.0))
        .collect();

    Aggregate {
        n_nodes: n_super,
        edges,
        loops,
        sizes,
        node_map: new_map,
    }
}
