//! Multi-level local-moving engine shared by Leiden and Louvain.
//!
//! Louvain repeats one loop: move nodes greedily between neighbouring
//! communities, collapse each community into a supernode, and start again on
//! the smaller graph from singletons.
//!
//! Leiden follows Traag, Waltman & van Eck (2019): fast local moving with a
//! node queue, then a randomised refinement that splits each community into
//! well-connected sub-communities, then collapse of the refined partition.
//! The next level starts from the unrefined partition rather than from
//! singletons.

use std::collections::{HashMap, VecDeque};

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
    /// Leiden's refinement randomness `θ`; `0` (or anything not positive)
    /// makes refinement greedy. Ignored by Louvain.
    pub randomness: f64,
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

    /// Factor `s` such that merging masses `a` and `b` costs `s · a · b` in
    /// edge-weight units: `γ / 2m` for modularity, `γ` for CPM.
    fn penalty_scale(self, graph: &Graph) -> f64 {
        match self.quality {
            Quality::Modularity if graph.total_weight > 0.0 => {
                self.resolution / (2.0 * graph.total_weight)
            }
            Quality::Modularity => 0.0,
            Quality::Cpm => self.resolution,
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
    let base_graph = Graph::new(n_nodes, edges);
    let mut levels = Levels {
        base: &base_graph,
        objective,
        list: Vec::new(),
        best: 0,
        best_quality: f64::NEG_INFINITY,
    };
    match settings.algorithm {
        Algorithm::Leiden => run_leiden(settings, objective, n_nodes, edges, &mut levels),
        Algorithm::Louvain => run_louvain(settings, objective, n_nodes, edges, &mut levels),
    }

    if levels.list.is_empty() {
        levels.record((0..n_nodes).collect());
    }
    (levels.list, levels.best)
}

/// Levels recorded so far, with the running best.
struct Levels<'a> {
    base: &'a Graph,
    objective: Objective,
    list: Vec<RawLevel>,
    best: usize,
    best_quality: f64,
}

impl Levels<'_> {
    /// Records a contiguous partition of the original nodes unless it equals
    /// the previous level.
    fn record(&mut self, partition: Vec<usize>) {
        if self
            .list
            .last()
            .is_some_and(|last| last.partition == partition)
        {
            return;
        }
        let quality = self.objective.evaluate(self.base, &partition);
        if quality > self.best_quality {
            self.best_quality = quality;
            self.best = self.list.len();
        }
        self.list.push(RawLevel { partition, quality });
    }
}

/// The graph being optimised at one level, plus how its nodes map back to
/// the original ones.
struct LevelGraph {
    graph: Graph,
    /// `node_map[supernode]` = original nodes it stands for.
    node_map: Vec<Vec<usize>>,
}

impl LevelGraph {
    fn base(n_nodes: usize, edges: &[(usize, usize, f64)]) -> Self {
        Self {
            graph: Graph::new(n_nodes, edges),
            node_map: (0..n_nodes).map(|i| vec![i]).collect(),
        }
    }

    /// Collapses every community of `partition` into one supernode.
    fn collapse(&self, partition: &[usize]) -> Self {
        let aggregate = aggregate(&self.graph, partition, &self.node_map);
        Self {
            graph: Graph::new(aggregate.n_nodes, &aggregate.edges)
                .with_self_loops(&aggregate.loops)
                .with_node_sizes(aggregate.sizes),
            node_map: aggregate.node_map,
        }
    }

    /// A partition of this graph's nodes, expressed on the original nodes.
    fn resolve(&self, partition: &[usize], n_nodes: usize) -> Vec<usize> {
        renumber(&resolve_partition(&self.node_map, partition, n_nodes))
    }
}

/// The Louvain loop: local moving from singletons, then collapse the
/// communities, until a level makes no move.
fn run_louvain(
    settings: &Settings,
    objective: Objective,
    n_nodes: usize,
    edges: &[(usize, usize, f64)],
    levels: &mut Levels<'_>,
) {
    let mut rng = Rng::new(settings.seed);
    let mut level = LevelGraph::base(n_nodes, edges);

    for _iteration in 0..settings.max_iter {
        let (local_partition, any_moves) = move_nodes(&level.graph, objective, &mut rng);
        levels.record(level.resolve(&local_partition, n_nodes));

        if !any_moves {
            break;
        }
        level = level.collapse(&local_partition);
        if level.graph.n_nodes == 1 {
            break;
        }
    }
}

/// Leiden as in Traag, Waltman & van Eck (2019), Algorithm A.2, iterated
/// until an iteration leaves the partition unchanged.
///
/// One iteration, starting from a partition `P` of the original graph:
///
/// 1. fast local moving of the current graph's nodes, starting from `P`;
/// 2. stop once every community of `P` is a single node;
/// 3. refine `P` into well-connected sub-communities;
/// 4. collapse the refined partition, and start the next level from `P`
///    (each supernode begins in the community of `P` that contains it).
///
/// `max_iter` caps the total number of local-moving passes over all
/// iterations.
fn run_leiden(
    settings: &Settings,
    objective: Objective,
    n_nodes: usize,
    edges: &[(usize, usize, f64)],
    levels: &mut Levels<'_>,
) {
    let mut rng = Rng::new(settings.seed);
    let mut budget = settings.max_iter;
    let mut current: Vec<usize> = (0..n_nodes).collect();
    let mut ran = false;

    while budget > 0 {
        let (next, finished) = leiden_iteration(
            settings,
            objective,
            n_nodes,
            edges,
            &current,
            &mut budget,
            &mut rng,
            levels,
        );
        let unchanged = next == current;
        current = next;
        ran = true;
        if unchanged || !finished {
            break;
        }
    }

    // Normally every community is a single supernode of the last level, i.e.
    // a refined sub-community, and so connected. Running out of budget, or
    // ending an iteration because nothing could be refined, can leave a
    // disconnected one; splitting it into its components only raises the
    // quality, so the result is always connected.
    if ran {
        levels.record(split_disconnected(levels.base, &current));
        levels.best = levels.list.len() - 1;
    }
}

/// One iteration of Leiden from `start` (a contiguous partition of the
/// original nodes). Returns the resulting partition and whether the
/// iteration finished before the budget ran out.
#[allow(
    clippy::too_many_arguments,
    reason = "private helper threading the run's shared state"
)]
fn leiden_iteration(
    settings: &Settings,
    objective: Objective,
    n_nodes: usize,
    edges: &[(usize, usize, f64)],
    start: &[usize],
    budget: &mut usize,
    rng: &mut Rng,
    levels: &mut Levels<'_>,
) -> (Vec<usize>, bool) {
    let mut level = LevelGraph::base(n_nodes, edges);
    let mut partition = start.to_vec();
    let mut resolved = start.to_vec();

    while *budget > 0 {
        *budget -= 1;
        partition = fast_move_nodes(&level.graph, partition, objective, rng);
        resolved = level.resolve(&partition, n_nodes);
        levels.record(resolved.clone());

        let n_communities = count(&partition);
        if n_communities == level.graph.n_nodes {
            return (resolved, true);
        }

        let mut refined = refine(
            &level.graph,
            &partition,
            objective,
            settings.randomness,
            rng,
        );
        if count(&refined) == level.graph.n_nodes && settings.randomness > 0.0 {
            // Every random draw kept its node alone. Retry greedily before
            // giving up on this level.
            refined = refine(&level.graph, &partition, objective, 0.0, rng);
        }
        if count(&refined) == level.graph.n_nodes {
            // Nothing is worth merging, so collapsing would leave the graph
            // unchanged. End the iteration here; the next one starts again
            // from the original nodes.
            return (resolved, true);
        }
        // Every refined sub-community lies inside one community of `P`.
        let mut initial = vec![0usize; count(&refined)];
        for (&sub, &community) in refined.iter().zip(&partition) {
            initial[sub] = community;
        }
        level = level.collapse(&refined);
        partition = initial;
    }
    (resolved, false)
}

/// Number of communities in a contiguous partition.
fn count(partition: &[usize]) -> usize {
    partition.iter().copied().max().map_or(0, |m| m + 1)
}

/// Splits every community into its connected components. The result is
/// renumbered contiguously.
fn split_disconnected(graph: &Graph, partition: &[usize]) -> Vec<usize> {
    let n = graph.n_nodes;
    let mut out = vec![usize::MAX; n];
    let mut next = 0usize;
    let mut stack = Vec::new();
    for start in 0..n {
        if out[start] != usize::MAX {
            continue;
        }
        out[start] = next;
        stack.push(start);
        while let Some(v) = stack.pop() {
            for &(u, _) in graph.neighbours(v) {
                if out[u] == usize::MAX && partition[u] == partition[v] {
                    out[u] = next;
                    stack.push(u);
                }
            }
        }
        next += 1;
    }
    renumber(&out)
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

/// Scratch space for summing edge weight from one node to each neighbouring
/// community without a hash map.
struct NeighbourWeights {
    weight: Vec<f64>,
    seen: Vec<bool>,
    touched: Vec<usize>,
}

impl NeighbourWeights {
    fn new(n: usize) -> Self {
        Self {
            weight: vec![0.0; n],
            seen: vec![false; n],
            touched: Vec::new(),
        }
    }

    fn add(&mut self, community: usize, w: f64) {
        if !self.seen[community] {
            self.seen[community] = true;
            self.touched.push(community);
        }
        self.weight[community] += w;
    }

    fn clear(&mut self) {
        for &c in &self.touched {
            self.weight[c] = 0.0;
            self.seen[c] = false;
        }
        self.touched.clear();
    }
}

/// Leiden's fast local moving (Traag et al., 2019, Algorithm A.2,
/// `MoveNodesFast`), starting from `partition`.
///
/// Nodes wait in a queue, initially in random order. Each visited node moves
/// to the neighbouring (or an empty) community with the largest strictly
/// positive gain; when it moves, its neighbours outside the new community are
/// queued again. Stops when the queue is empty. Returns a contiguous
/// partition.
fn fast_move_nodes(
    graph: &Graph,
    mut partition: Vec<usize>,
    objective: Objective,
    rng: &mut Rng,
) -> Vec<usize> {
    let n = graph.n_nodes;
    let mass = objective.masses(graph);
    let scale = objective.penalty_scale(graph);

    let mut community_mass = vec![0.0f64; n];
    let mut members = vec![0usize; n];
    for (v, &c) in partition.iter().enumerate() {
        community_mass[c] += mass[v];
        members[c] += 1;
    }
    let mut empty: Vec<usize> = (0..n).rev().filter(|&c| members[c] == 0).collect();

    let mut order: Vec<usize> = (0..n).collect();
    rng.shuffle(&mut order);
    let mut queue: VecDeque<usize> = order.into();
    let mut queued = vec![true; n];
    let mut weights = NeighbourWeights::new(n);

    while let Some(v) = queue.pop_front() {
        queued[v] = false;
        let current = partition[v];
        let m_v = mass[v];
        community_mass[current] -= m_v;
        members[current] -= 1;

        for &(u, w) in graph.neighbours(v) {
            weights.add(partition[u], w);
        }

        let mut best = current;
        let mut best_gain = scale.mul_add(-m_v * community_mass[current], weights.weight[current]);
        for &c in &weights.touched {
            let gain = scale.mul_add(-m_v * community_mass[c], weights.weight[c]);
            if gain > best_gain {
                best = c;
                best_gain = gain;
            }
        }
        // An empty community gains exactly 0. If `v` was alone, its own
        // community is already that option.
        let into_empty = members[current] > 0 && best_gain < 0.0 && !empty.is_empty();
        if into_empty && let Some(&e) = empty.last() {
            best = e;
        }
        weights.clear();

        community_mass[best] += m_v;
        members[best] += 1;
        partition[v] = best;

        if best != current {
            if into_empty {
                empty.pop();
            }
            if members[current] == 0 {
                empty.push(current);
            }
            for &(u, _) in graph.neighbours(v) {
                if !queued[u] && partition[u] != best {
                    queued[u] = true;
                    queue.push_back(u);
                }
            }
        }
    }

    renumber(&partition)
}

/// Leiden refinement (Traag et al., 2019, `RefinePartition` and
/// `MergeNodesSubset`).
///
/// Every node starts as its own sub-community. Within each community `S` of
/// `partition`, the nodes are visited in random order; a node is considered
/// only if it is still a singleton and is well connected to the rest of `S`
/// (`E(v, S − v) ≥ s · ‖v‖ · (‖S‖ − ‖v‖)`, `s` from
/// [`Objective::penalty_scale`]). It may join a neighbouring sub-community
/// `C` of `S` that is itself well connected to `S − C` and whose gain is
/// non-negative, or stay alone. The choice is random with probability
/// proportional to `exp(gain / θ)`, so `θ → 0` approaches the greedy choice.
///
/// Sub-communities only ever grow by adjacent singletons, so each one is
/// connected.
fn refine(
    graph: &Graph,
    partition: &[usize],
    objective: Objective,
    randomness: f64,
    rng: &mut Rng,
) -> Vec<usize> {
    let n = graph.n_nodes;
    let mass = objective.masses(graph);
    let scale = objective.penalty_scale(graph);

    let mut groups: Vec<Vec<usize>> = vec![Vec::new(); count(partition)];
    for (v, &c) in partition.iter().enumerate() {
        groups[c].push(v);
    }

    let mut refined: Vec<usize> = (0..n).collect();
    let mut sub_mass = mass.clone();
    let mut sub_size = vec![1usize; n];
    // Edge weight from each node, and from each sub-community, to the rest of
    // its community of `partition`.
    let mut node_external = vec![0.0f64; n];
    for v in 0..n {
        node_external[v] = graph
            .neighbours(v)
            .iter()
            .filter(|&&(u, _)| partition[u] == partition[v])
            .map(|&(_, w)| w)
            .sum();
    }
    let mut sub_external = node_external.clone();

    let mut weights = NeighbourWeights::new(n);
    let mut candidates: Vec<(usize, f64)> = Vec::new();

    for group in &mut groups {
        if group.len() <= 1 {
            continue;
        }
        let total: f64 = group.iter().map(|&v| mass[v]).sum();
        rng.shuffle(group);

        for &v in group.iter() {
            let own = refined[v];
            let m_v = mass[v];
            if sub_size[own] != 1 || node_external[v] < scale * m_v * (total - m_v) {
                continue;
            }

            for &(u, w) in graph.neighbours(v) {
                if partition[u] == partition[v] && refined[u] != own {
                    weights.add(refined[u], w);
                }
            }

            candidates.clear();
            candidates.push((own, 0.0));
            for &c in &weights.touched {
                let well_connected = sub_external[c] >= scale * sub_mass[c] * (total - sub_mass[c]);
                let gain = scale.mul_add(-m_v * sub_mass[c], weights.weight[c]);
                if well_connected && gain >= 0.0 {
                    candidates.push((c, gain));
                }
            }

            let chosen = choose(&candidates, randomness, rng);
            if chosen != own {
                let w_to_chosen = weights.weight[chosen];
                refined[v] = chosen;
                sub_mass[chosen] += m_v;
                sub_size[chosen] += 1;
                sub_external[chosen] += 2.0f64.mul_add(-w_to_chosen, node_external[v]);
                sub_mass[own] = 0.0;
                sub_size[own] = 0;
                sub_external[own] = 0.0;
            }
            weights.clear();
        }
    }

    renumber(&refined)
}

/// Picks a candidate with probability proportional to `exp(gain / θ)`, or
/// the first one with the largest gain when `θ` is not positive. `candidates`
/// is never empty.
fn choose(candidates: &[(usize, f64)], randomness: f64, rng: &mut Rng) -> usize {
    let mut best = candidates[0];
    for &candidate in &candidates[1..] {
        if candidate.1 > best.1 {
            best = candidate;
        }
    }
    if candidates.len() == 1 || randomness.is_nan() || randomness <= 0.0 {
        return best.0;
    }
    // Shift by the largest gain so the exponentials cannot overflow.
    let total: f64 = candidates
        .iter()
        .map(|&(_, gain)| ((gain - best.1) / randomness).exp())
        .sum();
    let mut target = rng.next_f64() * total;
    for &(c, gain) in candidates {
        target -= ((gain - best.1) / randomness).exp();
        if target < 0.0 {
            return c;
        }
    }
    best.0
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choose_is_greedy_without_randomness() {
        let mut rng = Rng::new(1);
        let candidates = [(3, 0.0), (5, 2.0), (7, 2.0), (9, 1.0)];
        for _ in 0..10 {
            assert_eq!(choose(&candidates, 0.0, &mut rng), 5);
        }
    }

    #[test]
    fn choose_follows_exp_gain_over_theta() {
        let mut rng = Rng::new(9);
        // With θ = 1 and gains 0 and ln 3 the odds are 1 : 3.
        let candidates = [(0, 0.0), (1, 3.0f64.ln())];
        let draws = 20_000;
        let ones = (0..draws)
            .filter(|_| choose(&candidates, 1.0, &mut rng) == 1)
            .count();
        let share = f64::from(u32::try_from(ones).unwrap_or(0)) / f64::from(draws);
        assert!((share - 0.75).abs() < 0.02, "{share}");
        // A tiny θ makes the best gain all but certain.
        assert!((0..100).all(|_| choose(&candidates, 1e-3, &mut rng) == 1));
    }

    #[test]
    fn refined_sub_communities_stay_inside_and_connected() {
        // Two triangles in one community, linked by a single edge, plus an
        // isolated node in the same community.
        let edges = [
            (0, 1, 1.0),
            (1, 2, 1.0),
            (0, 2, 1.0),
            (3, 4, 1.0),
            (4, 5, 1.0),
            (3, 5, 1.0),
            (2, 3, 1.0),
        ];
        let graph = Graph::new(7, &edges);
        let objective = Objective {
            quality: Quality::Modularity,
            resolution: 1.0,
        };
        let partition = vec![0; 7];
        for seed in 0..20 {
            let refined = refine(&graph, &partition, objective, 0.01, &mut Rng::new(seed));
            // The isolated node is never well connected, so it stays alone.
            assert!((0..6).all(|v| refined[v] != refined[6]));
            assert_eq!(split_disconnected(&graph, &refined), refined);
        }
    }
}
