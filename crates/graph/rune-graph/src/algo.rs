use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};

use crate::graph::Graph;
use crate::id::NodeId;
use crate::traverse::Direction;

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Wrapper around f64 that implements `Ord` for use in `BinaryHeap`.
///
/// Treats NaN as greater than everything else (sinks to the bottom of a
/// min-heap). Weights should always be finite in practice.
#[derive(Clone, Copy, PartialEq)]
struct OrdF64(f64);

impl Eq for OrdF64 {}

impl PartialOrd for OrdF64 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrdF64 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .partial_cmp(&other.0)
            .unwrap_or(std::cmp::Ordering::Greater)
    }
}

fn edge_weight(graph: &Graph, eid: crate::id::EdgeId, weight_key: &str) -> f64 {
    graph
        .edge(eid)
        .and_then(|e| e.get(weight_key))
        .and_then(crate::Value::as_f64)
        .unwrap_or(1.0)
}

// ── Public algorithms ─────────────────────────────────────────────────────────

/// Compute shortest distances from `start` to all reachable nodes using
/// Dijkstra's algorithm.
///
/// Edge weights are read from the property named `weight_key`. If an edge does
/// not have that property (or its value is not numeric), a default weight of
/// `1.0` is used. Negative weights are not supported.
///
/// Returns a map from `NodeId` → distance. Nodes unreachable from `start` are
/// not present in the map, and the map is empty if `start` is not in the graph.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let c = g.add_node(&[], props! {});
/// g.add_edge(a, b, "E", props! { "w" => 2.0_f64 }).unwrap();
/// g.add_edge(b, c, "E", props! { "w" => 3.0_f64 }).unwrap();
///
/// let dist = algo::dijkstra(&g, a, "w");
/// assert_eq!(dist[&b], 2.0);
/// assert_eq!(dist[&c], 5.0);
/// ```
#[must_use]
pub fn dijkstra(graph: &Graph, start: NodeId, weight_key: &str) -> HashMap<NodeId, f64> {
    let mut dist: HashMap<NodeId, f64> = HashMap::new();
    if !graph.contains_node(start) {
        return dist;
    }
    // min-heap: (Reverse(distance), node)
    let mut heap: BinaryHeap<(Reverse<OrdF64>, NodeId)> = BinaryHeap::new();

    dist.insert(start, 0.0);
    heap.push((Reverse(OrdF64(0.0)), start));

    while let Some((Reverse(OrdF64(cost)), node)) = heap.pop() {
        if dist.get(&node).copied().unwrap_or(f64::INFINITY) < cost {
            continue;
        }
        for eid in graph.outgoing_edges(node) {
            let Some(edge) = graph.edge(eid) else {
                continue;
            };
            let w = edge_weight(graph, eid, weight_key);
            let next = edge.target();
            let new_cost = cost + w;
            let entry = dist.entry(next).or_insert(f64::INFINITY);
            if new_cost < *entry {
                *entry = new_cost;
                heap.push((Reverse(OrdF64(new_cost)), next));
            }
        }
    }
    dist
}

/// Find the shortest weighted path from `from` to `to`, returning both the
/// total distance and the sequence of nodes (inclusive of endpoints).
///
/// Uses Dijkstra with the same weight logic as [`dijkstra`].
/// Returns `None` if `to` is unreachable from `from`.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let c = g.add_node(&[], props! {});
/// g.add_edge(a, b, "E", props! { "w" => 1.0_f64 }).unwrap();
/// g.add_edge(b, c, "E", props! { "w" => 4.0_f64 }).unwrap();
/// g.add_edge(a, c, "E", props! { "w" => 10.0_f64 }).unwrap();
///
/// let (dist, path) = algo::shortest_weighted_path(&g, a, c, "w").unwrap();
/// assert_eq!(dist, 5.0);
/// assert_eq!(path, vec![a, b, c]);
/// ```
#[must_use]
pub fn shortest_weighted_path(
    graph: &Graph,
    from: NodeId,
    to: NodeId,
    weight_key: &str,
) -> Option<(f64, Vec<NodeId>)> {
    if !graph.contains_node(from) || !graph.contains_node(to) {
        return None;
    }
    if from == to {
        return Some((0.0, vec![from]));
    }

    let mut dist: HashMap<NodeId, f64> = HashMap::new();
    let mut prev: HashMap<NodeId, NodeId> = HashMap::new();
    let mut heap: BinaryHeap<(Reverse<OrdF64>, NodeId)> = BinaryHeap::new();

    dist.insert(from, 0.0);
    heap.push((Reverse(OrdF64(0.0)), from));

    while let Some((Reverse(OrdF64(cost)), node)) = heap.pop() {
        if node == to {
            break;
        }
        if dist.get(&node).copied().unwrap_or(f64::INFINITY) < cost {
            continue;
        }
        for eid in graph.outgoing_edges(node) {
            let Some(edge) = graph.edge(eid) else {
                continue;
            };
            let w = edge_weight(graph, eid, weight_key);
            let next = edge.target();
            let new_cost = cost + w;
            let entry = dist.entry(next).or_insert(f64::INFINITY);
            if new_cost < *entry {
                *entry = new_cost;
                prev.insert(next, node);
                heap.push((Reverse(OrdF64(new_cost)), next));
            }
        }
    }

    let total = *dist.get(&to)?;
    let mut path = vec![to];
    let mut cur = to;
    while let Some(&p) = prev.get(&cur) {
        path.push(p);
        cur = p;
    }
    if path.last() != Some(&from) {
        return None;
    }
    path.reverse();
    Some((total, path))
}

/// Partition the graph into weakly connected components.
///
/// Edges are treated as undirected for this computation. Returns a `Vec` of
/// components, each component being a `Vec` of `NodeId`s. Components with more
/// nodes appear first.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let c = g.add_node(&[], props! {}); // isolated
/// g.add_edge(a, b, "E", props! {}).unwrap();
///
/// let comps = algo::weakly_connected_components(&g);
/// assert_eq!(comps.len(), 2);
/// assert_eq!(comps[0].len(), 2); // {a, b}
/// assert_eq!(comps[1].len(), 1); // {c}
/// ```
#[must_use]
pub fn weakly_connected_components(graph: &Graph) -> Vec<Vec<NodeId>> {
    let mut visited: HashSet<NodeId> = HashSet::new();
    let mut components: Vec<Vec<NodeId>> = Vec::new();

    for (node, _) in graph.nodes() {
        if visited.contains(&node) {
            continue;
        }
        // BFS treating edges as undirected.
        let mut component = Vec::new();
        let mut queue = VecDeque::new();
        visited.insert(node);
        queue.push_back(node);

        while let Some(cur) = queue.pop_front() {
            component.push(cur);
            for neighbor in graph.neighbors(cur).chain(graph.predecessors(cur)) {
                if visited.insert(neighbor) {
                    queue.push_back(neighbor);
                }
            }
        }
        components.push(component);
    }

    components.sort_by_key(|c| std::cmp::Reverse(c.len()));
    components
}

/// Topological sort of a directed acyclic graph using Kahn's algorithm.
///
/// Returns `Some(order)` where nodes with no incoming edges come first.
/// Returns `None` if the graph contains a cycle.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let c = g.add_node(&[], props! {});
/// g.add_edge(a, b, "DEP", props! {}).unwrap();
/// g.add_edge(b, c, "DEP", props! {}).unwrap();
///
/// let order = algo::topological_sort(&g).unwrap();
/// assert_eq!(order[0], a);
/// assert_eq!(*order.last().unwrap(), c);
/// ```
#[must_use]
pub fn topological_sort(graph: &Graph) -> Option<Vec<NodeId>> {
    toposort(graph).ok()
}

/// A directed cycle found by [`toposort`] or [`find_cycle`].
///
/// [`nodes`](Self::nodes) lists the cycle in edge order: each node has an
/// edge to the next, and the last has an edge back to the first. A self-loop
/// is a cycle of one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cycle {
    nodes: Vec<NodeId>,
}

impl Cycle {
    /// The nodes on the cycle, in edge order.
    #[must_use]
    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }
}

impl std::fmt::Display for Cycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("graph has a cycle: ")?;
        for n in &self.nodes {
            write!(f, "{n} -> ")?;
        }
        self.nodes
            .first()
            .map_or(Ok(()), |first| write!(f, "{first}"))
    }
}

impl std::error::Error for Cycle {}

/// Kahn's algorithm. Returns the emitted order and the in-degree left over
/// for nodes stuck behind a cycle.
fn kahn(graph: &Graph) -> (Vec<NodeId>, HashMap<NodeId, usize>) {
    let mut in_degree: HashMap<NodeId, usize> = graph
        .nodes()
        .map(|(id, _)| (id, graph.incoming_edges(id).count()))
        .collect();
    let mut seeds: Vec<NodeId> = in_degree
        .iter()
        .filter(|&(_, d)| *d == 0)
        .map(|(&n, _)| n)
        .collect();
    seeds.sort_unstable();
    let mut queue = VecDeque::from(seeds);
    let mut order = Vec::with_capacity(in_degree.len());
    while let Some(node) = queue.pop_front() {
        order.push(node);
        for next in graph.neighbors(node) {
            if let Some(d) = in_degree.get_mut(&next) {
                *d = d.saturating_sub(1);
                if *d == 0 {
                    queue.push_back(next);
                }
            }
        }
    }
    in_degree.retain(|_, d| *d > 0);
    (order, in_degree)
}

/// Topological sort that reports a concrete cycle when there is one.
///
/// Nodes with no incoming edges come first; ties start in ascending id order.
/// Runs in O(V + E).
///
/// # Errors
///
/// Returns a [`Cycle`] witness if the graph is not a DAG.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let c = g.add_node(&[], props! {});
/// g.add_edge(a, b, "DEP", props! {}).unwrap();
/// g.add_edge(b, c, "DEP", props! {}).unwrap();
/// assert_eq!(algo::toposort(&g).unwrap(), vec![a, b, c]);
///
/// g.add_edge(c, b, "DEP", props! {}).unwrap();
/// let cycle = algo::toposort(&g).unwrap_err();
/// assert_eq!(cycle.nodes().len(), 2);
/// ```
pub fn toposort(graph: &Graph) -> Result<Vec<NodeId>, Cycle> {
    let (order, stuck) = kahn(graph);
    if stuck.is_empty() {
        return Ok(order);
    }
    // Every stuck node has a stuck predecessor, so walking predecessors
    // through stuck nodes must eventually repeat a node.
    let Some(mut cur) = stuck.keys().min().copied() else {
        return Ok(order);
    };
    let mut path: Vec<NodeId> = Vec::new();
    let mut pos: HashMap<NodeId, usize> = HashMap::new();
    loop {
        if let Some(&i) = pos.get(&cur) {
            let mut nodes = path.split_off(i);
            nodes.reverse();
            return Err(Cycle { nodes });
        }
        pos.insert(cur, path.len());
        path.push(cur);
        match graph.predecessors(cur).find(|p| stuck.contains_key(p)) {
            Some(p) => cur = p,
            // Unreachable for a consistent graph; fall back to the stuck set.
            None => {
                return Err(Cycle { nodes: path });
            }
        }
    }
}

/// Return some directed cycle, or `None` if the graph is acyclic.
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// g.add_edge(a, a, "SELF", props! {}).unwrap();
/// assert_eq!(algo::find_cycle(&g), Some(vec![a]));
/// ```
#[must_use]
pub fn find_cycle(graph: &Graph) -> Option<Vec<NodeId>> {
    toposort(graph).err().map(|c| c.nodes)
}

/// `true` if the graph contains a directed cycle (including self-loops).
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// g.add_edge(a, b, "E", props! {}).unwrap();
/// assert!(!algo::has_cycle(&g));
/// g.add_edge(b, a, "E", props! {}).unwrap();
/// assert!(algo::has_cycle(&g));
/// ```
#[must_use]
pub fn has_cycle(graph: &Graph) -> bool {
    !kahn(graph).1.is_empty()
}

/// Partition the graph into strongly connected components (Tarjan's
/// algorithm, iterative so deep graphs cannot overflow the stack).
///
/// Two nodes share a component when each is reachable from the other.
/// Components with more nodes appear first. Runs in O(V + E).
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let c = g.add_node(&[], props! {});
/// g.add_edge(a, b, "E", props! {}).unwrap();
/// g.add_edge(b, a, "E", props! {}).unwrap();
/// g.add_edge(b, c, "E", props! {}).unwrap();
///
/// let comps = algo::strongly_connected_components(&g);
/// assert_eq!(comps.len(), 2);
/// assert_eq!(comps[0].len(), 2); // {a, b}
/// assert_eq!(comps[1], vec![c]);
/// ```
#[must_use]
pub fn strongly_connected_components(graph: &Graph) -> Vec<Vec<NodeId>> {
    struct Frame {
        node: NodeId,
        succ: Vec<NodeId>,
        next: usize,
    }
    let mut index: HashMap<NodeId, usize> = HashMap::new();
    let mut low: HashMap<NodeId, usize> = HashMap::new();
    let mut on_stack: HashSet<NodeId> = HashSet::new();
    let mut stack: Vec<NodeId> = Vec::new();
    let mut components: Vec<Vec<NodeId>> = Vec::new();
    let mut counter = 0usize;

    let mut roots: Vec<NodeId> = graph.nodes().map(|(id, _)| id).collect();
    roots.sort_unstable();
    for root in roots {
        if index.contains_key(&root) {
            continue;
        }
        index.insert(root, counter);
        low.insert(root, counter);
        counter += 1;
        stack.push(root);
        on_stack.insert(root);
        let mut calls = vec![Frame {
            node: root,
            succ: graph.neighbors(root).collect(),
            next: 0,
        }];
        while let Some(frame) = calls.last_mut() {
            let v = frame.node;
            if let Some(&w) = frame.succ.get(frame.next) {
                frame.next += 1;
                if let Some(&iw) = index.get(&w) {
                    if on_stack.contains(&w) {
                        let lv = low.get(&v).copied().unwrap_or(iw);
                        low.insert(v, lv.min(iw));
                    }
                } else {
                    index.insert(w, counter);
                    low.insert(w, counter);
                    counter += 1;
                    stack.push(w);
                    on_stack.insert(w);
                    calls.push(Frame {
                        node: w,
                        succ: graph.neighbors(w).collect(),
                        next: 0,
                    });
                }
                continue;
            }
            calls.pop();
            let lv = low.get(&v).copied().unwrap_or(0);
            if let Some(parent) = calls.last() {
                let lp = low.get(&parent.node).copied().unwrap_or(lv);
                low.insert(parent.node, lp.min(lv));
            }
            if index.get(&v) == Some(&lv) {
                let mut comp = Vec::new();
                while let Some(w) = stack.pop() {
                    on_stack.remove(&w);
                    comp.push(w);
                    if w == v {
                        break;
                    }
                }
                components.push(comp);
            }
        }
    }
    components.sort_by_key(|c| Reverse(c.len()));
    components
}

/// Degree centrality: each node's degree divided by `n - 1`, the largest
/// possible degree without parallel edges. Parallel edges and self-loops are
/// counted, so scores can exceed `1.0` in multigraphs.
///
/// `direction` picks in-degree, out-degree or total degree. Every node scores
/// `0.0` in a graph with fewer than two nodes.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Direction, Graph, algo, props};
///
/// let mut g = Graph::new();
/// let hub = g.add_node(&[], props! {});
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// g.add_edge(a, hub, "E", props! {}).unwrap();
/// g.add_edge(b, hub, "E", props! {}).unwrap();
///
/// let c = algo::degree_centrality(&g, Direction::Incoming);
/// assert_eq!(c[&hub], 1.0);
/// assert_eq!(c[&a], 0.0);
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn degree_centrality(graph: &Graph, direction: Direction) -> HashMap<NodeId, f64> {
    let n = graph.node_count();
    graph
        .nodes()
        .map(|(id, _)| {
            let score = if n < 2 {
                0.0
            } else {
                graph.edges_directed(id, direction).count() as f64 / (n - 1) as f64
            };
            (id, score)
        })
        .collect()
}

/// Hop distances from `start` to every node reachable in `direction`.
///
/// Returns an empty map if `start` is not in the graph.
///
/// ```rust
/// use rune_graph::{Direction, Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// g.add_edge(a, b, "E", props! {}).unwrap();
/// let d = algo::unweighted_distances(&g, b, Direction::Incoming);
/// assert_eq!(d[&a], 1);
/// ```
#[must_use]
pub fn unweighted_distances(
    graph: &Graph,
    start: NodeId,
    direction: Direction,
) -> HashMap<NodeId, usize> {
    let mut it = graph.bfs_iter(start, direction);
    let mut out = HashMap::new();
    while let Some((n, d)) = it.next_with_depth() {
        out.insert(n, d);
    }
    out
}

/// Compute `PageRank` scores for all nodes.
///
/// Uses the standard iterative formula with damping factor `d` for
/// `iterations` steps. Scores converge to a stable distribution over the
/// graph. Higher score = more "important" in the link structure.
///
/// `damping` is typically `0.85`. `iterations` of `50`–`100` is sufficient
/// for most graphs.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let hub  = g.add_node(&[], props! {});
/// let leaf = g.add_node(&[], props! {});
/// g.add_edge(leaf, hub, "LINKS", props! {}).unwrap();
/// g.add_edge(leaf, hub, "LINKS", props! {}).unwrap(); // extra link boosts hub
///
/// let scores = algo::page_rank(&g, 0.85, 50);
/// assert!(scores[&hub] > scores[&leaf]);
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn page_rank(graph: &Graph, damping: f64, iterations: usize) -> HashMap<NodeId, f64> {
    let nodes: Vec<NodeId> = graph.nodes().map(|(id, _)| id).collect();
    let n = nodes.len();
    if n == 0 {
        return HashMap::new();
    }

    let nf = n as f64;
    let out_deg: HashMap<NodeId, usize> = nodes
        .iter()
        .map(|&id| (id, graph.outgoing_edges(id).count()))
        .collect();
    let mut rank: HashMap<NodeId, f64> = nodes.iter().map(|&id| (id, 1.0 / nf)).collect();

    for _ in 0..iterations {
        // Rank held by dangling nodes is spread evenly over every node; sum it
        // once instead of looping over all nodes per dangling node.
        let dangling: f64 = nodes
            .iter()
            .filter(|id| out_deg.get(id).copied().unwrap_or(0) == 0)
            .map(|id| rank.get(id).copied().unwrap_or(0.0))
            .sum();
        let base = damping.mul_add(dangling, 1.0 - damping) / nf;
        let mut new_rank: HashMap<NodeId, f64> = nodes.iter().map(|&id| (id, base)).collect();

        for &node in &nodes {
            let deg = out_deg.get(&node).copied().unwrap_or(0);
            if deg == 0 {
                continue;
            }
            let share = damping * rank.get(&node).copied().unwrap_or(0.0) / deg as f64;
            for target in graph.neighbors(node) {
                *new_rank.entry(target).or_insert(0.0) += share;
            }
        }
        rank = new_rank;
    }
    rank
}

/// Topological sort with cycle tolerance.
///
/// Like [`topological_sort`] but never returns `None`. When a cycle is
/// detected, the remaining cyclic nodes are appended in arbitrary order after
/// all acyclic nodes have been emitted. Useful when an approximate ordering is
/// acceptable — for example, call graphs that may contain mutual recursion.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let c = g.add_node(&[], props! {}); // isolated node, in-degree 0
/// g.add_edge(a, b, "E", props! {}).unwrap();
/// g.add_edge(b, a, "E", props! {}).unwrap(); // cycle between a and b
///
/// let order = algo::topological_sort_relaxed(&g);
/// assert_eq!(order.len(), 3);
/// // c has in-degree 0 so Kahn's emits it first; cyclic pair follows
/// assert_eq!(order[0], c);
/// ```
#[must_use]
pub fn topological_sort_relaxed(graph: &Graph) -> Vec<NodeId> {
    let (mut order, stuck) = kahn(graph);
    let mut rest: Vec<NodeId> = stuck.into_keys().collect();
    rest.sort_unstable();
    order.extend(rest);
    order
}

/// Return the in-degree (number of incoming edges) of `node`.
///
/// Returns `0` if the node does not exist.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// g.add_edge(a, b, "E", props! {}).unwrap();
/// assert_eq!(algo::in_degree(&g, b), 1);
/// assert_eq!(algo::in_degree(&g, a), 0);
/// ```
#[must_use]
pub fn in_degree(graph: &Graph, node: NodeId) -> usize {
    graph.incoming_edges(node).count()
}

/// Return the out-degree (number of outgoing edges) of `node`.
///
/// Returns `0` if the node does not exist.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// g.add_edge(a, b, "E", props! {}).unwrap();
/// assert_eq!(algo::out_degree(&g, a), 1);
/// assert_eq!(algo::out_degree(&g, b), 0);
/// ```
#[must_use]
pub fn out_degree(graph: &Graph, node: NodeId) -> usize {
    graph.outgoing_edges(node).count()
}

/// Edge density of the graph: actual edges divided by the maximum possible.
///
/// For a directed graph with `n` nodes the maximum is `n * (n - 1)`.
/// Returns `0.0` for graphs with fewer than 2 nodes.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// g.add_edge(a, b, "e", props! {}).unwrap();
///
/// // 1 edge out of 2 possible (a→b and b→a)
/// assert!((algo::density(&g) - 0.5).abs() < 1e-9);
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn density(graph: &Graph) -> f64 {
    let n = graph.node_count();
    if n < 2 {
        return 0.0;
    }
    graph.edge_count() as f64 / (n * (n - 1)) as f64
}

/// Graph diameter: the length of the longest shortest path between any two nodes.
///
/// Returns `None` if the graph is empty or is not strongly connected (i.e. at
/// least one pair of nodes has no directed path between them).
///
/// Runs BFS from every node — O(V * (V + E)).
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let c = g.add_node(&[], props! {});
/// g.add_edge(a, b, "e", props! {}).unwrap();
/// g.add_edge(b, c, "e", props! {}).unwrap();
/// g.add_edge(c, a, "e", props! {}).unwrap(); // cycle so every pair reachable
///
/// assert_eq!(algo::diameter(&g), Some(2));
/// ```
#[must_use]
pub fn diameter(graph: &Graph) -> Option<usize> {
    let nodes: Vec<NodeId> = graph.nodes().map(|(id, _)| id).collect();
    if nodes.is_empty() {
        return None;
    }
    let mut max_dist: Option<usize> = Some(0);
    for &start in &nodes {
        let dist = bfs_distances(graph, start);
        for &target in &nodes {
            if target == start {
                continue;
            }
            match dist.get(&target) {
                None => return None, // unreachable pair → no diameter
                Some(&d) => max_dist = Some(max_dist.unwrap_or(0).max(d)),
            }
        }
    }
    max_dist
}

/// Betweenness centrality for every node.
///
/// Measures how often a node lies on the shortest path between two other nodes.
/// Scores are normalised to `[0, 1]` by dividing by `(n-1)(n-2)` (the maximum
/// for a directed graph with `n` nodes).
///
/// Runs BFS from every node — O(V * (V + E)).
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, algo, props};
///
/// let mut g = Graph::new();
/// let hub  = g.add_node(&[], props! {});
/// let a    = g.add_node(&[], props! {});
/// let b    = g.add_node(&[], props! {});
/// g.add_edge(a, hub, "e", props! {}).unwrap();
/// g.add_edge(hub, b, "e", props! {}).unwrap();
///
/// let bc = algo::betweenness_centrality(&g);
/// // Hub lies on the only path from a to b
/// assert!(bc[&hub] > bc[&a]);
/// assert!(bc[&hub] > bc[&b]);
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
pub fn betweenness_centrality(graph: &Graph) -> HashMap<NodeId, f64> {
    let nodes: Vec<NodeId> = graph.nodes().map(|(id, _)| id).collect();
    let n = nodes.len();
    let mut scores: HashMap<NodeId, f64> = nodes.iter().map(|&id| (id, 0.0)).collect();

    for &source in &nodes {
        // BFS to collect shortest-path counts and predecessors.
        let mut dist: HashMap<NodeId, usize> = HashMap::new();
        let mut sigma: HashMap<NodeId, f64> = HashMap::new(); // number of shortest paths
        let mut preds: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        let mut queue = VecDeque::new();
        let mut stack: Vec<NodeId> = Vec::new();

        dist.insert(source, 0);
        sigma.insert(source, 1.0);
        queue.push_back(source);

        while let Some(v) = queue.pop_front() {
            stack.push(v);
            for w in graph.neighbors(v) {
                if !dist.contains_key(&w) {
                    dist.insert(w, dist[&v] + 1);
                    queue.push_back(w);
                }
                if dist[&w] == dist[&v] + 1 {
                    *sigma.entry(w).or_insert(0.0) += sigma.get(&v).copied().unwrap_or(0.0);
                    preds.entry(w).or_default().push(v);
                }
            }
        }

        // Back-propagate dependency.
        let mut delta: HashMap<NodeId, f64> = nodes.iter().map(|&id| (id, 0.0)).collect();
        while let Some(w) = stack.pop() {
            for &v in preds.get(&w).map_or(&[][..], Vec::as_slice) {
                let s_v = sigma.get(&v).copied().unwrap_or(0.0);
                let s_w = sigma.get(&w).copied().unwrap_or(1.0);
                *delta.entry(v).or_insert(0.0) =
                    f64::mul_add(s_v / s_w, 1.0 + delta[&w], *delta.entry(v).or_insert(0.0));
            }
            if w != source {
                *scores.entry(w).or_insert(0.0) += delta[&w];
            }
        }
    }

    // Normalise.
    let norm = if n > 2 {
        ((n - 1) * (n - 2)) as f64
    } else {
        1.0
    };
    for score in scores.values_mut() {
        *score /= norm;
    }
    scores
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// BFS distances from `start` to all reachable nodes.
fn bfs_distances(graph: &Graph, start: NodeId) -> HashMap<NodeId, usize> {
    unweighted_distances(graph, start, Direction::Outgoing)
}
