//! Property tests: every algorithm in `rune-graph` is checked against a
//! brute-force reference (Floyd–Warshall / adjacency-matrix DP) on small
//! random multigraphs with self-loops and parallel edges.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]
#![allow(
    clippy::needless_range_loop,
    clippy::float_cmp,
    reason = "index loops mirror the reference algorithms; small integer sums are exact in f64"
)]

use std::collections::{HashMap, HashSet};

use proptest::prelude::*;
use rune_graph::{Graph, NodeId, algo, props};

const INF: u64 = u64::MAX / 4;

/// A random graph description: node count plus `(src, dst, weight)` edges.
#[derive(Debug, Clone)]
struct Spec {
    n: usize,
    edges: Vec<(usize, usize, u32)>,
}

fn spec() -> impl Strategy<Value = Spec> {
    (1usize..8).prop_flat_map(|n| {
        prop::collection::vec((0..n, 0..n, 0u32..10), 0..20)
            .prop_map(move |edges| Spec { n, edges })
    })
}

fn build(s: &Spec) -> (Graph, Vec<NodeId>) {
    let mut g = Graph::new();
    let ids: Vec<NodeId> = (0..s.n).map(|_| g.add_node(&[], props! {})).collect();
    for &(u, v, w) in &s.edges {
        g.add_edge(ids[u], ids[v], "E", props! { "w" => i64::from(w) })
            .unwrap();
    }
    (g, ids)
}

/// All-pairs shortest distances; `unit` ignores weights (hop count).
fn floyd(s: &Spec, unit: bool) -> Vec<Vec<u64>> {
    let mut d = vec![vec![INF; s.n]; s.n];
    for i in 0..s.n {
        d[i][i] = 0;
    }
    for &(u, v, w) in &s.edges {
        let w = if unit { 1 } else { u64::from(w) };
        if u != v {
            d[u][v] = d[u][v].min(w);
        }
    }
    for k in 0..s.n {
        for i in 0..s.n {
            for j in 0..s.n {
                if d[i][k] + d[k][j] < d[i][j] {
                    d[i][j] = d[i][k] + d[k][j];
                }
            }
        }
    }
    d
}

/// Edge multiplicities `m[u][v]`.
fn multiplicity(s: &Spec) -> Vec<Vec<u64>> {
    let mut m = vec![vec![0u64; s.n]; s.n];
    for &(u, v, _) in &s.edges {
        m[u][v] += 1;
    }
    m
}

fn is_acyclic(s: &Spec) -> bool {
    let d = floyd(s, true);
    // A cycle exists iff some edge u→v has v reaching u (covers self-loops).
    s.edges.iter().all(|&(u, v, _)| d[v][u] == INF)
}

fn index_of(ids: &[NodeId]) -> HashMap<NodeId, usize> {
    ids.iter().enumerate().map(|(i, &id)| (id, i)).collect()
}

#[allow(clippy::cast_precision_loss, reason = "test values are tiny integers")]
const fn as_f64(x: u64) -> f64 {
    x as f64
}

proptest! {
    #[test]
    fn dijkstra_matches_floyd_warshall(s in spec(), src in 0usize..8) {
        let (g, ids) = build(&s);
        let src = src % s.n;
        let d = floyd(&s, false);
        let got = algo::dijkstra(&g, ids[src], "w");
        for t in 0..s.n {
            if d[src][t] == INF {
                prop_assert!(!got.contains_key(&ids[t]));
            } else {
                prop_assert_eq!(got[&ids[t]], as_f64(d[src][t]));
            }
        }
    }

    #[test]
    fn shortest_weighted_path_is_a_real_optimal_path(s in spec(), a in 0usize..8, b in 0usize..8) {
        let (g, ids) = build(&s);
        let (a, b) = (a % s.n, b % s.n);
        let d = floyd(&s, false);
        match algo::shortest_weighted_path(&g, ids[a], ids[b], "w") {
            None => prop_assert_eq!(d[a][b], INF),
            Some((dist, path)) => {
                prop_assert_eq!(dist, as_f64(d[a][b]));
                prop_assert_eq!(path.first(), Some(&ids[a]));
                prop_assert_eq!(path.last(), Some(&ids[b]));
                // Each hop uses a real edge and the cheapest hops sum to `dist`.
                let idx = index_of(&ids);
                let mut total = 0u64;
                for w in path.windows(2) {
                    let (u, v) = (idx[&w[0]], idx[&w[1]]);
                    let best = s.edges.iter()
                        .filter(|e| e.0 == u && e.1 == v)
                        .map(|e| u64::from(e.2))
                        .min();
                    prop_assert!(best.is_some(), "hop {u}->{v} is not an edge");
                    total += best.unwrap_or(0);
                }
                prop_assert_eq!(as_f64(total), dist);
            }
        }
    }

    #[test]
    fn bfs_shortest_path_matches_hop_distance(s in spec(), a in 0usize..8, b in 0usize..8) {
        let (g, ids) = build(&s);
        let (a, b) = (a % s.n, b % s.n);
        let d = floyd(&s, true);
        let path = g.shortest_path(ids[a], ids[b]);
        prop_assert_eq!(g.has_path(ids[a], ids[b]), d[a][b] != INF);
        match path {
            None => prop_assert_eq!(d[a][b], INF),
            Some(p) => {
                prop_assert_eq!(p.len() as u64 - 1, d[a][b]);
                for w in p.windows(2) {
                    prop_assert!(g.neighbors(w[0]).any(|x| x == w[1]));
                }
            }
        }
    }

    #[test]
    fn bfs_and_dfs_visit_exactly_the_reachable_set(s in spec(), src in 0usize..8) {
        let (g, ids) = build(&s);
        let src = src % s.n;
        let d = floyd(&s, true);
        let idx = index_of(&ids);
        let reachable: HashSet<NodeId> =
            (0..s.n).filter(|&t| d[src][t] != INF).map(|t| ids[t]).collect();

        let bfs = g.bfs(ids[src]);
        let dfs = g.dfs(ids[src]);
        for order in [&bfs, &dfs] {
            prop_assert_eq!(order.first(), Some(&ids[src]));
            let set: HashSet<NodeId> = order.iter().copied().collect();
            prop_assert_eq!(set.len(), order.len(), "duplicate visit");
            prop_assert_eq!(&set, &reachable);
            // Every visited node after the first has an already-visited predecessor.
            for (i, &v) in order.iter().enumerate().skip(1) {
                prop_assert!(order[..i].iter().any(|&u| g.neighbors(u).any(|x| x == v)));
            }
        }
        // BFS emits nodes in non-decreasing hop distance.
        let hops: Vec<u64> = bfs.iter().map(|v| d[src][idx[v]]).collect();
        prop_assert!(hops.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn topological_sorts_are_consistent(s in spec()) {
        let (g, ids) = build(&s);
        let idx = index_of(&ids);
        let acyclic = is_acyclic(&s);
        let strict = algo::topological_sort(&g);
        prop_assert_eq!(strict.is_some(), acyclic);
        let relaxed = algo::topological_sort_relaxed(&g);
        let mut sorted = relaxed.clone();
        sorted.sort_unstable();
        prop_assert_eq!(sorted, ids, "relaxed order is not a permutation");
        if let Some(order) = strict {
            // Ties are broken by hash order, so compare the edge constraint
            // rather than the exact sequence.
            for candidate in [&order, &relaxed] {
                let pos: HashMap<usize, usize> =
                    candidate.iter().enumerate().map(|(p, id)| (idx[id], p)).collect();
                for &(u, v, _) in &s.edges {
                    prop_assert!(pos[&u] < pos[&v]);
                }
            }
        }
    }

    #[test]
    fn weak_components_match_undirected_reachability(s in spec()) {
        let (g, ids) = build(&s);
        let idx = index_of(&ids);
        let mut undirected = s.clone();
        undirected.edges.extend(s.edges.iter().map(|&(u, v, w)| (v, u, w)));
        let d = floyd(&undirected, true);
        let comps = algo::weakly_connected_components(&g);
        prop_assert!(comps.windows(2).all(|w| w[0].len() >= w[1].len()));
        prop_assert_eq!(comps.iter().map(Vec::len).sum::<usize>(), s.n);
        for comp in &comps {
            for a in comp {
                for b in comp {
                    prop_assert!(d[idx[a]][idx[b]] != INF);
                }
            }
        }
        // Distinct components are mutually unreachable.
        for (i, c1) in comps.iter().enumerate() {
            for c2 in &comps[i + 1..] {
                prop_assert!(d[idx[&c1[0]]][idx[&c2[0]]] == INF);
            }
        }
    }

    #[test]
    fn page_rank_is_a_probability_distribution(s in spec(), iters in 0usize..40) {
        let (g, _) = build(&s);
        let pr = algo::page_rank(&g, 0.85, iters);
        prop_assert_eq!(pr.len(), s.n);
        let total: f64 = pr.values().sum();
        prop_assert!((total - 1.0).abs() < 1e-9, "sum = {total}");
        prop_assert!(pr.values().all(|&x| x > 0.0));
    }

    #[test]
    fn diameter_and_density_match_reference(s in spec()) {
        let (g, _) = build(&s);
        let d = floyd(&s, true);
        let max = d.iter().flatten().copied().max().unwrap_or(0);
        let expected = if max == INF { None } else { usize::try_from(max).ok() };
        prop_assert_eq!(algo::diameter(&g), expected);
        let density = algo::density(&g);
        if s.n < 2 {
            prop_assert_eq!(density, 0.0);
        } else {
            let want = as_f64(s.edges.len() as u64) / as_f64((s.n * (s.n - 1)) as u64);
            prop_assert!((density - want).abs() < 1e-12);
        }
    }

    #[test]
    fn betweenness_matches_path_counting(s in spec()) {
        let (g, ids) = build(&s);
        let n = s.n;
        let d = floyd(&s, true);
        let m = multiplicity(&s);
        // sigma[a][b]: number of shortest a→b walks, counting parallel edges.
        let mut sigma = vec![vec![0u64; n]; n];
        for a in 0..n {
            sigma[a][a] = 1;
            let mut order: Vec<usize> = (0..n).filter(|&b| d[a][b] != INF).collect();
            order.sort_by_key(|&b| d[a][b]);
            for &b in &order {
                if b == a {
                    continue;
                }
                sigma[a][b] = (0..n)
                    .filter(|&u| u != b && d[a][u] != INF && d[a][u] + 1 == d[a][b])
                    .map(|u| sigma[a][u] * m[u][b])
                    .sum();
            }
        }
        let norm = if n > 2 { as_f64(((n - 1) * (n - 2)) as u64) } else { 1.0 };
        let bc = algo::betweenness_centrality(&g);
        for v in 0..n {
            let mut want = 0.0;
            for a in 0..n {
                for b in 0..n {
                    if a == b || a == v || b == v || d[a][b] == INF {
                        continue;
                    }
                    if d[a][v] != INF && d[v][b] != INF && d[a][v] + d[v][b] == d[a][b] {
                        want += as_f64(sigma[a][v] * sigma[v][b]) / as_f64(sigma[a][b]);
                    }
                }
            }
            want /= norm;
            prop_assert!((bc[&ids[v]] - want).abs() < 1e-9, "node {v}: {} vs {want}", bc[&ids[v]]);
        }
    }
}

proptest! {
    #[test]
    fn strong_components_match_mutual_reachability(s in spec()) {
        let (g, ids) = build(&s);
        let idx = index_of(&ids);
        let d = floyd(&s, true);
        let comps = algo::strongly_connected_components(&g);
        prop_assert!(comps.windows(2).all(|w| w[0].len() >= w[1].len()));
        prop_assert_eq!(comps.iter().map(Vec::len).sum::<usize>(), s.n);
        let comp_of: HashMap<usize, usize> = comps
            .iter()
            .enumerate()
            .flat_map(|(c, nodes)| {
                let idx = &idx;
                nodes.iter().map(move |n| (idx[n], c))
            })
            .collect();
        for a in 0..s.n {
            for b in 0..s.n {
                let mutual = d[a][b] != INF && d[b][a] != INF;
                prop_assert_eq!(comp_of[&a] == comp_of[&b], mutual, "{} {}", a, b);
            }
        }
    }

    #[test]
    fn toposort_orders_edges_or_returns_a_real_cycle(s in spec()) {
        let (g, ids) = build(&s);
        let idx = index_of(&ids);
        match algo::toposort(&g) {
            Ok(order) => {
                prop_assert!(is_acyclic(&s));
                let pos: HashMap<NodeId, usize> =
                    order.iter().enumerate().map(|(p, &id)| (id, p)).collect();
                prop_assert_eq!(pos.len(), s.n);
                for &(u, v, _) in &s.edges {
                    prop_assert!(pos[&ids[u]] < pos[&ids[v]]);
                }
                prop_assert!(!algo::has_cycle(&g));
            }
            Err(cycle) => {
                prop_assert!(!is_acyclic(&s));
                prop_assert!(algo::has_cycle(&g));
                let nodes = cycle.nodes();
                prop_assert!(!nodes.is_empty());
                let distinct: HashSet<_> = nodes.iter().collect();
                prop_assert_eq!(distinct.len(), nodes.len());
                for i in 0..nodes.len() {
                    let (u, v) = (nodes[i], nodes[(i + 1) % nodes.len()]);
                    prop_assert!(
                        s.edges.iter().any(|e| e.0 == idx[&u] && e.1 == idx[&v]),
                        "{u} -> {v} is not an edge"
                    );
                }
            }
        }
    }

    #[test]
    fn lazy_traversals_respect_depth(s in spec(), src in 0usize..8, depth in 0usize..4) {
        use rune_graph::Direction;
        let (g, ids) = build(&s);
        let src = src % s.n;
        let d = floyd(&s, true);
        let got: HashSet<NodeId> = g.bfs_iter(ids[src], Direction::Outgoing).max_depth(depth).collect();
        let want: HashSet<NodeId> = (0..s.n)
            .filter(|&t| d[src][t] != INF && d[src][t] <= depth as u64)
            .map(|t| ids[t])
            .collect();
        prop_assert_eq!(got, want);
        // Walking incoming edges finds exactly the nodes that reach `src`.
        let back: HashSet<NodeId> = g.dfs_iter(ids[src], Direction::Incoming).collect();
        let reach: HashSet<NodeId> = (0..s.n).filter(|&t| d[t][src] != INF).map(|t| ids[t]).collect();
        prop_assert_eq!(back, reach);
    }
}

// ── Mutation invariants ─────────────────────────────────────────────────────

use rune_graph::Value;

const LABELS: [&str; 3] = ["A", "B", "C"];
const KEYS: [&str; 2] = ["k", "j"];

#[derive(Debug, Clone)]
enum Op {
    AddNode(usize, Option<i64>),
    AddEdge(usize, usize),
    RemoveNode(usize),
    RemoveEdge(usize),
    SetProp(usize, usize, i64),
    SetFloat(usize, usize, bool),
    RemoveProp(usize, usize),
    AddLabel(usize, usize),
    RemoveLabel(usize, usize),
    CreateIndex(usize, usize),
    DropIndex(usize, usize),
    Clear,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0usize..3, prop::option::of(0i64..3)).prop_map(|(l, v)| Op::AddNode(l, v)),
        3 => (0usize..64, 0usize..64).prop_map(|(a, b)| Op::AddEdge(a, b)),
        2 => (0usize..64).prop_map(Op::RemoveNode),
        1 => (0usize..64).prop_map(Op::RemoveEdge),
        3 => (0usize..64, 0usize..2, 0i64..3).prop_map(|(n, k, v)| Op::SetProp(n, k, v)),
        1 => (0usize..64, 0usize..2, any::<bool>()).prop_map(|(n, k, neg)| Op::SetFloat(n, k, neg)),
        1 => (0usize..64, 0usize..2).prop_map(|(n, k)| Op::RemoveProp(n, k)),
        2 => (0usize..64, 0usize..3).prop_map(|(n, l)| Op::AddLabel(n, l)),
        2 => (0usize..64, 0usize..3).prop_map(|(n, l)| Op::RemoveLabel(n, l)),
        2 => (0usize..3, 0usize..2).prop_map(|(l, k)| Op::CreateIndex(l, k)),
        1 => (0usize..3, 0usize..2).prop_map(|(l, k)| Op::DropIndex(l, k)),
        1 => Just(Op::Clear),
    ]
}

fn pick<T: Copy>(items: &[T], i: usize) -> Option<T> {
    (!items.is_empty()).then(|| items[i % items.len()])
}

fn run(ops: &[Op]) -> Graph {
    let mut g = Graph::new();
    for op in ops {
        let nodes: Vec<NodeId> = {
            let mut v: Vec<_> = g.nodes().map(|(id, _)| id).collect();
            v.sort_unstable();
            v
        };
        let edges: Vec<rune_graph::EdgeId> = {
            let mut v: Vec<_> = g.edges().map(|(id, _)| id).collect();
            v.sort_unstable();
            v
        };
        match *op {
            Op::AddNode(l, v) => {
                let p = v.map_or_else(|| props! {}, |v| props! { "k" => v });
                g.add_node(&[LABELS[l]], p);
            }
            Op::AddEdge(a, b) => {
                if let (Some(a), Some(b)) = (pick(&nodes, a), pick(&nodes, b)) {
                    g.add_edge(a, b, "E", props! {}).unwrap();
                }
            }
            Op::RemoveNode(n) => {
                if let Some(n) = pick(&nodes, n) {
                    g.remove_node(n).unwrap();
                }
            }
            Op::RemoveEdge(e) => {
                if let Some(e) = pick(&edges, e) {
                    g.remove_edge(e).unwrap();
                }
            }
            Op::SetProp(n, k, v) => {
                if let Some(n) = pick(&nodes, n) {
                    g.set_node_property(n, KEYS[k], Value::Int(v)).unwrap();
                }
            }
            Op::SetFloat(n, k, neg) => {
                if let Some(n) = pick(&nodes, n) {
                    let x = if neg { -0.0 } else { 0.0 };
                    g.set_node_property(n, KEYS[k], Value::Float(x)).unwrap();
                }
            }
            Op::RemoveProp(n, k) => {
                if let Some(n) = pick(&nodes, n) {
                    g.remove_node_property(n, KEYS[k]).unwrap();
                }
            }
            Op::AddLabel(n, l) => {
                if let Some(n) = pick(&nodes, n) {
                    g.add_node_label(n, LABELS[l]).unwrap();
                }
            }
            Op::RemoveLabel(n, l) => {
                if let Some(n) = pick(&nodes, n) {
                    g.remove_node_label(n, LABELS[l]).unwrap();
                }
            }
            Op::CreateIndex(l, k) => {
                g.create_index(LABELS[l], KEYS[k]);
            }
            Op::DropIndex(l, k) => {
                g.drop_index(LABELS[l], KEYS[k]);
            }
            Op::Clear => g.clear(),
        }
    }
    g
}

fn sorted(it: impl Iterator<Item = NodeId>) -> Vec<NodeId> {
    let mut v: Vec<_> = it.collect();
    v.sort_unstable();
    v
}

fn check_invariants(g: &Graph) -> Result<(), TestCaseError> {
    // Adjacency and edge table agree; no edge points at a removed node.
    for (eid, e) in g.edges() {
        prop_assert!(g.contains_node(e.source()) && g.contains_node(e.target()));
        prop_assert!(g.outgoing_edges(e.source()).any(|x| x == eid));
        prop_assert!(g.incoming_edges(e.target()).any(|x| x == eid));
    }
    let adjacency: usize = g.nodes().map(|(n, _)| g.outgoing_edges(n).count()).sum();
    prop_assert_eq!(adjacency, g.edge_count());
    let in_adjacency: usize = g.nodes().map(|(n, _)| g.incoming_edges(n).count()).sum();
    prop_assert_eq!(in_adjacency, g.edge_count());

    // Label index matches a scan.
    for label in LABELS {
        let scan = sorted(g.find_nodes(|n| n.has_label(label)));
        prop_assert_eq!(sorted(g.nodes_with_label(label)), scan);
    }
    prop_assert_eq!(g.edges_with_label("E").count(), g.edge_count());

    // Property lookups (indexed or not) match a scan.
    let probes = [
        Value::Int(0),
        Value::Int(1),
        Value::Int(2),
        Value::Float(0.0),
        Value::Float(-0.0),
        Value::Null,
    ];
    for label in LABELS {
        for key in KEYS {
            for v in &probes {
                let scan = sorted(g.find_nodes(|n| n.has_label(label) && n.get(key) == Some(v)));
                let got = sorted(g.nodes_by_property(label, key, v));
                prop_assert_eq!(got, scan, "{}.{} = {:?}", label, key, v);
            }
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn indexes_and_adjacency_stay_consistent(ops in prop::collection::vec(op(), 0..60)) {
        let g = run(&ops);
        check_invariants(&g)?;
    }

    #[test]
    fn removing_a_node_removes_exactly_its_edges(ops in prop::collection::vec(op(), 0..40), pick_n in 0usize..64) {
        let mut g = run(&ops);
        let nodes = sorted(g.nodes().map(|(id, _)| id));
        let Some(victim) = pick(&nodes, pick_n) else { return Ok(()) };
        let before = g.edge_count();
        let incident: HashSet<_> = g.outgoing_edges(victim).chain(g.incoming_edges(victim)).collect();
        g.remove_node(victim).unwrap();
        prop_assert!(!g.contains_node(victim));
        prop_assert_eq!(g.edge_count(), before - incident.len());
        for e in incident {
            prop_assert!(!g.contains_edge(e));
        }
        prop_assert!(g.edges().all(|(_, e)| e.source() != victim && e.target() != victim));
        check_invariants(&g)?;
    }
}

#[cfg(feature = "persist")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn snapshots_and_jsonl_round_trip(ops in prop::collection::vec(op(), 0..60)) {
        let g = run(&ops);
        let canon = g.to_json().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.bin");
        g.save(&path).unwrap();
        let loaded = Graph::load(&path).unwrap();
        prop_assert_eq!(&loaded.to_json().unwrap(), &canon);
        check_invariants(&loaded)?;

        let from_json = Graph::from_json(&canon).unwrap();
        prop_assert_eq!(&from_json.to_json().unwrap(), &canon);

        let mut lines = Vec::new();
        g.write_jsonl(&mut lines).unwrap();
        let from_lines = Graph::read_jsonl(lines.as_slice()).unwrap();
        check_invariants(&from_lines)?;
        // JSON Lines does not carry the id counters, so compare content only.
        prop_assert_eq!(from_lines.node_count(), g.node_count());
        prop_assert_eq!(from_lines.edge_count(), g.edge_count());
        let mut again = Vec::new();
        from_lines.write_jsonl(&mut again).unwrap();
        prop_assert_eq!(again, lines);
    }
}
