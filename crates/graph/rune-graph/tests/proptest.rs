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
