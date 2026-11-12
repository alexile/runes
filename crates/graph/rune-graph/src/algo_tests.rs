#![allow(
    clippy::many_single_char_names,
    reason = "short names keep the graph fixtures readable"
)]

use crate::{Graph, algo, props};

#[allow(
    clippy::many_single_char_names,
    reason = "short names keep the graph fixtures readable"
)]
fn weighted_graph() -> (
    Graph,
    crate::NodeId,
    crate::NodeId,
    crate::NodeId,
    crate::NodeId,
) {
    //  a -1-> b -4-> d
    //  a -6-> c -2-> d
    // shortest weighted: a→b→d = 5, a→c→d = 8
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let c = g.add_node(&[], props! {});
    let d = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! { "w" => 1.0_f64 }).unwrap();
    g.add_edge(a, c, "E", props! { "w" => 6.0_f64 }).unwrap();
    g.add_edge(b, d, "E", props! { "w" => 4.0_f64 }).unwrap();
    g.add_edge(c, d, "E", props! { "w" => 2.0_f64 }).unwrap();
    (g, a, b, c, d)
}

// ── Dijkstra ──────────────────────────────────────────────────────────────────

#[allow(
    clippy::many_single_char_names,
    reason = "short names keep the graph fixtures readable"
)]
#[test]
fn dijkstra_distances_are_correct() {
    let (g, a, b, c, d) = weighted_graph();
    let dist = algo::dijkstra(&g, a, "w");
    assert_eq!(dist[&a], 0.0);
    assert_eq!(dist[&b], 1.0);
    assert_eq!(dist[&c], 6.0);
    assert_eq!(dist[&d], 5.0); // via a→b→d
}

#[test]
fn dijkstra_unreachable_node_not_in_map() {
    let (g, _, _, _, d) = weighted_graph();
    let dist = algo::dijkstra(&g, d, "w");
    // d has no outgoing edges in this graph
    assert_eq!(dist.len(), 1);
    assert_eq!(dist[&d], 0.0);
}

#[test]
fn dijkstra_default_weight_is_one() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {}); // no "w" property
    g.add_edge(a, b, "E", props! {}).unwrap();
    let dist = algo::dijkstra(&g, a, "w");
    assert_eq!(dist[&b], 1.0);
}

// ── Shortest weighted path ────────────────────────────────────────────────────

#[test]
fn shortest_weighted_path_finds_optimal_route() {
    let (g, a, b, _, d) = weighted_graph();
    let (dist, path) = algo::shortest_weighted_path(&g, a, d, "w").unwrap();
    assert_eq!(dist, 5.0);
    assert_eq!(path, vec![a, b, d]);
}

#[test]
fn shortest_weighted_path_no_route_returns_none() {
    let (g, _, _, _, d) = weighted_graph();
    let a = crate::NodeId::from(0);
    assert!(algo::shortest_weighted_path(&g, d, a, "w").is_none());
}

#[test]
fn shortest_weighted_path_self_is_zero() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let (dist, path) = algo::shortest_weighted_path(&g, a, a, "w").unwrap();
    assert_eq!(dist, 0.0);
    assert_eq!(path, vec![a]);
}

// ── Connected components ──────────────────────────────────────────────────────

#[test]
fn weakly_connected_two_components() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let c = g.add_node(&[], props! {}); // isolated
    g.add_edge(a, b, "E", props! {}).unwrap();
    let comps = algo::weakly_connected_components(&g);
    assert_eq!(comps.len(), 2);
    assert_eq!(comps[0].len(), 2);
    assert_eq!(comps[1].len(), 1);
    assert!(comps[1].contains(&c));
}

#[test]
fn weakly_connected_all_in_one() {
    let (g, _, _, _, _) = weighted_graph();
    let comps = algo::weakly_connected_components(&g);
    assert_eq!(comps.len(), 1);
    assert_eq!(comps[0].len(), 4);
}

#[test]
fn weakly_connected_empty_graph() {
    let g = Graph::new();
    assert_eq!(
        algo::weakly_connected_components(&g),
        [] as [Vec<crate::NodeId>; 0]
    );
}

// ── Topological sort ──────────────────────────────────────────────────────────

#[test]
fn topological_sort_dag() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let c = g.add_node(&[], props! {});
    g.add_edge(a, b, "D", props! {}).unwrap();
    g.add_edge(b, c, "D", props! {}).unwrap();
    let order = algo::topological_sort(&g).unwrap();
    assert_eq!(order[0], a);
    assert_eq!(*order.last().unwrap(), c);
}

#[test]
fn topological_sort_cycle_returns_none() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    g.add_edge(b, a, "E", props! {}).unwrap(); // cycle
    assert!(algo::topological_sort(&g).is_none());
}

#[test]
fn topological_sort_single_node() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let order = algo::topological_sort(&g).unwrap();
    assert_eq!(order, vec![a]);
}

// ── Topological sort (relaxed) ────────────────────────────────────────────────

#[test]
fn topological_sort_relaxed_acyclic_matches_strict() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let c = g.add_node(&[], props! {});
    g.add_edge(a, b, "D", props! {}).unwrap();
    g.add_edge(b, c, "D", props! {}).unwrap();
    let relaxed = algo::topological_sort_relaxed(&g);
    let strict = algo::topological_sort(&g).unwrap();
    assert_eq!(relaxed, strict);
}

#[test]
fn topological_sort_relaxed_cycle_returns_all_nodes() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let c = g.add_node(&[], props! {}); // isolated — in-degree 0
    g.add_edge(a, b, "E", props! {}).unwrap();
    g.add_edge(b, a, "E", props! {}).unwrap(); // cycle between a and b

    let order = algo::topological_sort_relaxed(&g);
    assert_eq!(order.len(), 3);
    // c has in-degree 0 so Kahn's emits it first, then the cyclic pair follows
    assert_eq!(order[0], c);
    assert!(order.contains(&a));
    assert!(order.contains(&b));
}

#[test]
fn topological_sort_relaxed_full_cycle_returns_all_nodes() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    g.add_edge(b, a, "E", props! {}).unwrap();
    let order = algo::topological_sort_relaxed(&g);
    assert_eq!(order.len(), 2);
}

// ── PageRank ──────────────────────────────────────────────────────────────────

#[test]
fn page_rank_hub_scores_higher() {
    let mut g = Graph::new();
    let hub = g.add_node(&[], props! {});
    let l1 = g.add_node(&[], props! {});
    let l2 = g.add_node(&[], props! {});
    let l3 = g.add_node(&[], props! {});
    g.add_edge(l1, hub, "L", props! {}).unwrap();
    g.add_edge(l2, hub, "L", props! {}).unwrap();
    g.add_edge(l3, hub, "L", props! {}).unwrap();
    let scores = algo::page_rank(&g, 0.85, 100);
    assert!(scores[&hub] > scores[&l1]);
    assert!(scores[&hub] > scores[&l2]);
    assert!(scores[&hub] > scores[&l3]);
}

#[test]
fn page_rank_scores_sum_to_approx_one() {
    let (g, _, _, _, _) = weighted_graph();
    let scores = algo::page_rank(&g, 0.85, 100);
    let total: f64 = scores.values().sum();
    assert!((total - 1.0).abs() < 1e-9);
}

#[test]
fn page_rank_empty_graph() {
    let g = Graph::new();
    assert!(algo::page_rank(&g, 0.85, 50).is_empty());
}

// ── Degree ────────────────────────────────────────────────────────────────────

#[allow(
    clippy::many_single_char_names,
    reason = "short names keep the graph fixtures readable"
)]
#[test]
fn in_out_degree_correct() {
    let (g, a, b, c, d) = weighted_graph();
    assert_eq!(algo::out_degree(&g, a), 2);
    assert_eq!(algo::in_degree(&g, a), 0);
    assert_eq!(algo::out_degree(&g, b), 1);
    assert_eq!(algo::in_degree(&g, b), 1);
    assert_eq!(algo::out_degree(&g, d), 0);
    assert_eq!(algo::in_degree(&g, d), 2);
    let _ = c; // referenced in graph setup
}

#[test]
fn degree_missing_node_returns_zero() {
    let g = Graph::new();
    let phantom = crate::NodeId::from(999);
    assert_eq!(algo::in_degree(&g, phantom), 0);
    assert_eq!(algo::out_degree(&g, phantom), 0);
}

// ── Dijkstra edge cases ───────────────────────────────────────────────────────

#[test]
fn dijkstra_missing_start_returns_empty_map() {
    // Regression: a start node absent from the graph used to be reported at
    // distance 0.
    let g = Graph::new();
    let phantom = crate::NodeId::from(7);
    assert!(algo::dijkstra(&g, phantom, "w").is_empty());
}

#[test]
fn dijkstra_picks_cheaper_parallel_edge_and_int_weights() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! { "w" => 9_i64 }).unwrap();
    g.add_edge(a, b, "E", props! { "w" => 3_i64 }).unwrap();
    let dist = algo::dijkstra(&g, a, "w");
    assert_eq!(dist[&b], 3.0);
}

#[test]
fn dijkstra_zero_weight_edges_and_self_loops() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let c = g.add_node(&[], props! {});
    g.add_edge(a, a, "E", props! { "w" => 0.0_f64 }).unwrap();
    g.add_edge(a, b, "E", props! { "w" => 0.0_f64 }).unwrap();
    g.add_edge(b, c, "E", props! { "w" => 2.5_f64 }).unwrap();
    let dist = algo::dijkstra(&g, a, "w");
    assert_eq!(dist[&a], 0.0);
    assert_eq!(dist[&b], 0.0);
    assert_eq!(dist[&c], 2.5);
}

#[test]
fn dijkstra_non_numeric_weight_defaults_to_one() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! { "w" => "heavy" }).unwrap();
    assert_eq!(algo::dijkstra(&g, a, "w")[&b], 1.0);
}

#[test]
fn dijkstra_relaxes_later_cheaper_route() {
    // a→d is direct but expensive; a→b→c→d is three cheap hops.
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let c = g.add_node(&[], props! {});
    let d = g.add_node(&[], props! {});
    g.add_edge(a, d, "E", props! { "w" => 10.0_f64 }).unwrap();
    g.add_edge(a, b, "E", props! { "w" => 1.0_f64 }).unwrap();
    g.add_edge(b, c, "E", props! { "w" => 1.0_f64 }).unwrap();
    g.add_edge(c, d, "E", props! { "w" => 1.0_f64 }).unwrap();
    assert_eq!(algo::dijkstra(&g, a, "w")[&d], 3.0);
    let (dist, path) = algo::shortest_weighted_path(&g, a, d, "w").unwrap();
    assert_eq!(dist, 3.0);
    assert_eq!(path, vec![a, b, c, d]);
}

#[test]
fn shortest_weighted_path_missing_endpoint_returns_none() {
    let (g, a, ..) = weighted_graph();
    let phantom = crate::NodeId::from(999);
    assert!(algo::shortest_weighted_path(&g, a, phantom, "w").is_none());
    assert!(algo::shortest_weighted_path(&g, phantom, a, "w").is_none());
}

#[test]
fn algorithms_ignore_removed_nodes() {
    let (mut g, a, b, c, d) = weighted_graph();
    g.remove_node(b).unwrap();
    let dist = algo::dijkstra(&g, a, "w");
    assert!(!dist.contains_key(&b));
    assert_eq!(dist[&d], 8.0);
    assert_eq!(
        algo::shortest_weighted_path(&g, a, d, "w").unwrap().1,
        vec![a, c, d]
    );
    assert_eq!(algo::topological_sort(&g).unwrap().len(), 3);
    assert_eq!(algo::weakly_connected_components(&g).len(), 1);
}

// ── Components / topo order on richer fixtures ───────────────────────────────

#[test]
fn weakly_connected_ignores_direction() {
    // a→b←c is one weak component even though no node reaches all others.
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let c = g.add_node(&[], props! {});
    let d = g.add_node(&[], props! {});
    let e = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    g.add_edge(c, b, "E", props! {}).unwrap();
    g.add_edge(e, d, "E", props! {}).unwrap();
    let comps = algo::weakly_connected_components(&g);
    assert_eq!(comps.len(), 2);
    let mut first = comps[0].clone();
    first.sort_unstable();
    assert_eq!(first, vec![a, b, c]);
    let mut second = comps[1].clone();
    second.sort_unstable();
    assert_eq!(second, vec![d, e]);
}

#[test]
fn topological_sort_respects_every_edge_in_diamond() {
    let (g, a, b, c, d) = weighted_graph();
    let order = algo::topological_sort(&g).unwrap();
    let pos = |n| order.iter().position(|&x| x == n).unwrap();
    for (_, e) in g.edges() {
        assert!(pos(e.source()) < pos(e.target()));
    }
    assert_eq!(pos(a), 0);
    assert_eq!(pos(d), 3);
    let _ = (b, c);
}

#[test]
fn topological_sort_self_loop_is_a_cycle() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    g.add_edge(a, a, "E", props! {}).unwrap();
    assert!(algo::topological_sort(&g).is_none());
    assert_eq!(algo::topological_sort_relaxed(&g), vec![a]);
}

#[test]
fn topological_sort_parallel_edges_still_acyclic() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    g.add_edge(a, b, "E", props! {}).unwrap();
    assert_eq!(algo::topological_sort(&g).unwrap(), vec![a, b]);
}

#[test]
fn topological_sort_relaxed_places_downstream_of_cycle_last() {
    // root → (x ⇄ y) → tail: root is the only node Kahn's can emit.
    let mut g = Graph::new();
    let root = g.add_node(&[], props! {});
    let x = g.add_node(&[], props! {});
    let y = g.add_node(&[], props! {});
    let tail = g.add_node(&[], props! {});
    g.add_edge(root, x, "E", props! {}).unwrap();
    g.add_edge(x, y, "E", props! {}).unwrap();
    g.add_edge(y, x, "E", props! {}).unwrap();
    g.add_edge(y, tail, "E", props! {}).unwrap();
    let order = algo::topological_sort_relaxed(&g);
    assert_eq!(order.len(), 4);
    assert_eq!(order[0], root);
    let mut rest = order[1..].to_vec();
    rest.sort_unstable();
    assert_eq!(rest, vec![x, y, tail]);
}

// ── PageRank ──────────────────────────────────────────────────────────────────

#[test]
fn page_rank_symmetric_cycle_is_uniform() {
    let mut g = Graph::new();
    let n: Vec<_> = (0..4).map(|_| g.add_node(&[], props! {})).collect();
    for i in 0..4 {
        g.add_edge(n[i], n[(i + 1) % 4], "E", props! {}).unwrap();
    }
    let pr = algo::page_rank(&g, 0.85, 30);
    for id in &n {
        assert!((pr[id] - 0.25).abs() < 1e-12);
    }
}

#[test]
fn page_rank_zero_iterations_is_uniform_prior() {
    let (g, a, ..) = weighted_graph();
    let pr = algo::page_rank(&g, 0.85, 0);
    assert!((pr[&a] - 0.25).abs() < 1e-12);
}

#[test]
fn page_rank_known_answer_two_nodes() {
    // a → b, b dangling. Fixed point with d = 0.5:
    //   pa = 0.25 + 0.5 * pb / 2
    //   pb = 0.25 + 0.5 * pa + 0.5 * pb / 2
    // With pa + pb = 1 ⇒ pa = 0.4, pb = 0.6.
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    let pr = algo::page_rank(&g, 0.5, 200);
    assert!((pr[&a] - 0.4).abs() < 1e-9);
    assert!((pr[&b] - 0.6).abs() < 1e-9);
}

// ── Density / diameter / betweenness ──────────────────────────────────────────

#[test]
fn density_small_graphs() {
    let mut g = Graph::new();
    assert_eq!(algo::density(&g), 0.0);
    let a = g.add_node(&[], props! {});
    assert_eq!(algo::density(&g), 0.0);
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    g.add_edge(b, a, "E", props! {}).unwrap();
    assert!((algo::density(&g) - 1.0).abs() < 1e-12);
    let (g, ..) = weighted_graph();
    assert!((algo::density(&g) - 4.0 / 12.0).abs() < 1e-12);
}

#[test]
fn diameter_edge_cases() {
    let mut g = Graph::new();
    assert_eq!(algo::diameter(&g), None);
    let a = g.add_node(&[], props! {});
    assert_eq!(algo::diameter(&g), Some(0));
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    // b cannot reach a: not strongly connected.
    assert_eq!(algo::diameter(&g), None);
    g.add_edge(b, a, "E", props! {}).unwrap();
    assert_eq!(algo::diameter(&g), Some(1));
}

#[test]
fn diameter_uses_shortest_not_longest_route() {
    // Directed 5-ring: going "backwards" one step (i → i-1) takes 4 hops.
    let mut g = Graph::new();
    let n: Vec<_> = (0..5).map(|_| g.add_node(&[], props! {})).collect();
    for i in 0..5 {
        g.add_edge(n[i], n[(i + 1) % 5], "E", props! {}).unwrap();
    }
    assert_eq!(algo::diameter(&g), Some(4));
    // Chords 2→0 and 4→2 shorten several pairs, but 0→4 still needs 4 hops.
    g.add_edge(n[2], n[0], "E", props! {}).unwrap();
    g.add_edge(n[4], n[2], "E", props! {}).unwrap();
    assert_eq!(algo::diameter(&g), Some(4));
    // Chord 0→3 makes 0→4 two hops; the longest shortest path is now 3.
    g.add_edge(n[0], n[3], "E", props! {}).unwrap();
    assert_eq!(algo::diameter(&g), Some(3));
}

#[test]
fn betweenness_path_graph_known_values() {
    // a → b → c: only (a, c) routes through b. Normalised by (n-1)(n-2) = 2.
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let c = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    g.add_edge(b, c, "E", props! {}).unwrap();
    let bc = algo::betweenness_centrality(&g);
    assert!((bc[&a]).abs() < 1e-12);
    assert!((bc[&b] - 0.5).abs() < 1e-12);
    assert!((bc[&c]).abs() < 1e-12);
}

#[test]
fn betweenness_splits_credit_across_equal_paths() {
    // Diamond s → {x, y} → t: each middle node carries half of (s, t).
    let mut g = Graph::new();
    let s = g.add_node(&[], props! {});
    let x = g.add_node(&[], props! {});
    let y = g.add_node(&[], props! {});
    let t = g.add_node(&[], props! {});
    g.add_edge(s, x, "E", props! {}).unwrap();
    g.add_edge(s, y, "E", props! {}).unwrap();
    g.add_edge(x, t, "E", props! {}).unwrap();
    g.add_edge(y, t, "E", props! {}).unwrap();
    let bc = algo::betweenness_centrality(&g);
    let norm = 6.0; // (4-1)(4-2)
    assert!((bc[&x] - 0.5 / norm).abs() < 1e-12);
    assert!((bc[&y] - 0.5 / norm).abs() < 1e-12);
    assert!(bc[&s].abs() < 1e-12);
    assert!(bc[&t].abs() < 1e-12);
}

#[test]
fn betweenness_empty_and_tiny_graphs() {
    let mut g = Graph::new();
    assert!(algo::betweenness_centrality(&g).is_empty());
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    let bc = algo::betweenness_centrality(&g);
    assert_eq!(bc.len(), 2);
    assert!(bc.values().all(|v| *v == 0.0));
}

// ── Components, cycles, centrality ───────────────────────────────────────────

#[test]
fn scc_known_example() {
    // a ⇄ b → c ⇄ d, e isolated
    let mut g = Graph::new();
    let [a, b, c, d, e] = [(); 5].map(|()| g.add_node(&[], props! {}));
    for (u, v) in [(a, b), (b, a), (b, c), (c, d), (d, c)] {
        g.add_edge(u, v, "E", props! {}).unwrap();
    }
    let mut comps = algo::strongly_connected_components(&g);
    for c in &mut comps {
        c.sort_unstable();
    }
    comps.sort();
    assert_eq!(comps, vec![vec![a, b], vec![c, d], vec![e]]);
}

#[test]
fn scc_handles_long_chains_without_recursion() {
    let mut g = Graph::new();
    let first = g.add_node(&[], props! {});
    let mut prev = first;
    for _ in 0..50_000 {
        let n = g.add_node(&[], props! {});
        g.add_edge(prev, n, "E", props! {}).unwrap();
        prev = n;
    }
    g.add_edge(prev, first, "E", props! {}).unwrap();
    let comps = algo::strongly_connected_components(&g);
    assert_eq!(comps.len(), 1);
    assert_eq!(comps[0].len(), 50_001);
}

#[test]
fn toposort_is_deterministic_and_cycle_is_ordered() {
    let mut g = Graph::new();
    let [a, b, c, d] = [(); 4].map(|()| g.add_node(&[], props! {}));
    g.add_edge(a, c, "E", props! {}).unwrap();
    g.add_edge(b, c, "E", props! {}).unwrap();
    assert_eq!(algo::toposort(&g).unwrap(), vec![a, b, d, c]);

    g.add_edge(c, d, "E", props! {}).unwrap();
    g.add_edge(d, b, "E", props! {}).unwrap();
    let cycle = algo::toposort(&g).unwrap_err();
    let nodes = cycle.nodes().to_vec();
    assert_eq!(nodes.len(), 3);
    let start = nodes.iter().position(|&n| n == b).unwrap();
    let rotated: Vec<_> = nodes[start..]
        .iter()
        .chain(&nodes[..start])
        .copied()
        .collect();
    assert_eq!(rotated, vec![b, c, d]);
    assert!(cycle.to_string().starts_with("graph has a cycle"));
    assert_eq!(algo::find_cycle(&g).map(|c| c.len()), Some(3));
}

#[test]
fn degree_centrality_values() {
    use crate::Direction;
    let mut g = Graph::new();
    let [a, b, c] = [(); 3].map(|()| g.add_node(&[], props! {}));
    g.add_edge(a, b, "E", props! {}).unwrap();
    g.add_edge(a, c, "E", props! {}).unwrap();
    let out = algo::degree_centrality(&g, Direction::Outgoing);
    assert!((out[&a] - 1.0).abs() < 1e-12);
    assert!(out[&b].abs() < 1e-12);
    let both = algo::degree_centrality(&g, Direction::Both);
    assert!((both[&b] - 0.5).abs() < 1e-12);

    let mut single = Graph::new();
    let only = single.add_node(&[], props! {});
    assert!(algo::degree_centrality(&single, Direction::Both)[&only].abs() < 1e-12);
}

#[test]
fn page_rank_known_values_with_dangling_node() {
    // a → b with b dangling, damping 0.5. b's rank is spread over both nodes:
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    let pr = algo::page_rank(&g, 0.5, 200);
    // r_a = 0.25 + 0.25*r_b ; r_b = 0.25 + 0.25*r_b + 0.5*r_a
    // → r_a = 0.4, r_b = 0.6
    assert!((pr[&a] - 0.4).abs() < 1e-9, "{}", pr[&a]);
    assert!((pr[&b] - 0.6).abs() < 1e-9, "{}", pr[&b]);
}
