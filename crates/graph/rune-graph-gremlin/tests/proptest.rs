//! Property tests for the Gremlin step pipeline on random multigraphs.
//!
//! Step results are compared against adjacency-matrix references: walk
//! counts for `out`/`repeat_times`/`paths`, degrees for `both`, and set
//! semantics for `dedup` / `limit` / filters.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::collections::{HashMap, HashSet};

use proptest::prelude::*;
use rune_graph::{Graph, NodeId, Value, props};
use rune_graph_gremlin::{GraphTraversalSource, P, VertexTraversal};

#[derive(Debug, Clone)]
struct Spec {
    n: usize,
    ages: Vec<i64>,
    edges: Vec<(usize, usize, bool)>,
}

fn spec() -> impl Strategy<Value = Spec> {
    (1usize..7).prop_flat_map(|n| {
        (
            prop::collection::vec(0i64..5, n),
            prop::collection::vec((0..n, 0..n, any::<bool>()), 0..16),
        )
            .prop_map(move |(ages, edges)| Spec { n, ages, edges })
    })
}

fn build(s: &Spec) -> (Graph, Vec<NodeId>) {
    let mut g = Graph::new();
    let ids: Vec<NodeId> = s
        .ages
        .iter()
        .map(|&age| g.add_node(&["N"], props! { "age" => age }))
        .collect();
    for &(u, v, red) in &s.edges {
        let label = if red { "red" } else { "blue" };
        g.add_edge(ids[u], ids[v], label, props! {}).unwrap();
    }
    (g, ids)
}

/// Number of walks of exactly `k` hops from `src`, per end node.
fn walks(s: &Spec, src: usize, k: usize, label: Option<bool>) -> Vec<u64> {
    let mut cur = vec![0u64; s.n];
    cur[src] = 1;
    for _ in 0..k {
        let mut next = vec![0u64; s.n];
        for &(u, v, red) in &s.edges {
            if label.is_none_or(|l| l == red) {
                next[v] += cur[u];
            }
        }
        cur = next;
    }
    cur
}

fn histogram(ids: &[NodeId], nodes: &[NodeId]) -> Vec<u64> {
    let idx: HashMap<NodeId, usize> = ids.iter().enumerate().map(|(i, &id)| (id, i)).collect();
    let mut h = vec![0u64; ids.len()];
    for n in nodes {
        h[idx[n]] += 1;
    }
    h
}

proptest! {
    #[test]
    fn repeat_times_out_counts_walks(s in spec(), src in 0usize..7, k in 0usize..4) {
        let (g, ids) = build(&s);
        let src = src % s.n;
        let t = GraphTraversalSource::new(&g);
        let got = t.v_id(ids[src]).repeat_times(k, VertexTraversal::out_any).collect();
        prop_assert_eq!(histogram(&ids, &got), walks(&s, src, k, None));
        // Chaining `out` k times is the same as repeat_times(k, out).
        let mut chained = t.v_id(ids[src]);
        for _ in 0..k {
            chained = chained.out_any();
        }
        prop_assert_eq!(chained.collect(), got);
    }

    #[test]
    fn labelled_out_counts_walks(s in spec(), src in 0usize..7, red in any::<bool>()) {
        let (g, ids) = build(&s);
        let src = src % s.n;
        let t = GraphTraversalSource::new(&g);
        let label = if red { "red" } else { "blue" };
        let got = t.v_id(ids[src]).out(label).out(label).collect();
        prop_assert_eq!(histogram(&ids, &got), walks(&s, src, 2, Some(red)));
        // out(label) == out_e(label).in_v()
        let via_edges = t.v_id(ids[src]).out_e(label).in_v().collect();
        prop_assert_eq!(t.v_id(ids[src]).out(label).collect(), via_edges);
    }

    #[test]
    fn in_and_both_match_degrees(s in spec()) {
        let (g, ids) = build(&s);
        let t = GraphTraversalSource::new(&g);
        for (i, &id) in ids.iter().enumerate() {
            let outd = s.edges.iter().filter(|e| e.0 == i).count();
            let ind = s.edges.iter().filter(|e| e.1 == i).count();
            prop_assert_eq!(t.v_id(id).out_any().count(), outd);
            prop_assert_eq!(t.v_id(id).in_any().count(), ind);
            prop_assert_eq!(t.v_id(id).both_any().count(), outd + ind);
            prop_assert_eq!(t.v_id(id).in_e_any().out_v().collect(), t.v_id(id).in_any().collect());
        }
        // Summed over all vertices, out == in == edge count.
        prop_assert_eq!(t.v().out_any().count(), s.edges.len());
        prop_assert_eq!(t.v().in_any().count(), s.edges.len());
        prop_assert_eq!(t.e().count(), s.edges.len());
    }

    #[test]
    fn dedup_and_limit_semantics(s in spec(), k in 0usize..10) {
        let (g, _) = build(&s);
        let t = GraphTraversalSource::new(&g);
        let all = t.v().out_any().out_any().collect();
        let deduped = t.v().out_any().out_any().dedup().collect();
        // dedup keeps first occurrences, in order.
        let mut seen = HashSet::new();
        let want: Vec<NodeId> = all.iter().copied().filter(|n| seen.insert(*n)).collect();
        prop_assert_eq!(&deduped, &want);
        let limited = t.v().out_any().out_any().limit(k).collect();
        prop_assert_eq!(&limited[..], &all[..k.min(all.len())]);
    }

    #[test]
    fn has_p_predicates_agree_with_reference(s in spec(), pivot in 0i64..5) {
        let (g, _) = build(&s);
        let t = GraphTraversalSource::new(&g);
        let count = |f: &dyn Fn(i64) -> bool| s.ages.iter().filter(|&&a| f(a)).count();
        prop_assert_eq!(t.v().has_p("age", P::lt(pivot)).count(), count(&|a| a < pivot));
        prop_assert_eq!(t.v().has_p("age", P::lte(pivot)).count(), count(&|a| a <= pivot));
        prop_assert_eq!(t.v().has_p("age", P::gt(pivot)).count(), count(&|a| a > pivot));
        prop_assert_eq!(t.v().has_p("age", P::gte(pivot)).count(), count(&|a| a >= pivot));
        prop_assert_eq!(t.v().has_p("age", P::eq(pivot)).count(), count(&|a| a == pivot));
        prop_assert_eq!(t.v().has_p("age", P::neq(pivot)).count(), count(&|a| a != pivot));
        prop_assert_eq!(t.v().has("age", pivot).count(), count(&|a| a == pivot));
        prop_assert_eq!(
            t.v().has_p("age", P::within([pivot, pivot + 1])).count()
                + t.v().has_p("age", P::without([pivot, pivot + 1])).count(),
            s.n
        );
        // Int vs Float comparison is numeric.
        let fp = f64::from(i32::try_from(pivot).unwrap_or(0)) + 0.5;
        prop_assert_eq!(t.v().has_p("age", P::gt(fp)).count(), count(&|a| a > pivot));
        prop_assert!(t.v().values("age").collect().iter().all(|v| matches!(v, Value::Int(_))));
        prop_assert_eq!(t.v().values("age").count(), s.n);
    }

    #[test]
    fn paths_count_all_walks_up_to_depth(s in spec(), src in 0usize..7, depth in 0usize..4) {
        let (g, ids) = build(&s);
        let src = src % s.n;
        let t = GraphTraversalSource::new(&g);
        let paths = t.v_id(ids[src]).paths(VertexTraversal::out_any, depth);
        // Expansion stops early once no walk can be extended, and the number
        // of walks of length k is zero from then on, so the total is exact.
        let want: u64 = (0..=depth).map(|k| walks(&s, src, k, None).iter().sum::<u64>()).sum();
        prop_assert_eq!(paths.len() as u64, want);
        for p in &paths {
            prop_assert_eq!(p[0], ids[src]);
            prop_assert!(p.len() <= depth + 1);
            for w in p.windows(2) {
                prop_assert!(g.neighbors(w[0]).any(|x| x == w[1]));
            }
        }
    }
}
