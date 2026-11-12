//! Property tests: `match_pattern` and `chain` against brute-force
//! enumeration over random labelled multigraphs.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use proptest::prelude::*;
use rune_graph::{Graph, NodeId, Value, props};
use rune_graph_match::{NodeFilter, Pattern, RelFilter, chain, match_pattern};

const LABELS: [&str; 2] = ["A", "B"];
const RELS: [&str; 2] = ["r", "s"];

#[derive(Debug, Clone)]
struct Spec {
    /// Per node: (label index, `k` property value).
    nodes: Vec<(usize, i64)>,
    /// (src, dst, rel index)
    edges: Vec<(usize, usize, usize)>,
}

fn spec() -> impl Strategy<Value = Spec> {
    (1usize..6).prop_flat_map(|n| {
        (
            prop::collection::vec((0usize..2, 0i64..3), n),
            prop::collection::vec((0..n, 0..n, 0usize..2), 0..14),
        )
            .prop_map(|(nodes, edges)| Spec { nodes, edges })
    })
}

/// A node filter as data, so the reference can evaluate it independently.
#[derive(Debug, Clone)]
enum F {
    Any,
    Id(usize),
    Label(usize),
    Prop(i64),
}

fn filter() -> impl Strategy<Value = F> {
    prop_oneof![
        Just(F::Any),
        (0usize..6).prop_map(F::Id),
        (0usize..2).prop_map(F::Label),
        (0i64..3).prop_map(F::Prop),
    ]
}

fn rel() -> impl Strategy<Value = Option<usize>> {
    prop_oneof![Just(None), (0usize..2).prop_map(Some)]
}

fn build(s: &Spec) -> (Graph, Vec<NodeId>) {
    let mut g = Graph::new();
    let ids: Vec<NodeId> = s
        .nodes
        .iter()
        .map(|&(l, k)| g.add_node(&[LABELS[l]], props! { "k" => k }))
        .collect();
    for &(u, v, r) in &s.edges {
        g.add_edge(ids[u], ids[v], RELS[r], props! {}).unwrap();
    }
    (g, ids)
}

fn to_node_filter(f: &F, ids: &[NodeId]) -> NodeFilter {
    match *f {
        F::Any => NodeFilter::Any,
        // Out-of-range ids map to a node id that does not exist.
        F::Id(i) => NodeFilter::Id(ids.get(i).copied().unwrap_or(NodeId::from(1_000))),
        F::Label(l) => NodeFilter::HasLabel(LABELS[l].into()),
        F::Prop(k) => NodeFilter::Property {
            key: "k".into(),
            value: Value::Int(k),
        },
    }
}

fn accepts(s: &Spec, f: &F, n: usize) -> bool {
    match *f {
        F::Any => true,
        F::Id(i) => i == n,
        F::Label(l) => s.nodes[n].0 == l,
        F::Prop(k) => s.nodes[n].1 == k,
    }
}

fn pattern(f: &F, r: Option<usize>, t: &F, ids: &[NodeId]) -> Pattern {
    Pattern {
        from: to_node_filter(f, ids),
        rel: r.map_or(RelFilter::Any, |r| RelFilter::Label(RELS[r].into())),
        to: to_node_filter(t, ids),
    }
}

type Step = (F, Option<usize>, F);

fn edge_ok(s: &Spec, e: (usize, usize, usize), step: &Step) -> bool {
    accepts(s, &step.0, e.0) && step.1.is_none_or(|r| r == e.2) && accepts(s, &step.2, e.1)
}

proptest! {
    #[test]
    fn match_pattern_matches_brute_force(s in spec(), f in filter(), r in rel(), t in filter()) {
        let (g, ids) = build(&s);
        let step = (f, r, t);
        let mut got: Vec<(NodeId, NodeId)> = match_pattern(&g, &pattern(&step.0, step.1, &step.2, &ids))
            .into_iter()
            .map(|m| {
                let e = g.edge(m.edge).unwrap();
                assert_eq!((e.source(), e.target()), (m.source, m.target));
                (m.source, m.target)
            })
            .collect();
        let mut want: Vec<(NodeId, NodeId)> = s.edges.iter()
            .filter(|&&e| edge_ok(&s, e, &step))
            .map(|&(u, v, _)| (ids[u], ids[v]))
            .collect();
        got.sort();
        want.sort();
        prop_assert_eq!(got, want);
    }

    #[test]
    fn chain_matches_brute_force(
        s in spec(),
        steps in prop::collection::vec((filter(), rel(), filter()), 1..4),
    ) {
        let (g, ids) = build(&s);
        let patterns: Vec<Pattern> =
            steps.iter().map(|(f, r, t)| pattern(f, *r, t, &ids)).collect();
        let mut got = chain(&g, &patterns);

        // Reference: enumerate every edge sequence that satisfies each step.
        let mut want: Vec<Vec<usize>> = Vec::new();
        let mut stack: Vec<Vec<usize>> = s.edges.iter()
            .filter(|&&e| edge_ok(&s, e, &steps[0]))
            .map(|&(u, v, _)| vec![u, v])
            .collect();
        while let Some(path) = stack.pop() {
            let depth = path.len() - 1;
            if depth == steps.len() {
                want.push(path);
                continue;
            }
            let last = path[path.len() - 1];
            for &e in &s.edges {
                if e.0 == last && edge_ok(&s, e, &steps[depth]) {
                    let mut next = path.clone();
                    next.push(e.1);
                    stack.push(next);
                }
            }
        }
        let mut want: Vec<Vec<NodeId>> =
            want.into_iter().map(|p| p.into_iter().map(|i| ids[i]).collect()).collect();
        got.sort();
        want.sort();
        prop_assert_eq!(got, want);
    }
}
