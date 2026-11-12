use rune_graph::{Graph, Value, props};

use crate::{NodeFilter, Pattern, RelFilter, chain, match_pattern};

fn social_graph() -> (
    Graph,
    rune_graph::NodeId,
    rune_graph::NodeId,
    rune_graph::NodeId,
) {
    let mut g = Graph::new();
    let alice = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
    let bob = g.add_node(&["Person"], props! { "name" => "Bob",   "age" => 25_i64 });
    let acme = g.add_node(&["Org"], props! { "name" => "Acme" });
    g.add_edge(alice, bob, "KNOWS", props! {}).unwrap();
    g.add_edge(bob, acme, "WORKS_AT", props! {}).unwrap();
    g.add_edge(alice, acme, "WORKS_AT", props! {}).unwrap();
    (g, alice, bob, acme)
}

// ── NodeFilter::Any ───────────────────────────────────────────────────────────

#[test]
fn any_any_any_returns_all_edges() {
    let (g, _, _, _) = social_graph();
    let hits = match_pattern(
        &g,
        &Pattern {
            from: NodeFilter::Any,
            rel: RelFilter::Any,
            to: NodeFilter::Any,
        },
    );
    assert_eq!(hits.len(), 3);
}

// ── NodeFilter::Id ────────────────────────────────────────────────────────────

#[test]
fn id_filter_on_source() {
    let (g, alice, _, _) = social_graph();
    let hits = match_pattern(
        &g,
        &Pattern {
            from: NodeFilter::Id(alice),
            rel: RelFilter::Any,
            to: NodeFilter::Any,
        },
    );
    assert_eq!(hits.len(), 2); // Alice → Bob, Alice → Acme
}

#[test]
fn id_filter_on_target() {
    let (g, _, _, acme) = social_graph();
    let hits = match_pattern(
        &g,
        &Pattern {
            from: NodeFilter::Any,
            rel: RelFilter::Any,
            to: NodeFilter::Id(acme),
        },
    );
    assert_eq!(hits.len(), 2); // Bob → Acme, Alice → Acme
}

// ── NodeFilter::HasLabel ──────────────────────────────────────────────────────

#[test]
fn label_filter_matches_persons_only() {
    let (g, _, _, _) = social_graph();
    let hits = match_pattern(
        &g,
        &Pattern {
            from: NodeFilter::HasLabel("Person".into()),
            rel: RelFilter::Any,
            to: NodeFilter::Any,
        },
    );
    // Alice → Bob (Person→Person), Alice → Acme (Person→Org), Bob → Acme (Person→Org)
    assert_eq!(hits.len(), 3);
}

#[test]
fn label_filter_on_target_returns_person_targets() {
    let (g, _, _, _) = social_graph();
    let hits = match_pattern(
        &g,
        &Pattern {
            from: NodeFilter::Any,
            rel: RelFilter::Any,
            to: NodeFilter::HasLabel("Person".into()),
        },
    );
    assert_eq!(hits.len(), 1); // only Alice → Bob
}

// ── NodeFilter::Property ──────────────────────────────────────────────────────

#[test]
fn property_filter_finds_alice() {
    let (g, alice, _, _) = social_graph();
    let hits = match_pattern(
        &g,
        &Pattern {
            from: NodeFilter::Property {
                key: "name".into(),
                value: Value::Str("Alice".into()),
            },
            rel: RelFilter::Any,
            to: NodeFilter::Any,
        },
    );
    assert_eq!(hits.len(), 2);
    assert!(hits.iter().all(|m| m.source == alice));
}

#[test]
fn property_filter_no_match() {
    let (g, _, _, _) = social_graph();
    let hits = match_pattern(
        &g,
        &Pattern {
            from: NodeFilter::Property {
                key: "name".into(),
                value: Value::Str("Ghost".into()),
            },
            rel: RelFilter::Any,
            to: NodeFilter::Any,
        },
    );
    assert_eq!(hits, [] as [crate::Match; 0]);
}

// ── RelFilter ─────────────────────────────────────────────────────────────────

#[test]
fn rel_label_filter_knows_only() {
    let (g, alice, bob, _) = social_graph();
    let hits = match_pattern(
        &g,
        &Pattern {
            from: NodeFilter::Any,
            rel: RelFilter::Label("KNOWS".into()),
            to: NodeFilter::Any,
        },
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].source, alice);
    assert_eq!(hits[0].target, bob);
}

#[test]
fn rel_label_filter_works_at_only() {
    let (g, _, _, _) = social_graph();
    let hits = match_pattern(
        &g,
        &Pattern {
            from: NodeFilter::Any,
            rel: RelFilter::Label("WORKS_AT".into()),
            to: NodeFilter::Any,
        },
    );
    assert_eq!(hits.len(), 2);
}

// ── Combined filters ──────────────────────────────────────────────────────────

#[test]
fn combined_person_knows_person() {
    let (g, alice, bob, _) = social_graph();
    let hits = match_pattern(
        &g,
        &Pattern {
            from: NodeFilter::HasLabel("Person".into()),
            rel: RelFilter::Label("KNOWS".into()),
            to: NodeFilter::HasLabel("Person".into()),
        },
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].source, alice);
    assert_eq!(hits[0].target, bob);
}

// ── chain ─────────────────────────────────────────────────────────────────────

#[test]
fn chain_two_hops() {
    let (g, alice, bob, acme) = social_graph();
    let p1 = Pattern {
        from: NodeFilter::Id(alice),
        rel: RelFilter::Label("KNOWS".into()),
        to: NodeFilter::Any,
    };
    let p2 = Pattern {
        from: NodeFilter::Any,
        rel: RelFilter::Label("WORKS_AT".into()),
        to: NodeFilter::Any,
    };
    let paths = chain(&g, &[p1, p2]);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], vec![alice, bob, acme]);
}

#[test]
fn chain_empty_patterns_returns_empty() {
    let (g, _, _, _) = social_graph();
    assert_eq!(chain(&g, &[]), [] as [Vec<rune_graph::NodeId>; 0]);
}

#[test]
fn chain_no_connecting_path() {
    let (g, _, _, acme) = social_graph();
    // Acme has no outgoing edges, so a two-hop from Acme always fails.
    let p1 = Pattern {
        from: NodeFilter::Id(acme),
        rel: RelFilter::Any,
        to: NodeFilter::Any,
    };
    let p2 = Pattern {
        from: NodeFilter::Any,
        rel: RelFilter::Any,
        to: NodeFilter::Any,
    };
    assert_eq!(chain(&g, &[p1, p2]), [] as [Vec<rune_graph::NodeId>; 0]);
}

// ── Empty graph ───────────────────────────────────────────────────────────────

#[test]
fn empty_graph_returns_no_matches() {
    let g = Graph::new();
    let hits = match_pattern(
        &g,
        &Pattern {
            from: NodeFilter::Any,
            rel: RelFilter::Any,
            to: NodeFilter::Any,
        },
    );
    assert_eq!(hits, [] as [crate::Match; 0]);
}

// ── chain: filter semantics on intermediate nodes ─────────────────────────────

#[test]
fn chain_applies_next_patterns_from_filter() {
    // Regression: the `from` filter of every pattern after the first was
    // silently replaced by the previous hop's node id and never checked.
    let (g, alice, _, _) = social_graph();
    let p1 = Pattern {
        from: NodeFilter::Id(alice),
        rel: RelFilter::Any,
        to: NodeFilter::Any,
    };
    // Only continue from Org nodes; Acme has no outgoing edges, and Bob (a
    // Person) must not be used as a stepping stone.
    let p2 = Pattern {
        from: NodeFilter::HasLabel("Org".into()),
        rel: RelFilter::Any,
        to: NodeFilter::Any,
    };
    assert_eq!(chain(&g, &[p1, p2]), [] as [Vec<rune_graph::NodeId>; 0]);
}

#[test]
fn chain_property_filter_on_join_node() {
    let (g, alice, bob, acme) = social_graph();
    let any = || Pattern {
        from: NodeFilter::Any,
        rel: RelFilter::Any,
        to: NodeFilter::Any,
    };
    let via_bob = Pattern {
        from: NodeFilter::Property {
            key: "name".into(),
            value: Value::Str("Bob".into()),
        },
        rel: RelFilter::Label("WORKS_AT".into()),
        to: NodeFilter::Id(acme),
    };
    assert_eq!(chain(&g, &[any(), via_bob]), vec![vec![alice, bob, acme]]);
}

#[test]
fn chain_single_pattern_equals_match_pattern() {
    let (g, ..) = social_graph();
    let p = Pattern {
        from: NodeFilter::HasLabel("Person".into()),
        rel: RelFilter::Any,
        to: NodeFilter::Any,
    };
    let mut from_chain = chain(&g, std::slice::from_ref(&p));
    let mut from_match: Vec<_> = match_pattern(&g, &p)
        .into_iter()
        .map(|m| vec![m.source, m.target])
        .collect();
    from_chain.sort();
    from_match.sort();
    assert_eq!(from_chain, from_match);
}

#[test]
fn chain_follows_cycles_and_parallel_edges() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "e", props! {}).unwrap();
    g.add_edge(a, b, "e", props! {}).unwrap();
    g.add_edge(b, a, "e", props! {}).unwrap();
    let step = || Pattern {
        from: NodeFilter::Id(a),
        rel: RelFilter::Any,
        to: NodeFilter::Any,
    };
    let back = Pattern {
        from: NodeFilter::Any,
        rel: RelFilter::Any,
        to: NodeFilter::Id(a),
    };
    // a ⇒ b (two edges) → a ⇒ b (two edges): 4 distinct edge sequences.
    let paths = chain(&g, &[step(), back, step()]);
    assert_eq!(paths.len(), 4);
    assert!(paths.iter().all(|p| p == &vec![a, b, a, b]));
}

#[test]
fn match_pattern_self_loop_and_removed_edges() {
    let mut g = Graph::new();
    let a = g.add_node(&["L"], props! {});
    let b = g.add_node(&[], props! {});
    let loop_e = g.add_edge(a, a, "self", props! {}).unwrap();
    let gone = g.add_edge(a, b, "x", props! {}).unwrap();
    g.remove_edge(gone).unwrap();
    let any = Pattern {
        from: NodeFilter::Any,
        rel: RelFilter::Any,
        to: NodeFilter::Any,
    };
    let hits = match_pattern(&g, &any);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].edge, loop_e);
    assert_eq!((hits[0].source, hits[0].target), (a, a));
}
