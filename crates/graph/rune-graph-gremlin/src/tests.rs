use rune_graph::{Graph, Value, props};

use crate::{GraphTraversalSource, P};

// ── Test fixture ──────────────────────────────────────────────────────────────

fn social() -> (Graph, [rune_graph::NodeId; 5]) {
    let mut g = Graph::new();
    let alice = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
    let bob = g.add_node(&["Person"], props! { "name" => "Bob",   "age" => 22_i64 });
    let carol = g.add_node(&["Person"], props! { "name" => "Carol", "age" => 35_i64 });
    let acme = g.add_node(&["Company"], props! { "name" => "Acme" });
    let paris = g.add_node(&["City"], props! { "name" => "Paris" });
    g.add_edge(alice, bob, "knows", props! {}).unwrap();
    g.add_edge(alice, carol, "knows", props! {}).unwrap();
    g.add_edge(bob, acme, "works_at", props! {}).unwrap();
    g.add_edge(alice, acme, "founded", props! {}).unwrap();
    g.add_edge(acme, paris, "located_in", props! {}).unwrap();
    (g, [alice, bob, carol, acme, paris])
}

// ── GraphTraversalSource ──────────────────────────────────────────────────────

#[test]
fn v_yields_all_vertices() {
    let (g, _) = social();
    let src = GraphTraversalSource::new(&g);
    assert_eq!(src.v().count(), 5);
}

#[test]
fn v_id_seeds_single_vertex() {
    let (g, [alice, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    assert_eq!(src.v_id(alice).count(), 1);
}

#[test]
fn v_id_missing_yields_empty() {
    let (g, _) = social();
    let src = GraphTraversalSource::new(&g);
    assert_eq!(src.v_id(rune_graph::NodeId::from(9999u64)).count(), 0);
}

#[test]
fn v_ids_filters_missing() {
    let (g, [alice, bob, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    let missing = rune_graph::NodeId::from(9999u64);
    let result = src.v_ids([alice, bob, missing]).count();
    assert_eq!(result, 2);
}

#[test]
fn e_yields_all_edges() {
    let (g, _) = social();
    let src = GraphTraversalSource::new(&g);
    assert_eq!(src.e().count(), 5);
}

// ── Vertex → Vertex steps ─────────────────────────────────────────────────────

#[test]
fn out_any_follows_all_outgoing() {
    let (g, [alice, bob, carol, acme, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    let mut result = src.v_id(alice).out_any().collect();
    result.sort();
    let mut expected = vec![bob, carol, acme];
    expected.sort();
    assert_eq!(result, expected);
}

#[test]
fn out_filtered_by_label() {
    let (g, [alice, bob, carol, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    let mut result = src.v_id(alice).out("knows").collect();
    result.sort();
    let mut expected = vec![bob, carol];
    expected.sort();
    assert_eq!(result, expected);
}

#[test]
fn in_any_follows_all_incoming() {
    let (g, [alice, bob, .., acme, _]) = social();
    let src = GraphTraversalSource::new(&g);
    let mut result = src.v_id(acme).in_any().collect();
    result.sort();
    let mut expected = vec![alice, bob];
    expected.sort();
    assert_eq!(result, expected);
}

#[test]
fn in_filtered_by_label() {
    let (g, [alice, _, _, acme, _]) = social();
    let src = GraphTraversalSource::new(&g);
    let result = src.v_id(acme).in_("founded").collect();
    assert_eq!(result, vec![alice]);
}

#[test]
fn both_finds_neighbours_in_both_directions() {
    let (g, [alice, bob, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    let result = src.v_id(bob).both("knows").collect();
    assert_eq!(result, vec![alice]);
}

#[test]
fn two_hop_traversal_via_repeat_times() {
    let (g, [alice, _, _, acme, paris]) = social();
    let src = GraphTraversalSource::new(&g);
    // Alice --founded--> Acme --located_in--> Paris
    let result = src.v_id(alice).out("founded").out("located_in").collect();
    assert_eq!(result, vec![paris]);
    // Same via repeat_times
    let rt = src
        .v_id(acme)
        .repeat_times(1, super::traversal::VertexTraversal::out_any)
        .collect();
    assert_eq!(rt, vec![paris]);
}

// ── Vertex → Edge steps ───────────────────────────────────────────────────────

#[test]
fn out_e_any_yields_outgoing_edges() {
    let (g, [alice, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    assert_eq!(src.v_id(alice).out_e_any().count(), 3);
}

#[test]
fn out_e_filtered_by_label() {
    let (g, [alice, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    assert_eq!(src.v_id(alice).out_e("knows").count(), 2);
}

#[test]
fn in_e_any_yields_incoming_edges() {
    let (g, [_, _, _, acme, _]) = social();
    let src = GraphTraversalSource::new(&g);
    assert_eq!(src.v_id(acme).in_e_any().count(), 2);
}

// ── Edge → Vertex steps ───────────────────────────────────────────────────────

#[test]
fn out_e_then_in_v_round_trips() {
    let (g, [alice, bob, carol, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    let mut result = src.v_id(alice).out_e("knows").in_v().collect();
    result.sort();
    let mut expected = vec![bob, carol];
    expected.sort();
    assert_eq!(result, expected);
}

#[test]
fn in_e_then_out_v_finds_sources() {
    let (g, [alice, bob, _, acme, _]) = social();
    let src = GraphTraversalSource::new(&g);
    let mut result = src.v_id(acme).in_e_any().out_v().collect();
    result.sort();
    let mut expected = vec![alice, bob];
    expected.sort();
    assert_eq!(result, expected);
}

// ── Filter steps ──────────────────────────────────────────────────────────────

#[test]
fn has_filters_by_exact_property() {
    let (g, [alice, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    let result = src.v().has("name", "Alice").collect();
    assert_eq!(result, vec![alice]);
}

#[test]
fn has_p_gt_filters_numerically() {
    let (g, [alice, _, carol, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    let mut result = src
        .v()
        .has_label("Person")
        .has_p("age", P::gt(25_i64))
        .collect();
    result.sort();
    let mut expected = vec![alice, carol];
    expected.sort();
    assert_eq!(result, expected);
}

#[test]
fn has_p_within_accepts_set() {
    let (g, [alice, _, carol, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    let mut result = src
        .v()
        .has_p("name", P::within(["Alice", "Carol"]))
        .collect();
    result.sort();
    let mut expected = vec![alice, carol];
    expected.sort();
    assert_eq!(result, expected);
}

#[test]
fn has_label_keeps_only_matching_label() {
    let (g, _) = social();
    let src = GraphTraversalSource::new(&g);
    assert_eq!(src.v().has_label("Person").count(), 3);
    assert_eq!(src.v().has_label("Company").count(), 1);
}

#[test]
fn dedup_removes_duplicates() {
    let (g, [alice, bob, carol, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    // All vertices that alice knows, then from each also knows — alice appears twice
    let raw = src.v_id(alice).out("knows").out_any().count();
    let deduped = src.v_id(alice).out("knows").out_any().dedup().count();
    assert!(raw >= deduped);
    let _ = (bob, carol); // used in fixture
}

#[test]
fn limit_caps_output() {
    let (g, _) = social();
    let src = GraphTraversalSource::new(&g);
    assert_eq!(src.v().limit(2).count(), 2);
}

// ── Map / projection steps ────────────────────────────────────────────────────

#[test]
fn values_extracts_property() {
    let (g, _) = social();
    let src = GraphTraversalSource::new(&g);
    let mut names: Vec<_> = src.v().has_label("Person").values("name").collect();
    names.sort_by_key(|v| format!("{v:?}"));
    assert_eq!(
        names,
        vec![
            Value::Str("Alice".into()),
            Value::Str("Bob".into()),
            Value::Str("Carol".into()),
        ]
    );
}

#[test]
fn values_skips_missing_property() {
    let (g, _) = social();
    let src = GraphTraversalSource::new(&g);
    // "age" only present on Person nodes, not Company/City
    assert_eq!(src.v().values("age").count(), 3);
}

#[test]
fn edge_label_step_yields_relation_types() {
    let (g, [alice, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    let mut labels: Vec<_> = src.v_id(alice).out_e_any().label().collect();
    labels.sort_by_key(|v| format!("{v:?}"));
    assert_eq!(
        labels,
        vec![
            Value::Str("founded".into()),
            Value::Str("knows".into()),
            Value::Str("knows".into()),
        ]
    );
}

// ── Repeat steps ──────────────────────────────────────────────────────────────

#[test]
fn repeat_times_zero_is_identity() {
    let (g, [alice, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    let result = src
        .v_id(alice)
        .repeat_times(0, super::traversal::VertexTraversal::out_any)
        .collect();
    assert_eq!(result, vec![alice]);
}

#[test]
fn repeat_until_stops_at_condition() {
    let (g, [alice, _, _, _, paris]) = social();
    let src = GraphTraversalSource::new(&g);
    let result = src
        .v_id(alice)
        .repeat_until(
            super::traversal::VertexTraversal::out_any,
            |g, nid| g.node(nid).is_some_and(|n| n.has_label("City")),
            10,
        )
        .collect();
    assert_eq!(result, vec![paris]);
}

// ── Path tracking ─────────────────────────────────────────────────────────────

#[test]
fn paths_captures_full_route() {
    let (g, [_, _, _, acme, paris]) = social();
    let src = GraphTraversalSource::new(&g);
    let paths = src
        .v_id(acme)
        .paths(super::traversal::VertexTraversal::out_any, 2);
    assert!(paths.iter().any(|p| p == &vec![acme, paris]));
}

// ── Terminal steps ────────────────────────────────────────────────────────────

#[test]
fn next_returns_first_element() {
    let (g, _) = social();
    let src = GraphTraversalSource::new(&g);
    assert!(src.v().next().is_some());
}

#[test]
fn any_returns_true_when_nonempty() {
    let (g, _) = social();
    let src = GraphTraversalSource::new(&g);
    assert!(src.v().has_label("Person").any());
    assert!(!src.v().has_label("Ghost").any());
}

// ── Edge filter steps ─────────────────────────────────────────────────────────

#[test]
fn edge_has_label_filters_edges() {
    let (g, _) = social();
    let src = GraphTraversalSource::new(&g);
    assert_eq!(src.e().has_label("knows").count(), 2);
}

#[test]
fn edge_has_p_filters_by_property() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let c = g.add_node(&[], props! {});
    g.add_edge(a, b, "e", props! { "weight" => 10_i64 })
        .unwrap();
    g.add_edge(a, c, "e", props! { "weight" => 90_i64 })
        .unwrap();

    let src = GraphTraversalSource::new(&g);
    assert_eq!(src.e().has_p("weight", P::gt(50_i64)).count(), 1);
}

// ── P predicate ───────────────────────────────────────────────────────────────

#[test]
fn p_eq_and_neq() {
    assert!(P::eq(5_i64).test(&Value::Int(5)));
    assert!(!P::eq(5_i64).test(&Value::Int(6)));
    assert!(P::neq(5_i64).test(&Value::Int(6)));
}

#[test]
fn p_ordering_predicates() {
    assert!(P::lt(10_i64).test(&Value::Int(5)));
    assert!(!P::lt(10_i64).test(&Value::Int(10)));
    assert!(P::lte(10_i64).test(&Value::Int(10)));
    assert!(P::gt(10_i64).test(&Value::Int(15)));
    assert!(P::gte(10_i64).test(&Value::Int(10)));
}

#[test]
fn p_within_and_without() {
    assert!(P::within([1_i64, 2_i64, 3_i64]).test(&Value::Int(2)));
    assert!(!P::within([1_i64, 2_i64, 3_i64]).test(&Value::Int(9)));
    assert!(P::without([1_i64, 2_i64]).test(&Value::Int(9)));
    assert!(!P::without([1_i64, 2_i64]).test(&Value::Int(1)));
}

#[test]
fn p_cross_numeric_comparison() {
    assert!(P::gt(5_i64).test(&Value::Float(5.5)));
    assert!(!P::gt(5_i64).test(&Value::Float(4.9)));
}

// ── Path tracking: exact results (regression for duplicated dead ends) ───────

#[test]
fn paths_reports_each_prefix_exactly_once() {
    // Regression: dead-end paths were emitted twice (once when found, once
    // when the frontier was flushed).
    let (g, [alice, bob, carol, acme, paris]) = social();
    let src = GraphTraversalSource::new(&g);
    let mut paths = src
        .v_id(alice)
        .paths(super::traversal::VertexTraversal::out_any, 3);
    paths.sort();
    let mut want = vec![
        vec![alice],
        vec![alice, bob],
        vec![alice, carol],
        vec![alice, acme],
        vec![alice, bob, acme],
        vec![alice, acme, paris],
        vec![alice, bob, acme, paris],
    ];
    want.sort();
    assert_eq!(paths, want);
}

#[test]
fn paths_from_sink_is_just_the_seed() {
    let (g, [.., paris]) = social();
    let src = GraphTraversalSource::new(&g);
    let paths = src
        .v_id(paris)
        .paths(super::traversal::VertexTraversal::out_any, 5);
    assert_eq!(paths, vec![vec![paris]]);
}

#[test]
fn paths_depth_zero_and_cycles_are_bounded() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "e", props! {}).unwrap();
    g.add_edge(b, a, "e", props! {}).unwrap();
    let src = GraphTraversalSource::new(&g);
    assert_eq!(
        src.v_id(a)
            .paths(super::traversal::VertexTraversal::out_any, 0),
        vec![vec![a]]
    );
    let paths = src
        .v_id(a)
        .paths(super::traversal::VertexTraversal::out_any, 3);
    assert_eq!(
        paths,
        vec![vec![a], vec![a, b], vec![a, b, a], vec![a, b, a, b]]
    );
}

// ── Step pipeline on the fixture graph ────────────────────────────────────────

#[test]
fn pipeline_preserves_order_and_multiplicity() {
    let (g, [alice, bob, carol, acme, _]) = social();
    let src = GraphTraversalSource::new(&g);
    // Alice's out-edges in insertion order: bob, carol, acme.
    assert_eq!(src.v_id(alice).out_any().collect(), vec![bob, carol, acme]);
    // Two hops from alice: bob→acme and acme→paris (carol is a dead end).
    assert_eq!(src.v_id(alice).out_any().out_any().count(), 2);
    // acme is reached both directly and via bob: duplicates survive until dedup.
    let reach: Vec<_> = src
        .v_ids([alice, bob])
        .out_any()
        .filter(move |_, n| n == acme)
        .collect();
    assert_eq!(reach, vec![acme, acme]);
    assert_eq!(
        src.v_ids([alice, bob])
            .out_any()
            .dedup()
            .filter(move |_, n| n == acme)
            .count(),
        1
    );
}

#[test]
fn both_any_counts_in_and_out_edges() {
    let (g, [alice, bob, _, acme, _]) = social();
    let src = GraphTraversalSource::new(&g);
    // acme: in from bob and alice, out to paris.
    assert_eq!(src.v_id(acme).both_any().count(), 3);
    // bob: in from alice, out to acme — outgoing first.
    assert_eq!(src.v_id(bob).both_any().collect(), vec![acme, alice]);
}

#[test]
fn repeat_until_respects_max_depth() {
    let (g, [alice, ..]) = social();
    let src = GraphTraversalSource::new(&g);
    let is_city = |g: &Graph, n| g.node(n).is_some_and(|e| e.has_label("City"));
    // Paris is three hops away only via bob; via acme it is two.
    assert_eq!(
        src.v_id(alice)
            .repeat_until(super::traversal::VertexTraversal::out_any, is_city, 1)
            .count(),
        0
    );
    assert_eq!(
        src.v_id(alice)
            .repeat_until(super::traversal::VertexTraversal::out_any, is_city, 2)
            .count(),
        1
    );
}

#[test]
fn repeat_until_terminates_on_cycles() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "e", props! {}).unwrap();
    g.add_edge(b, a, "e", props! {}).unwrap();
    let src = GraphTraversalSource::new(&g);
    let hits = src
        .v_id(a)
        .repeat_until(
            super::traversal::VertexTraversal::out_any,
            |_, _| false,
            usize::MAX,
        )
        .collect();
    assert_eq!(hits, Vec::<rune_graph::NodeId>::new());
}

#[test]
fn has_p_ranges_partition_numeric_nodes() {
    let (g, _) = social();
    let src = GraphTraversalSource::new(&g);
    let lt = src.v().has_p("age", P::lt(30_i64)).count();
    let gte = src.v().has_p("age", P::gte(30_i64)).count();
    let with_age = src
        .v()
        .filter(|g, n| g.node(n).is_some_and(|e| e.get("age").is_some()))
        .count();
    assert_eq!(lt + gte, with_age);
    assert_eq!((lt, gte), (1, 2));
    // Strings never compare with numbers.
    assert_eq!(src.v().has_p("name", P::gt(0_i64)).count(), 0);
}

#[test]
fn edge_values_and_limit_compose() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    for w in [3_i64, 1, 2] {
        g.add_edge(a, b, "r", props! { "w" => w }).unwrap();
    }
    let src = GraphTraversalSource::new(&g);
    let ws = src.v_id(a).out_e("r").values("w").collect();
    assert_eq!(ws, vec![Value::Int(3), Value::Int(1), Value::Int(2)]);
    assert_eq!(src.v_id(a).out_e("r").limit(2).count(), 2);
    assert_eq!(
        src.v_id(a)
            .out_e("r")
            .has_p("w", P::gte(2_i64))
            .in_v()
            .count(),
        2
    );
}
