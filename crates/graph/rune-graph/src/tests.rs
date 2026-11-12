#![allow(
    clippy::many_single_char_names,
    reason = "short names keep the graph fixtures readable"
)]

use crate::{Graph, GraphError, Value, props};

fn people_graph() -> (Graph, crate::NodeId, crate::NodeId, crate::NodeId) {
    let mut g = Graph::new();
    let alice = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
    let bob = g.add_node(&["Person"], props! { "name" => "Bob",   "age" => 25_i64 });
    let corp = g.add_node(&["Org"], props! { "name" => "Acme" });
    g.add_edge(alice, bob, "KNOWS", props! { "since" => 2020_i64 })
        .unwrap();
    g.add_edge(alice, corp, "WORKS_AT", props! {}).unwrap();
    g.add_edge(bob, corp, "WORKS_AT", props! {}).unwrap();
    (g, alice, bob, corp)
}

// ── Node CRUD ─────────────────────────────────────────────────────────────────

#[test]
fn add_and_retrieve_node() {
    let mut g = Graph::new();
    let id = g.add_node(&["Animal"], props! { "species" => "cat" });
    let node = g.node(id).unwrap();
    assert!(node.has_label("Animal"));
    assert_eq!(node.get("species"), Some(&Value::Str("cat".into())));
}

#[test]
fn remove_node_also_removes_incident_edges() {
    let (mut g, alice, bob, _) = people_graph();
    // alice has 2 outgoing edges (→bob, →corp); bob has 1 (→corp). Total = 3.
    g.remove_node(alice).unwrap();
    assert!(!g.contains_node(alice));
    // Only bob→corp remains.
    assert_eq!(g.edge_count(), 1);
    // Bob's incoming edge from alice is gone; his outgoing edge to corp remains.
    assert_eq!(g.predecessors(bob).count(), 0);
    assert_eq!(g.neighbors(bob).count(), 1);
}

#[test]
fn remove_nonexistent_node_returns_error() {
    let mut g = Graph::new();
    let err = g.remove_node(crate::NodeId::from(999)).unwrap_err();
    assert_eq!(err, GraphError::NodeNotFound(crate::NodeId::from(999)));
}

#[test]
fn node_mut_can_update_property() {
    let mut g = Graph::new();
    let id = g.add_node(&[], props! { "x" => 1_i64 });
    g.node_mut(id).unwrap().set("x", Value::Int(42));
    assert_eq!(g.node(id).unwrap().get("x"), Some(&Value::Int(42)));
}

#[test]
fn add_label_to_existing_node() {
    let mut g = Graph::new();
    let id = g.add_node(&["A"], props! {});
    g.node_mut(id).unwrap().add_label("B");
    assert!(g.node(id).unwrap().has_label("B"));
}

// ── Edge CRUD ─────────────────────────────────────────────────────────────────

#[test]
fn add_edge_with_properties() {
    let (g, alice, bob, _) = people_graph();
    let eid = g.edges_with_label("KNOWS").next().unwrap();
    let edge = g.edge(eid).unwrap();
    assert_eq!(edge.source(), alice);
    assert_eq!(edge.target(), bob);
    assert_eq!(edge.get("since"), Some(&Value::Int(2020)));
}

#[test]
fn add_edge_to_missing_node_returns_error() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let err = g
        .add_edge(a, crate::NodeId::from(999), "X", props! {})
        .unwrap_err();
    assert!(matches!(err, GraphError::NodeNotFound(_)));
}

#[test]
fn remove_edge_preserves_nodes() {
    let (mut g, alice, _, _) = people_graph();
    let eid = g.edges_with_label("KNOWS").next().unwrap();
    g.remove_edge(eid).unwrap();
    assert!(!g.contains_edge(eid));
    assert!(g.contains_node(alice));
}

#[test]
fn remove_nonexistent_edge_returns_error() {
    let mut g = Graph::new();
    let err = g.remove_edge(crate::EdgeId::from(999)).unwrap_err();
    assert_eq!(err, GraphError::EdgeNotFound(crate::EdgeId::from(999)));
}

#[test]
fn parallel_edges_between_same_nodes() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    g.add_edge(a, b, "TYPE_A", props! {}).unwrap();
    g.add_edge(a, b, "TYPE_B", props! {}).unwrap();
    assert_eq!(g.edge_count(), 2);
    assert_eq!(g.neighbors(a).count(), 2);
}

// ── Traversal ─────────────────────────────────────────────────────────────────

#[test]
fn neighbors_follows_out_edges_only() {
    let (g, alice, _, _) = people_graph();
    let ns: std::collections::HashSet<_> = g.neighbors(alice).collect();
    assert_eq!(ns.len(), 2);
}

#[test]
fn predecessors_follows_in_edges() {
    let (g, _, _, corp) = people_graph();
    let preds: std::collections::HashSet<_> = g.predecessors(corp).collect();
    assert_eq!(preds.len(), 2);
}

#[test]
fn bfs_visits_all_reachable_nodes() {
    let (g, alice, _, _) = people_graph();
    let visited = g.bfs(alice);
    assert_eq!(visited.len(), 3);
    assert_eq!(visited[0], alice);
}

#[test]
fn bfs_from_isolated_node_returns_just_that_node() {
    let mut g = Graph::new();
    let solo = g.add_node(&[], props! {});
    assert_eq!(g.bfs(solo), vec![solo]);
}

#[test]
fn dfs_visits_all_nodes_from_root() {
    let (g, alice, _, _) = people_graph();
    let visited = g.dfs(alice);
    assert_eq!(visited.len(), 3);
    assert_eq!(visited[0], alice);
}

#[test]
fn shortest_path_direct_edge() {
    let (g, alice, bob, _) = people_graph();
    let path = g.shortest_path(alice, bob).unwrap();
    assert_eq!(path, vec![alice, bob]);
}

#[test]
fn shortest_path_two_hops() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let c = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    g.add_edge(b, c, "E", props! {}).unwrap();
    let path = g.shortest_path(a, c).unwrap();
    assert_eq!(path, vec![a, b, c]);
}

#[test]
fn shortest_path_no_route_returns_none() {
    let (g, _, bob, _) = people_graph();
    let corp_to_bob = g.shortest_path(bob, crate::NodeId::from(999));
    assert!(corp_to_bob.is_none());
}

#[test]
fn shortest_path_self_returns_single_node() {
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    assert_eq!(g.shortest_path(a, a), Some(vec![a]));
}

#[test]
fn has_path_true_and_false() {
    let (g, alice, _, corp) = people_graph();
    assert!(g.has_path(alice, corp));
    assert!(!g.has_path(corp, alice));
}

// ── Query helpers ─────────────────────────────────────────────────────────────

#[test]
fn nodes_with_label_filters_correctly() {
    let (g, _, _, _) = people_graph();
    assert_eq!(g.nodes_with_label("Person").count(), 2);
    assert_eq!(g.nodes_with_label("Org").count(), 1);
    assert_eq!(g.nodes_with_label("Missing").count(), 0);
}

#[test]
fn edges_with_label_filters_correctly() {
    let (g, _, _, _) = people_graph();
    assert_eq!(g.edges_with_label("WORKS_AT").count(), 2);
    assert_eq!(g.edges_with_label("KNOWS").count(), 1);
}

#[test]
fn find_nodes_by_property_value() {
    let (g, _, _, _) = people_graph();

    assert_eq!(
        g.find_nodes(|n| matches!(n.get("age"), Some(Value::Int(a)) if *a < 30))
            .count(),
        1
    );
}

// ── Props macro ───────────────────────────────────────────────────────────────

#[test]
fn props_macro_empty() {
    let p = props! {};
    assert!(p.is_empty());
}

#[test]
fn props_macro_mixed_types() {
    let p = props! {
        "s" => "hello",
        "n" => 42_i64,
        "b" => true,
        "f" => 2.5_f64,
    };
    assert_eq!(p["s"], Value::Str("hello".into()));
    assert_eq!(p["n"], Value::Int(42));
    assert_eq!(p["b"], Value::Bool(true));
    assert!(matches!(p["f"], Value::Float(_)));
}

// ── Value conversions ─────────────────────────────────────────────────────────

#[test]
fn value_display() {
    assert_eq!(Value::Null.to_string(), "null");
    assert_eq!(Value::Bool(true).to_string(), "true");
    assert_eq!(Value::Int(7).to_string(), "7");
    assert_eq!(Value::Str("hi".into()).to_string(), "hi");
    assert_eq!(
        Value::List(vec![Value::Int(1), Value::Int(2)]).to_string(),
        "[1, 2]"
    );
}

#[test]
fn value_from_impls() {
    assert_eq!(Value::from(42_i32), Value::Int(42));
    assert_eq!(Value::from(42_u32), Value::Int(42));
    assert_eq!(Value::from(42_usize), Value::Int(42));
    assert_eq!(Value::from(1.5_f32), Value::Float(f64::from(1.5_f32)));
    let v: Value = None::<Value>.into();
    assert_eq!(v, Value::Null);
}

// ── Graph utilities ───────────────────────────────────────────────────────────

#[test]
fn clear_empties_graph() {
    let (mut g, _, _, _) = people_graph();
    g.clear();
    assert!(g.is_empty());
    assert_eq!(g.edge_count(), 0);
}

#[test]
fn node_and_edge_id_display() {
    assert_eq!(crate::NodeId::from(5).to_string(), "N5");
    assert_eq!(crate::EdgeId::from(3).to_string(), "E3");
}

// ── Traversal order on fixture graphs ─────────────────────────────────────────

fn tree() -> (Graph, [crate::NodeId; 5]) {
    //   a → b → d
    //   a → c → e,  plus a back edge e → a
    let mut g = Graph::new();
    let ids: Vec<_> = (0..5).map(|_| g.add_node(&[], props! {})).collect();
    let [a, b, c, d, e] = [ids[0], ids[1], ids[2], ids[3], ids[4]];
    g.add_edge(a, b, "E", props! {}).unwrap();
    g.add_edge(a, c, "E", props! {}).unwrap();
    g.add_edge(b, d, "E", props! {}).unwrap();
    g.add_edge(c, e, "E", props! {}).unwrap();
    g.add_edge(e, a, "E", props! {}).unwrap();
    (g, [a, b, c, d, e])
}

#[test]
fn bfs_order_is_level_by_level_in_adjacency_order() {
    let (g, [a, b, c, d, e]) = tree();
    assert_eq!(g.bfs(a), vec![a, b, c, d, e]);
}

#[test]
fn dfs_order_is_preorder_in_adjacency_order() {
    let (g, [a, b, c, d, e]) = tree();
    assert_eq!(g.dfs(a), vec![a, b, d, c, e]);
    assert_eq!(g.dfs(c), vec![c, e, a, b, d]);
}

#[test]
fn dfs_handles_shared_descendants_once() {
    // a → b → x, a → x: x is reached via b first and never repeated.
    let mut g = Graph::new();
    let a = g.add_node(&[], props! {});
    let b = g.add_node(&[], props! {});
    let x = g.add_node(&[], props! {});
    g.add_edge(a, b, "E", props! {}).unwrap();
    g.add_edge(a, x, "E", props! {}).unwrap();
    g.add_edge(b, x, "E", props! {}).unwrap();
    assert_eq!(g.dfs(a), vec![a, b, x]);
}

#[test]
fn dfs_deep_chain_does_not_overflow_stack() {
    // Regression: DFS was recursive and overflowed the stack on long chains.
    let mut g = Graph::new();
    let first = g.add_node(&[], props! {});
    let mut prev = first;
    for _ in 0..200_000 {
        let next = g.add_node(&[], props! {});
        g.add_edge(prev, next, "E", props! {}).unwrap();
        prev = next;
    }
    let order = g.dfs(first);
    assert_eq!(order.len(), 200_001);
    assert_eq!(order.last(), Some(&prev));
}

#[test]
fn traversals_from_missing_node_are_empty() {
    let g = Graph::new();
    let phantom = crate::NodeId::from(3);
    assert_eq!(g.bfs(phantom), Vec::<crate::NodeId>::new());
    assert_eq!(g.dfs(phantom), Vec::<crate::NodeId>::new());
    assert!(g.shortest_path(phantom, phantom).is_none());
}

#[test]
fn shortest_path_prefers_fewest_hops_over_insertion_order() {
    let (g, [a, _, c, _, e]) = tree();
    assert_eq!(g.shortest_path(a, e), Some(vec![a, c, e]));
    assert_eq!(g.shortest_path(e, c), Some(vec![e, a, c]));
}

#[test]
fn match_triples_wildcards() {
    let (g, alice, bob, corp) = people_graph();
    assert_eq!(g.match_triples(None, None, None).len(), 3);
    assert_eq!(g.match_triples(None, Some("WORKS_AT"), None).len(), 2);
    assert_eq!(
        g.match_triples(Some(alice), None, Some(bob)),
        vec![(alice, "KNOWS", bob)]
    );
    assert_eq!(g.match_triples(Some(corp), None, None), vec![]);
}
