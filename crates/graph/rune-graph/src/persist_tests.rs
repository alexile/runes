#[cfg(feature = "persist")]
mod tests {
    use crate::{Graph, Value, props};

    fn sample_graph() -> Graph {
        let mut g = Graph::new();
        let a = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
        let b = g.add_node(&["Person"], props! { "name" => "Bob" });
        g.add_edge(a, b, "KNOWS", props! { "since" => 2021_i64 })
            .unwrap();
        g
    }

    fn round_trip_json(g: &Graph) -> Graph {
        let json = g.to_json().unwrap();
        Graph::from_json(&json).unwrap()
    }

    // ── JSON round-trip ───────────────────────────────────────────────────────

    #[test]
    fn json_preserves_node_count() {
        let g = sample_graph();
        let g2 = round_trip_json(&g);
        assert_eq!(g2.node_count(), g.node_count());
    }

    #[test]
    fn json_preserves_edge_count() {
        let g = sample_graph();
        let g2 = round_trip_json(&g);
        assert_eq!(g2.edge_count(), g.edge_count());
    }

    #[test]
    fn json_preserves_labels() {
        let g = sample_graph();
        let g2 = round_trip_json(&g);
        assert_eq!(g2.nodes_with_label("Person").count(), 2);
    }

    #[test]
    fn json_preserves_edge_label() {
        let g = sample_graph();
        let g2 = round_trip_json(&g);
        assert_eq!(g2.edges_with_label("KNOWS").count(), 1);
    }

    #[test]
    fn json_preserves_node_properties() {
        let g = sample_graph();
        let g2 = round_trip_json(&g);
        let alice_id = g2
            .find_nodes(|n| n.get("name") == Some(&Value::Str("Alice".into())))
            .next()
            .unwrap();
        assert_eq!(g2.node(alice_id).unwrap().get("age"), Some(&Value::Int(30)));
    }

    #[test]
    fn json_preserves_edge_properties() {
        let g = sample_graph();
        let g2 = round_trip_json(&g);
        let eid = g2.edges_with_label("KNOWS").next().unwrap();
        assert_eq!(g2.edge(eid).unwrap().get("since"), Some(&Value::Int(2021)));
    }

    #[test]
    fn invalid_json_returns_decode_error() {
        use crate::PersistError;
        let result = Graph::from_json("not json at all");
        assert!(matches!(result, Err(PersistError::Decode(_))));
    }

    // ── Bincode round-trip ────────────────────────────────────────────────────

    #[test]
    fn bincode_round_trip_preserves_structure() {
        let g = sample_graph();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("graph.bin");
        g.save(&path).unwrap();
        let g2 = Graph::load(&path).unwrap();
        assert_eq!(g2.node_count(), g.node_count());
        assert_eq!(g2.edge_count(), g.edge_count());
        assert_eq!(g2.nodes_with_label("Person").count(), 2);
    }

    #[test]
    fn bincode_preserves_node_properties() {
        let g = sample_graph();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.bin");
        g.save(&path).unwrap();
        let g2 = Graph::load(&path).unwrap();
        let alice = g2
            .find_nodes(|n| n.get("name") == Some(&Value::Str("Alice".into())))
            .next()
            .unwrap();
        assert_eq!(g2.node(alice).unwrap().get("age"), Some(&Value::Int(30)));
    }

    #[test]
    fn load_nonexistent_file_returns_io_error() {
        use crate::PersistError;
        let result = Graph::load("/does/not/exist.bin");
        assert!(matches!(result, Err(PersistError::Io(_))));
    }

    #[test]
    fn adjacency_survives_json_round_trip() {
        // Traversal must work correctly after deserialisation.
        let g = sample_graph();
        let json = g.to_json().unwrap();
        let g2 = Graph::from_json(&json).unwrap();
        // Find Alice and check she knows someone.
        let alice = g2
            .find_nodes(|n| n.get("name") == Some(&Value::Str("Alice".into())))
            .next()
            .unwrap();
        assert_eq!(g2.neighbors(alice).count(), 1);
    }

    #[test]
    fn adjacency_survives_bincode_round_trip() {
        let g = sample_graph();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g2.bin");
        g.save(&path).unwrap();
        let g2 = Graph::load(&path).unwrap();
        let alice = g2
            .find_nodes(|n| n.get("name") == Some(&Value::Str("Alice".into())))
            .next()
            .unwrap();
        assert_eq!(g2.neighbors(alice).count(), 1);
    }
}
