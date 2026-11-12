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

    // ── Snapshot format ───────────────────────────────────────────────────────

    use crate::persist::{HEADER_LEN, MAGIC};
    use crate::{LoadOptions, NodeId, PersistError};

    fn saved(g: &Graph) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.bin");
        g.save(&path).unwrap();
        (dir, path)
    }

    #[test]
    fn snapshot_has_versioned_header() {
        let (_dir, path) = saved(&sample_graph());
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 1);
        let len = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        assert_eq!(usize::try_from(len).unwrap(), bytes.len() - HEADER_LEN);
    }

    #[test]
    fn snapshot_bytes_are_deterministic() {
        // Two independently built graphs have different hash seeds.
        let (_d1, p1) = saved(&sample_graph());
        let (_d2, p2) = saved(&sample_graph());
        assert_eq!(std::fs::read(p1).unwrap(), std::fs::read(p2).unwrap());
    }

    #[test]
    fn flipped_payload_bit_fails_checksum() {
        let (_dir, path) = saved(&sample_graph());
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            Graph::load(&path),
            Err(PersistError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn truncated_snapshot_is_rejected() {
        let (_dir, path) = saved(&sample_graph());
        let bytes = std::fs::read(&path).unwrap();
        for cut in [4, HEADER_LEN - 1, bytes.len() - 1] {
            std::fs::write(&path, &bytes[..cut]).unwrap();
            assert!(Graph::load(&path).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn future_version_is_rejected() {
        let (_dir, path) = saved(&sample_graph());
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[8..12].copy_from_slice(&99u32.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            Graph::load(&path),
            Err(PersistError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn oversized_file_is_refused_before_reading() {
        let (_dir, path) = saved(&sample_graph());
        let err = Graph::load_with(&path, &LoadOptions::default().max_bytes(8)).unwrap_err();
        assert!(matches!(err, PersistError::TooLarge { limit: 8, .. }));
    }

    #[test]
    fn huge_length_prefix_does_not_allocate() {
        // A legacy-format file claiming 2^60 nodes must fail cleanly.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evil.bin");
        let mut bytes = (1u64 << 60).to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 32]);
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(Graph::load(&path), Err(PersistError::Decode(_))));
    }

    #[test]
    fn deeply_nested_values_are_rejected() {
        let mut v = Value::Null;
        for _ in 0..(Value::MAX_DEPTH + 10) {
            v = Value::List(vec![v]);
        }
        let mut g = Graph::new();
        g.add_node(&[], props! { "deep" => v });
        let json = g.to_json().unwrap();
        let err = Graph::from_json(&json).unwrap_err();
        assert!(matches!(err, PersistError::Decode(_)));
    }

    fn nested(depth: usize) -> Value {
        let mut v = Value::Null;
        for _ in 0..depth {
            v = Value::List(vec![v]);
        }
        v
    }

    #[test]
    fn binary_depth_limit_is_enforced() {
        let mut ok = Graph::new();
        ok.add_node(&[], props! { "v" => nested(Value::MAX_DEPTH) });
        let (_d1, p1) = saved(&ok);
        assert!(Graph::load(&p1).is_ok());

        let mut deep = Graph::new();
        deep.add_node(&[], props! { "v" => nested(Value::MAX_DEPTH + 2) });
        let (_d2, p2) = saved(&deep);
        let err = Graph::load(&p2).unwrap_err();
        assert!(err.to_string().contains("nested too deeply"), "{err}");
    }

    #[test]
    fn save_leaves_no_temp_files_and_replaces_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.bin");
        std::fs::write(&path, b"old contents").unwrap();
        sample_graph().save(&path).unwrap();
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("g.bin")]);
        assert_eq!(Graph::load(&path).unwrap().node_count(), 2);
    }

    #[test]
    fn save_into_missing_directory_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope").join("g.bin");
        assert!(matches!(
            sample_graph().save(&path),
            Err(PersistError::Io(_))
        ));
    }

    #[test]
    fn indexes_survive_snapshots() {
        let mut g = sample_graph();
        g.create_index("Person", "name");
        let (_dir, path) = saved(&g);
        let g2 = Graph::load(&path).unwrap();
        assert!(g2.has_index("Person", "name"));
        assert_eq!(
            g2.nodes_by_property("Person", "name", &Value::from("Bob"))
                .count(),
            1
        );
    }

    #[test]
    fn ids_and_counters_survive_snapshots() {
        let mut g = sample_graph();
        let gone = g.add_node(&[], props! {});
        g.remove_node(gone).unwrap();
        let (_dir, path) = saved(&g);
        let mut g2 = Graph::load(&path).unwrap();
        let fresh = g2.add_node(&[], props! {});
        assert!(fresh > gone, "ids must not be reused after reload");
    }

    // ── Legacy (0.3) formats ──────────────────────────────────────────────────

    #[derive(serde::Serialize)]
    struct Legacy<'a> {
        nodes: std::collections::HashMap<NodeId, &'a crate::NodeEntry>,
        edges: std::collections::HashMap<crate::EdgeId, &'a crate::EdgeEntry>,
        out_edges: std::collections::HashMap<NodeId, Vec<crate::EdgeId>>,
        in_edges: std::collections::HashMap<NodeId, Vec<crate::EdgeId>>,
        next_node: u64,
        next_edge: u64,
    }

    fn legacy(g: &Graph) -> Legacy<'_> {
        Legacy {
            nodes: g.nodes().collect(),
            edges: g.edges().collect(),
            out_edges: g
                .nodes()
                .map(|(n, _)| (n, g.outgoing_edges(n).collect()))
                .collect(),
            in_edges: g
                .nodes()
                .map(|(n, _)| (n, g.incoming_edges(n).collect()))
                .collect(),
            next_node: g.next_node,
            next_edge: g.next_edge,
        }
    }

    #[test]
    fn legacy_bincode_snapshot_loads() {
        let g = sample_graph();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.bin");
        std::fs::write(&path, bincode::serialize(&legacy(&g)).unwrap()).unwrap();
        let g2 = Graph::load(&path).unwrap();
        assert_eq!(g2.to_json().unwrap(), g.to_json().unwrap());
    }

    #[test]
    fn legacy_json_loads() {
        let g = sample_graph();
        let old = serde_json::to_string(&legacy(&g)).unwrap();
        let g2 = Graph::from_json(&old).unwrap();
        assert_eq!(g2.to_json().unwrap(), g.to_json().unwrap());
    }

    #[test]
    fn dangling_edge_in_json_is_invalid() {
        let json = r#"{"format":1,"nodes":[],"edges":[{"id":0,"source":0,"target":1,"label":"E","properties":{}}],"next_node":0,"next_edge":1,"indexes":[]}"#;
        assert!(Graph::from_json(json).is_err());
    }

    // ── JSON Lines ────────────────────────────────────────────────────────────

    #[test]
    fn jsonl_uses_plain_json_values() {
        let mut g = Graph::new();
        g.add_node(
            &["T"],
            props! { "i" => 1_i64, "f" => 1.0_f64, "s" => "x", "l" => vec![Value::Bool(true), Value::Null] },
        );
        let mut out = Vec::new();
        g.write_jsonl(&mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text.trim(),
            r#"{"id":0,"labels":["T"],"properties":{"f":1.0,"i":1,"l":[true,null],"s":"x"},"type":"node"}"#
        );
        let back = Graph::read_jsonl(text.as_bytes()).unwrap();
        let n = back.node(NodeId::from(0)).unwrap();
        assert_eq!(n.get("i"), Some(&Value::Int(1)));
        assert_eq!(n.get("f"), Some(&Value::Float(1.0)));
    }

    #[test]
    fn jsonl_rejects_bad_input_with_line_numbers() {
        let cases = [
            ("{\"type\":\"node\",\"id\":0}\nnot json", "line 2"),
            (
                "{\"type\":\"edge\",\"id\":0,\"source\":0,\"target\":1,\"label\":\"E\"}",
                "line 1",
            ),
            (
                "{\"type\":\"node\",\"id\":0}\n{\"type\":\"node\",\"id\":0}",
                "line 2",
            ),
            (
                "{\"type\":\"node\",\"id\":0,\"properties\":{\"o\":{}}}",
                "line 1",
            ),
            ("{\"type\":\"blob\"}", "line 1"),
        ];
        for (input, want) in cases {
            let err = Graph::read_jsonl(input.as_bytes()).unwrap_err();
            assert!(err.to_string().contains(want), "{input}: {err}");
        }
    }

    #[test]
    fn jsonl_enforces_record_limit() {
        let input = "{\"type\":\"node\",\"id\":0}\n{\"type\":\"node\",\"id\":1}\n";
        let opts = crate::JsonlOptions::default().max_records(Some(1));
        assert!(matches!(
            Graph::read_jsonl_with(input.as_bytes(), &opts),
            Err(PersistError::TooLarge { .. })
        ));
    }

    #[test]
    fn jsonl_refuses_non_finite_floats() {
        let mut g = Graph::new();
        g.add_node(&[], props! { "x" => f64::NAN });
        assert!(matches!(
            g.write_jsonl(Vec::new()),
            Err(PersistError::Encode(_))
        ));
    }

    #[test]
    fn huge_ids_are_rejected() {
        let input = format!("{{\"type\":\"node\",\"id\":{}}}", u64::MAX);
        assert!(matches!(
            Graph::read_jsonl(input.as_bytes()),
            Err(PersistError::Invalid(_))
        ));
    }
}
