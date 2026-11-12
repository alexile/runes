use tempfile::tempdir;

use crate::Value;
use crate::props;
use crate::wal::{WalError, WalWriter};

fn empty(dir: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    (dir.path().join("graph.bin"), dir.path().join("graph.wal"))
}

#[test]
fn create_and_basic_ops() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);

    let mut w = WalWriter::create(&snap, &wal).unwrap();
    let alice = w
        .add_node(&["Person"], props! { "name" => "Alice" })
        .unwrap();
    let bob = w.add_node(&["Person"], props! { "name" => "Bob" }).unwrap();
    w.add_edge(alice, bob, "KNOWS", props! {}).unwrap();

    assert_eq!(w.graph().node_count(), 2);
    assert_eq!(w.graph().edge_count(), 1);
}

#[test]
fn wal_persists_across_reopen() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);

    {
        let mut w = WalWriter::create(&snap, &wal).unwrap();
        let a = w.add_node(&["A"], props! { "x" => 1_i64 }).unwrap();
        let b = w.add_node(&["B"], props! { "x" => 2_i64 }).unwrap();
        w.add_edge(a, b, "LINK", props! {}).unwrap();
        // no checkpoint — only WAL exists
    }

    let w2 = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(w2.graph().node_count(), 2);
    assert_eq!(w2.graph().edge_count(), 1);
}

#[test]
fn checkpoint_compacts_wal() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);

    {
        let mut w = WalWriter::create(&snap, &wal).unwrap();
        let a = w.add_node(&["A"], props! {}).unwrap();
        w.add_node(&["B"], props! {}).unwrap();
        w.checkpoint().unwrap();
        // After checkpoint WAL should be empty — add one more op
        w.add_node(&["C"], props! {}).unwrap();
        w.remove_node(a).unwrap();
    }

    let wal_size = std::fs::metadata(&wal).map_or(0, |m| m.len());
    assert!(wal_size > 0, "WAL should contain post-checkpoint ops");

    let w2 = WalWriter::open(&snap, &wal).unwrap();
    // snapshot had A+B, WAL added C and removed A
    assert_eq!(w2.graph().node_count(), 2); // B + C
}

#[test]
fn set_node_property_round_trips() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);

    let node;
    {
        let mut w = WalWriter::create(&snap, &wal).unwrap();
        node = w.add_node(&["X"], props! { "score" => 0_i64 }).unwrap();
        w.set_node_property(node, "score", Value::Int(99)).unwrap();
    }

    let w2 = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(
        w2.graph().node(node).unwrap().get("score"),
        Some(&Value::Int(99))
    );
}

#[test]
fn set_edge_property_round_trips() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);

    let edge;
    {
        let mut w = WalWriter::create(&snap, &wal).unwrap();
        let a = w.add_node(&[], props! {}).unwrap();
        let b = w.add_node(&[], props! {}).unwrap();
        edge = w.add_edge(a, b, "E", props! { "w" => 1_i64 }).unwrap();
        w.set_edge_property(edge, "w", Value::Int(7)).unwrap();
    }

    let w2 = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(
        w2.graph().edge(edge).unwrap().get("w"),
        Some(&Value::Int(7))
    );
}

#[test]
fn remove_edge_round_trips() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);

    {
        let mut w = WalWriter::create(&snap, &wal).unwrap();
        let a = w.add_node(&[], props! {}).unwrap();
        let b = w.add_node(&[], props! {}).unwrap();
        let eid = w.add_edge(a, b, "E", props! {}).unwrap();
        w.remove_edge(eid).unwrap();
    }

    let w2 = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(w2.graph().edge_count(), 0);
}

#[test]
fn open_missing_snapshot_uses_empty_graph() {
    let dir = tempdir().unwrap();
    let snap = dir.path().join("missing.bin");
    let wal = dir.path().join("graph.wal");

    // Write a WAL without ever saving a snapshot
    {
        let mut w = WalWriter::create(&snap, &wal).unwrap();
        w.add_node(&["Solo"], props! {}).unwrap();
    }

    let w2 = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(w2.graph().node_count(), 1);
}

#[test]
fn remove_nonexistent_node_errors() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);

    let mut w = WalWriter::create(&snap, &wal).unwrap();
    let fake = crate::NodeId::from(999);
    assert!(matches!(w.remove_node(fake), Err(WalError::Apply(_))));
}

#[test]
fn multiple_checkpoints() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);

    let mut w = WalWriter::create(&snap, &wal).unwrap();
    for i in 0..5_i64 {
        w.add_node(&["N"], props! { "i" => i }).unwrap();
        w.checkpoint().unwrap();
    }
    w.add_node(&["N"], props! { "i" => 5_i64 }).unwrap();

    let w2 = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(w2.graph().node_count(), 6);
}

// ── Recovery edge cases ───────────────────────────────────────────────────────

#[test]
fn crash_between_snapshot_and_wal_reset_does_not_double_apply() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);
    let mut w = WalWriter::create(&snap, &wal).unwrap();
    let a = w.add_node(&["A"], props! {}).unwrap();
    let b = w.add_node(&["B"], props! {}).unwrap();
    w.remove_node(b).unwrap();
    // Simulate a crash right after the snapshot rename: the snapshot holds
    // generation 1 with all ops applied, the WAL is still at generation 0.
    w.graph().save_snapshot(&snap, 1).unwrap();
    drop(w);

    let w2 = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(w2.graph().node_count(), 1);
    assert!(w2.graph().contains_node(a));
    // The stale log was reset; a further reopen is still consistent.
    drop(w2);
    assert_eq!(
        WalWriter::open(&snap, &wal).unwrap().graph().node_count(),
        1
    );
}

#[test]
fn torn_tail_is_truncated_and_later_writes_survive() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);
    let mut w = WalWriter::create(&snap, &wal).unwrap();
    w.add_node(&["A"], props! {}).unwrap();
    drop(w);
    // Half-written frame at the tail.
    let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
    std::io::Write::write_all(&mut f, &[200, 0, 0, 0, 1, 2]).unwrap();
    drop(f);

    let mut w = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(w.graph().node_count(), 1);
    w.add_node(&["B"], props! {}).unwrap();
    drop(w);
    let w = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(w.graph().node_count(), 2);
}

#[test]
fn corrupt_frame_checksum_stops_replay() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);
    let mut w = WalWriter::create(&snap, &wal).unwrap();
    w.add_node(&["A"], props! {}).unwrap();
    w.add_node(&["B"], props! {}).unwrap();
    drop(w);
    let mut bytes = std::fs::read(&wal).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&wal, bytes).unwrap();
    let w = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(w.graph().node_count(), 1);
}

#[test]
fn oversized_frame_length_is_treated_as_corruption() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);
    drop(WalWriter::create(&snap, &wal).unwrap());
    let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
    std::io::Write::write_all(&mut f, &u32::MAX.to_le_bytes()).unwrap();
    drop(f);
    assert_eq!(
        WalWriter::open(&snap, &wal).unwrap().graph().node_count(),
        0
    );
}

#[test]
fn wal_ahead_of_snapshot_is_an_error() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);
    let mut w = WalWriter::create(&snap, &wal).unwrap();
    w.checkpoint().unwrap();
    drop(w);
    // Roll the snapshot back to generation 0.
    crate::Graph::new().save_snapshot(&snap, 0).unwrap();
    assert!(matches!(
        WalWriter::open(&snap, &wal),
        Err(WalError::GenerationMismatch {
            snapshot: 0,
            wal: 1
        })
    ));
}

#[test]
fn legacy_wal_is_replayed_and_migrated() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);
    // 0.3 format: no header, frames of u32 length + bincode payload.
    let op = crate::wal::WalOp::AddNode {
        id: crate::NodeId::from(0),
        labels: vec!["Old".into()],
        props: props! { "k" => 1_i64 },
    };
    let payload = bincode::serialize(&op).unwrap();
    let mut bytes = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
    bytes.extend_from_slice(&payload);
    std::fs::write(&wal, bytes).unwrap();

    let mut w = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(w.graph().nodes_with_label("Old").count(), 1);
    w.add_node(&["New"], props! {}).unwrap();
    drop(w);
    let w = WalWriter::open(&snap, &wal).unwrap();
    assert_eq!(w.graph().node_count(), 2);
    assert!(std::fs::read(&wal).unwrap().starts_with(b"RUNEGWAL"));
}

#[test]
fn labels_props_and_indexes_replay() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);
    let mut w = WalWriter::create(&snap, &wal).unwrap();
    assert!(w.create_index("User", "email").unwrap());
    let a = w
        .add_node(&["Draft"], props! { "email" => "a@x", "tmp" => 1_i64 })
        .unwrap();
    assert!(w.add_node_label(a, "User").unwrap());
    assert!(w.remove_node_label(a, "Draft").unwrap());
    assert_eq!(
        w.remove_node_property(a, "tmp").unwrap(),
        Some(Value::Int(1))
    );
    let e = w.add_edge(a, a, "SELF", props! { "w" => 1_i64 }).unwrap();
    assert_eq!(w.remove_edge_property(e, "w").unwrap(), Some(Value::Int(1)));
    drop(w);

    let w = WalWriter::open(&snap, &wal).unwrap();
    let g = w.graph();
    assert!(g.has_index("User", "email"));
    assert_eq!(
        g.nodes_by_property("User", "email", &Value::from("a@x"))
            .collect::<Vec<_>>(),
        vec![a]
    );
    assert_eq!(g.nodes_with_label("Draft").count(), 0);
    assert_eq!(g.node(a).unwrap().get("tmp"), None);
    assert_eq!(g.edge(e).unwrap().get("w"), None);
}

#[test]
fn create_resets_existing_files() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);
    let mut w = WalWriter::create(&snap, &wal).unwrap();
    w.add_node(&[], props! {}).unwrap();
    w.checkpoint().unwrap();
    w.add_node(&[], props! {}).unwrap();
    drop(w);
    drop(WalWriter::create(&snap, &wal).unwrap());
    assert_eq!(
        WalWriter::open(&snap, &wal).unwrap().graph().node_count(),
        0
    );
}

#[test]
fn sync_and_into_graph() {
    let dir = tempdir().unwrap();
    let (snap, wal) = empty(&dir);
    let mut w = WalWriter::create(&snap, &wal).unwrap();
    w.set_sync_on_write(true);
    w.add_node(&[], props! {}).unwrap();
    w.sync().unwrap();
    assert_eq!(w.into_graph().node_count(), 1);
}
