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
