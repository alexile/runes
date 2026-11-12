//! Write-ahead log for crash-safe graph mutations.
//!
//! [`WalWriter`] wraps a [`Graph`] and records every mutation to an append-only
//! WAL file *before* applying it to the in-memory graph. If the process crashes
//! mid-session the WAL is replayed on top of the last snapshot next time you
//! call [`WalWriter::open`], recovering all completed operations.
//!
//! # File layout
//!
//! Two files on disk:
//!
//! - **snapshot** (`*.bin`) — a full bincode graph snapshot, written by
//!   [`WalWriter::checkpoint`].
//! - **WAL** (`*.wal`) — an append-only log of `WalOp`s in a simple
//!   length-prefixed bincode frame format (4-byte LE length + payload).
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "wal")]
//! # {
//! use rune_graph::{props, Value};
//! use rune_graph::wal::WalWriter;
//!
//! // Create a new WAL-backed graph
//! let mut w = WalWriter::create("graph.bin", "graph.wal").unwrap();
//! let alice = w.add_node(&["Person"], props! { "name" => "Alice" }).unwrap();
//! let bob   = w.add_node(&["Person"], props! { "name" => "Bob"   }).unwrap();
//! w.add_edge(alice, bob, "KNOWS", props! {}).unwrap();
//!
//! // Compact WAL into snapshot, then continue writing
//! w.checkpoint().unwrap();
//! w.set_node_property(alice, "age", Value::Int(30)).unwrap();
//!
//! // Later — or after a crash — open with full recovery:
//! // let mut w2 = WalWriter::open("graph.bin", "graph.wal").unwrap();
//! // assert_eq!(w2.graph().node_count(), 2);
//! # }
//! ```

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::GraphError;
use crate::graph::Graph;
use crate::id::{EdgeId, NodeId};
use crate::persist::PersistError;
use crate::value::Value;

// ── WAL frame helpers ─────────────────────────────────────────────────────────

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
fn write_frame(writer: &mut BufWriter<File>, op: &WalOp) -> Result<(), WalError> {
    let payload = bincode::serialize(op).map_err(|e| WalError::Encode(e.to_string()))?;
    let len = payload.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

fn read_frames(path: &Path) -> Result<Vec<WalOp>, WalError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(WalError::Io(e)),
    };
    let mut reader = BufReader::new(file);
    let mut ops = Vec::new();
    let mut len_buf = [0u8; 4];
    loop {
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(WalError::Io(e)),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        match reader.read_exact(&mut payload) {
            Ok(()) => {}
            Err(_) => break, // truncated entry — stop here
        }
        match bincode::deserialize::<WalOp>(&payload) {
            Ok(op) => ops.push(op),
            Err(_) => break, // corrupt entry — stop
        }
    }
    Ok(ops)
}

// ── WalOp ─────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub(crate) enum WalOp {
    AddNode {
        id: NodeId,
        labels: Vec<String>,
        props: HashMap<String, Value>,
    },
    RemoveNode {
        id: NodeId,
    },
    AddEdge {
        id: EdgeId,
        source: NodeId,
        target: NodeId,
        label: String,
        props: HashMap<String, Value>,
    },
    RemoveEdge {
        id: EdgeId,
    },
    SetNodeProp {
        id: NodeId,
        key: String,
        value: Value,
    },
    SetEdgeProp {
        id: EdgeId,
        key: String,
        value: Value,
    },
}

fn apply_op(graph: &mut Graph, op: WalOp) -> Result<(), GraphError> {
    match op {
        WalOp::AddNode { id, labels, props } => {
            graph.restore_node(id, labels, props);
        }
        WalOp::RemoveNode { id } => {
            graph.remove_node(id)?;
        }
        WalOp::AddEdge {
            id,
            source,
            target,
            label,
            props,
        } => {
            graph.restore_edge(id, source, target, label, props);
        }
        WalOp::RemoveEdge { id } => {
            graph.remove_edge(id)?;
        }
        WalOp::SetNodeProp { id, key, value } => {
            graph.set_node_property(id, &key, value)?;
        }
        WalOp::SetEdgeProp { id, key, value } => {
            graph.set_edge_property(id, &key, value)?;
        }
    }
    Ok(())
}

// ── WalError ──────────────────────────────────────────────────────────────────

/// Errors produced by [`WalWriter`] operations.
#[derive(Debug)]
pub enum WalError {
    /// An I/O error while reading or writing files.
    Io(std::io::Error),
    /// Failed to encode a WAL entry.
    Encode(String),
    /// Failed to save or load a snapshot.
    Persist(PersistError),
    /// A replayed WAL operation was invalid (e.g. referenced a missing node).
    Apply(GraphError),
}

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "WAL I/O error: {e}"),
            Self::Encode(e) => write!(f, "WAL encode error: {e}"),
            Self::Persist(e) => write!(f, "WAL snapshot error: {e}"),
            Self::Apply(e) => write!(f, "WAL replay error: {e}"),
        }
    }
}

impl std::error::Error for WalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Persist(e) => Some(e),
            Self::Apply(e) => Some(e),
            Self::Encode(_) => None,
        }
    }
}

impl From<std::io::Error> for WalError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<PersistError> for WalError {
    fn from(e: PersistError) -> Self {
        Self::Persist(e)
    }
}

// ── WalWriter ─────────────────────────────────────────────────────────────────

/// A [`Graph`] with crash-safe persistence via a write-ahead log.
///
/// Every mutation is written to the WAL file and flushed *before* being applied
/// to the in-memory graph. On the next call to [`open`][WalWriter::open] the WAL
/// is replayed on top of the snapshot, recovering any operations that completed
/// before the crash.
///
/// Use [`checkpoint`][WalWriter::checkpoint] periodically to compact the WAL
/// into a new snapshot, keeping the WAL file small.
///
/// # Example
///
/// ```rust,no_run
/// # #[cfg(feature = "wal")]
/// # {
/// use rune_graph::{props, Value};
/// use rune_graph::wal::WalWriter;
///
/// let mut w = WalWriter::create("g.bin", "g.wal").unwrap();
/// let a = w.add_node(&["A"], props! {}).unwrap();
/// w.checkpoint().unwrap();
/// let b = w.add_node(&["B"], props! {}).unwrap();
/// w.add_edge(a, b, "E", props! {}).unwrap();
///
/// // After a crash, open recovers everything:
/// // let w2 = WalWriter::open("g.bin", "g.wal").unwrap();
/// // assert_eq!(w2.graph().node_count(), 2);
/// # }
/// ```
pub struct WalWriter {
    graph: Graph,
    writer: BufWriter<File>,
    snapshot_path: PathBuf,
    wal_path: PathBuf,
}

impl WalWriter {
    /// Create a new WAL-backed graph with empty state.
    ///
    /// Neither file needs to exist. If `snapshot_path` already exists it is
    /// overwritten on the first [`checkpoint`][WalWriter::checkpoint].
    ///
    /// # Errors
    ///
    /// Returns [`WalError`] if the WAL file cannot be created.
    pub fn create(
        snapshot_path: impl AsRef<Path>,
        wal_path: impl AsRef<Path>,
    ) -> Result<Self, WalError> {
        let snapshot_path = snapshot_path.as_ref().to_path_buf();
        let wal_path = wal_path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)?;
        Ok(Self {
            graph: Graph::new(),
            writer: BufWriter::new(file),
            snapshot_path,
            wal_path,
        })
    }

    /// Open an existing WAL-backed graph, replaying any pending WAL entries.
    ///
    /// If the snapshot file does not exist an empty graph is used as the base.
    /// If the WAL file does not exist the snapshot is loaded as-is.
    /// Truncated or corrupt WAL entries at the tail are silently ignored —
    /// only fully flushed entries are replayed.
    ///
    /// # Errors
    ///
    /// Returns [`WalError`] on I/O failure, snapshot decode failure, or if a
    /// replayed WAL entry references a node or edge that does not exist.
    pub fn open(
        snapshot_path: impl AsRef<Path>,
        wal_path: impl AsRef<Path>,
    ) -> Result<Self, WalError> {
        let snapshot_path = snapshot_path.as_ref().to_path_buf();
        let wal_path = wal_path.as_ref().to_path_buf();

        let mut graph = if snapshot_path.exists() {
            Graph::load(&snapshot_path)?
        } else {
            Graph::new()
        };

        for op in read_frames(&wal_path)? {
            apply_op(&mut graph, op).map_err(WalError::Apply)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)?;

        Ok(Self {
            graph,
            writer: BufWriter::new(file),
            snapshot_path,
            wal_path,
        })
    }

    /// Read-only access to the underlying graph.
    #[must_use]
    pub const fn graph(&self) -> &Graph {
        &self.graph
    }

    /// Flush in-memory state to a new snapshot and truncate the WAL.
    ///
    /// After a checkpoint the WAL file is empty and the snapshot contains the
    /// complete graph state.
    ///
    /// # Errors
    ///
    /// Returns [`WalError`] if the snapshot cannot be written or the WAL
    /// file cannot be truncated.
    pub fn checkpoint(&mut self) -> Result<(), WalError> {
        self.graph.save(&self.snapshot_path)?;
        // Truncate WAL by reopening the file with truncation.
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.wal_path)?;
        self.writer = BufWriter::new(file);
        Ok(())
    }

    // ── Mutations ─────────────────────────────────────────────────────────────

    /// Add a node — writes to WAL before updating the in-memory graph.
    ///
    /// # Errors
    ///
    /// Returns [`WalError`] if the WAL write fails.
    pub fn add_node(
        &mut self,
        labels: &[&str],
        props: HashMap<String, Value>,
    ) -> Result<NodeId, WalError> {
        let id = self.graph.next_node_id();
        let labels_vec: Vec<String> = labels
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        write_frame(
            &mut self.writer,
            &WalOp::AddNode {
                id,
                labels: labels_vec.clone(),
                props: props.clone(),
            },
        )?;
        self.graph.restore_node(id, labels_vec, props);
        Ok(id)
    }

    /// Remove a node and all its incident edges — writes to WAL first.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Apply`] if the node does not exist, or
    /// [`WalError::Io`] / [`WalError::Encode`] on WAL write failure.
    pub fn remove_node(&mut self, id: NodeId) -> Result<(), WalError> {
        if !self.graph.contains_node(id) {
            return Err(WalError::Apply(GraphError::NodeNotFound(id)));
        }
        write_frame(&mut self.writer, &WalOp::RemoveNode { id })?;
        self.graph.remove_node(id).map_err(WalError::Apply)
    }

    /// Add an edge — writes to WAL before updating the in-memory graph.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Apply`] if either endpoint does not exist.
    pub fn add_edge(
        &mut self,
        source: NodeId,
        target: NodeId,
        label: &str,
        props: HashMap<String, Value>,
    ) -> Result<EdgeId, WalError> {
        if !self.graph.contains_node(source) {
            return Err(WalError::Apply(GraphError::NodeNotFound(source)));
        }
        if !self.graph.contains_node(target) {
            return Err(WalError::Apply(GraphError::NodeNotFound(target)));
        }
        let id = self.graph.next_edge_id();
        write_frame(
            &mut self.writer,
            &WalOp::AddEdge {
                id,
                source,
                target,
                label: label.to_string(),
                props: props.clone(),
            },
        )?;
        self.graph
            .restore_edge(id, source, target, label.to_string(), props);
        Ok(id)
    }

    /// Remove an edge — writes to WAL first.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Apply`] if the edge does not exist.
    pub fn remove_edge(&mut self, id: EdgeId) -> Result<(), WalError> {
        if !self.graph.contains_edge(id) {
            return Err(WalError::Apply(GraphError::EdgeNotFound(id)));
        }
        write_frame(&mut self.writer, &WalOp::RemoveEdge { id })?;
        self.graph.remove_edge(id).map_err(WalError::Apply)
    }

    /// Set or overwrite a node property — writes to WAL first.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Apply`] if the node does not exist.
    pub fn set_node_property(
        &mut self,
        id: NodeId,
        key: &str,
        value: Value,
    ) -> Result<(), WalError> {
        if !self.graph.contains_node(id) {
            return Err(WalError::Apply(GraphError::NodeNotFound(id)));
        }
        write_frame(
            &mut self.writer,
            &WalOp::SetNodeProp {
                id,
                key: key.to_string(),
                value: value.clone(),
            },
        )?;
        self.graph
            .set_node_property(id, key, value)
            .map_err(WalError::Apply)
    }

    /// Set or overwrite an edge property — writes to WAL first.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Apply`] if the edge does not exist.
    pub fn set_edge_property(
        &mut self,
        id: EdgeId,
        key: &str,
        value: Value,
    ) -> Result<(), WalError> {
        if !self.graph.contains_edge(id) {
            return Err(WalError::Apply(GraphError::EdgeNotFound(id)));
        }
        write_frame(
            &mut self.writer,
            &WalOp::SetEdgeProp {
                id,
                key: key.to_string(),
                value: value.clone(),
            },
        )?;
        self.graph
            .set_edge_property(id, key, value)
            .map_err(WalError::Apply)
    }
}
