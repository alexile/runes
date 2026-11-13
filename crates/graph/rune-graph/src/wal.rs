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
//! - **snapshot** — a binary graph snapshot (see [`Graph::save`]), written
//!   atomically by [`WalWriter::checkpoint`].
//! - **WAL** — a 20-byte header (magic `RUNEGWAL`, `u32` version, `u64`
//!   generation) followed by frames of `u32` length, `u32` CRC-32 and a
//!   bincode-encoded operation.
//!
//! Both files carry a *generation* number. A checkpoint writes the snapshot
//! with generation `g + 1` and then replaces the WAL with an empty one at
//! `g + 1`. If a crash lands between those two steps, the old WAL (generation
//! `g`) is recognised as already folded into the snapshot and skipped, so
//! operations are never applied twice.
//!
//! # Durability
//!
//! Each frame is flushed to the operating system before the in-memory graph
//! changes, which survives a process crash. To also survive power loss, call
//! [`WalWriter::sync`] at commit points or enable
//! [`WalWriter::set_sync_on_write`]. A torn or corrupt tail (bad length or
//! checksum) is dropped on [`open`](WalWriter::open) and the file is truncated
//! back to the last good frame.
//!
//! If writing a frame fails, the writer cuts the file back to the last good
//! frame. If it cannot, or if a checkpoint fails after the new snapshot is in
//! place, the log no longer matches the graph and every further change is
//! refused until a [`checkpoint`](WalWriter::checkpoint) succeeds or the
//! files are reopened.
//!
//! # Example
//!
//! ```rust
//! use rune_graph::{props, Value};
//! use rune_graph::wal::WalWriter;
//!
//! let dir = std::env::temp_dir().join(format!("rune-graph-wal-doc-{}", std::process::id()));
//! std::fs::create_dir_all(&dir).unwrap();
//! let (snap, log) = (dir.join("graph.bin"), dir.join("graph.wal"));
//!
//! let mut w = WalWriter::create(&snap, &log).unwrap();
//! let alice = w.add_node(&["Person"], props! { "name" => "Alice" }).unwrap();
//! let bob   = w.add_node(&["Person"], props! { "name" => "Bob"   }).unwrap();
//! w.add_edge(alice, bob, "KNOWS", props! {}).unwrap();
//! w.checkpoint().unwrap();
//! w.set_node_property(alice, "age", Value::Int(30)).unwrap();
//! drop(w);
//!
//! // Later, or after a crash:
//! let w2 = WalWriter::open(&snap, &log).unwrap();
//! assert_eq!(w2.graph().node_count(), 2);
//! assert_eq!(w2.graph().node(alice).unwrap().get("age"), Some(&Value::Int(30)));
//! # std::fs::remove_dir_all(&dir).unwrap();
//! ```

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use bincode::Options;
use serde::{Deserialize, Serialize};

use crate::GraphError;
use crate::checksum::crc32;
use crate::entry::{EdgeEntry, NodeEntry};
use crate::graph::Graph;
use crate::id::{EdgeId, NodeId};
use crate::persist::{LoadOptions, PersistError, atomic_write};
use crate::value::Value;

const WAL_MAGIC: &[u8; 8] = b"RUNEGWAL";
const WAL_VERSION: u32 = 1;
const WAL_HEADER_LEN: u64 = 20;

/// Largest frame accepted on replay. Anything bigger is treated as a corrupt
/// tail rather than allocated.
pub const MAX_FRAME_BYTES: u32 = 64 << 20;

fn opts() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
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
    RemoveNodeProp {
        id: NodeId,
        key: String,
    },
    RemoveEdgeProp {
        id: EdgeId,
        key: String,
    },
    AddNodeLabel {
        id: NodeId,
        label: String,
    },
    RemoveNodeLabel {
        id: NodeId,
        label: String,
    },
    CreateIndex {
        label: String,
        key: String,
    },
    DropIndex {
        label: String,
        key: String,
    },
}

impl WalOp {
    /// Whether a property value is nested deeper than replay accepts.
    fn too_deep(&self) -> bool {
        match self {
            Self::AddNode { props, .. } | Self::AddEdge { props, .. } => {
                props.values().any(Value::too_deep)
            }
            Self::SetNodeProp { value, .. } | Self::SetEdgeProp { value, .. } => value.too_deep(),
            _ => false,
        }
    }
}

fn apply_op(graph: &mut Graph, op: WalOp) -> Result<(), GraphError> {
    match op {
        WalOp::AddNode { id, labels, props } => {
            graph.insert_node_with_id(id, NodeEntry::from_parts(labels, props))?;
        }
        WalOp::RemoveNode { id } => graph.remove_node(id)?,
        WalOp::AddEdge {
            id,
            source,
            target,
            label,
            props,
        } => graph.insert_edge_with_id(
            id,
            EdgeEntry {
                source,
                target,
                label,
                properties: props,
            },
        )?,
        WalOp::RemoveEdge { id } => graph.remove_edge(id)?,
        WalOp::SetNodeProp { id, key, value } => graph.set_node_property(id, &key, value)?,
        WalOp::SetEdgeProp { id, key, value } => graph.set_edge_property(id, &key, value)?,
        WalOp::RemoveNodeProp { id, key } => {
            graph.remove_node_property(id, &key)?;
        }
        WalOp::RemoveEdgeProp { id, key } => {
            graph.remove_edge_property(id, &key)?;
        }
        WalOp::AddNodeLabel { id, label } => {
            graph.add_node_label(id, &label)?;
        }
        WalOp::RemoveNodeLabel { id, label } => {
            graph.remove_node_label(id, &label)?;
        }
        WalOp::CreateIndex { label, key } => {
            graph.create_index(&label, &key);
        }
        WalOp::DropIndex { label, key } => {
            graph.drop_index(&label, &key);
        }
    }
    Ok(())
}

// ── WalError ──────────────────────────────────────────────────────────────────

/// Errors produced by [`WalWriter`] operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum WalError {
    /// An I/O error while reading or writing files.
    Io(std::io::Error),
    /// Failed to encode a WAL entry.
    Encode(String),
    /// Failed to save or load a snapshot.
    Persist(PersistError),
    /// A replayed WAL operation was invalid (e.g. referenced a missing node),
    /// or a mutation was rejected before being logged.
    Apply(GraphError),
    /// The WAL is newer than the snapshot next to it, so the snapshot was
    /// replaced or rolled back behind the log's back. Nothing is replayed.
    GenerationMismatch {
        /// Generation recorded in the snapshot.
        snapshot: u64,
        /// Generation recorded in the WAL header.
        wal: u64,
    },
    /// The WAL header names a format version this crate does not know.
    UnsupportedVersion(u32),
}

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "WAL I/O error: {e}"),
            Self::Encode(e) => write!(f, "WAL encode error: {e}"),
            Self::Persist(e) => write!(f, "WAL snapshot error: {e}"),
            Self::Apply(e) => write!(f, "WAL replay error: {e}"),
            Self::GenerationMismatch { snapshot, wal } => write!(
                f,
                "WAL generation {wal} is ahead of snapshot generation {snapshot}"
            ),
            Self::UnsupportedVersion(v) => write!(f, "unsupported WAL format version {v}"),
        }
    }
}

impl std::error::Error for WalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Persist(e) => Some(e),
            Self::Apply(e) => Some(e),
            _ => None,
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

// ── Frame reading ─────────────────────────────────────────────────────────────

enum Header {
    Missing,
    Legacy,
    V1 { generation: u64 },
}

fn read_header(reader: &mut impl Read) -> Result<(Header, Vec<u8>), WalError> {
    let mut head = Vec::with_capacity(20);
    reader.take(WAL_HEADER_LEN).read_to_end(&mut head)?;
    if head.starts_with(WAL_MAGIC) {
        let version = head
            .get(8..12)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes);
        let generation = head
            .get(12..20)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes);
        return match (version, generation) {
            (Some(WAL_VERSION), Some(generation)) => Ok((Header::V1 { generation }, Vec::new())),
            (Some(v), Some(_)) => Err(WalError::UnsupportedVersion(v)),
            _ => Ok((Header::Missing, Vec::new())),
        };
    }
    if head.is_empty() {
        return Ok((Header::Missing, head));
    }
    Ok((Header::Legacy, head))
}

/// Read the next frame. `Ok(None)` means end of log or a bad tail.
fn next_frame(reader: &mut impl Read, checksummed: bool) -> Result<Option<(WalOp, u64)>, WalError> {
    let mut len_buf = [0u8; 4];
    if !read_full(reader, &mut len_buf)? {
        return Ok(None);
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Ok(None);
    }
    let mut crc_buf = [0u8; 4];
    if checksummed && !read_full(reader, &mut crc_buf)? {
        return Ok(None);
    }
    let mut payload = Vec::new();
    reader.take(u64::from(len)).read_to_end(&mut payload)?;
    if payload.len() != len as usize {
        return Ok(None);
    }
    if checksummed && crc32(&payload) != u32::from_le_bytes(crc_buf) {
        return Ok(None);
    }
    let decoded = if checksummed {
        opts().with_limit(u64::from(len)).deserialize(&payload)
    } else {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(u64::from(len))
            .deserialize(&payload)
    };
    let frame_len = 4 + u64::from(len) + if checksummed { 4 } else { 0 };
    Ok(decoded.ok().map(|op| (op, frame_len)))
}

/// Fill `buf` completely. `Ok(false)` on a clean or partial EOF.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> Result<bool, WalError> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(WalError::Io(e)),
    }
}

// ── WalWriter ─────────────────────────────────────────────────────────────────

/// A [`Graph`] with crash-safe persistence via a write-ahead log.
///
/// Every mutation is validated, written to the WAL and flushed *before*
/// being applied to the in-memory graph. On the next call to
/// [`open`][WalWriter::open] the WAL is replayed on top of the snapshot.
///
/// Use [`checkpoint`][WalWriter::checkpoint] periodically to fold the WAL
/// into a new snapshot, keeping the WAL file small.
///
/// `WalWriter` is `Send` but not meant to be shared: wrap it in a `Mutex`
/// if several threads write.
pub struct WalWriter {
    graph: Graph,
    file: File,
    /// Length of the log up to the last frame that was fully written.
    len: u64,
    /// Set when the log may no longer match the in-memory graph.
    broken: bool,
    snapshot_path: PathBuf,
    wal_path: PathBuf,
    generation: u64,
    sync_on_write: bool,
}

impl std::fmt::Debug for WalWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalWriter")
            .field("snapshot_path", &self.snapshot_path)
            .field("wal_path", &self.wal_path)
            .field("generation", &self.generation)
            .field("nodes", &self.graph.node_count())
            .field("edges", &self.graph.edge_count())
            .finish_non_exhaustive()
    }
}

fn write_wal_header(path: &Path, generation: u64) -> Result<(), WalError> {
    atomic_write(path, |file| {
        file.write_all(WAL_MAGIC)?;
        file.write_all(&WAL_VERSION.to_le_bytes())?;
        file.write_all(&generation.to_le_bytes())?;
        Ok(())
    })?;
    Ok(())
}

fn next_generation(generation: u64) -> Result<u64, WalError> {
    generation.checked_add(1).ok_or_else(|| {
        WalError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snapshot generation counter is exhausted",
        ))
    })
}

fn open_append(path: &Path) -> Result<File, WalError> {
    Ok(OpenOptions::new().append(true).open(path)?)
}

impl WalWriter {
    /// Start a new, empty WAL-backed graph.
    ///
    /// Writes an empty snapshot and an empty WAL right away, replacing
    /// whatever was at either path.
    ///
    /// # Errors
    ///
    /// Returns [`WalError`] if either file cannot be written.
    pub fn create(
        snapshot_path: impl AsRef<Path>,
        wal_path: impl AsRef<Path>,
    ) -> Result<Self, WalError> {
        let snapshot_path = snapshot_path.as_ref().to_path_buf();
        let wal_path = wal_path.as_ref().to_path_buf();
        let graph = Graph::new();
        graph.save_snapshot(&snapshot_path, 0)?;
        write_wal_header(&wal_path, 0)?;
        Ok(Self {
            file: open_append(&wal_path)?,
            len: WAL_HEADER_LEN,
            broken: false,
            graph,
            snapshot_path,
            wal_path,
            generation: 0,
            sync_on_write: false,
        })
    }

    /// Open an existing WAL-backed graph, replaying pending WAL entries.
    ///
    /// If the snapshot does not exist an empty graph is used as the base; if
    /// the WAL does not exist the snapshot is loaded as is. A truncated or
    /// corrupt tail is dropped and cut off the file. WAL files written by
    /// rune-graph 0.3 are replayed and then checkpointed into the new format.
    ///
    /// # Errors
    ///
    /// Returns [`WalError`] on I/O failure, snapshot decode failure, a
    /// generation mismatch, or if a replayed entry is inconsistent with the
    /// graph (for example removes a node that does not exist).
    pub fn open(
        snapshot_path: impl AsRef<Path>,
        wal_path: impl AsRef<Path>,
    ) -> Result<Self, WalError> {
        Self::open_with(snapshot_path, wal_path, &LoadOptions::default())
    }

    /// Like [`open`](Self::open), with explicit snapshot [`LoadOptions`].
    ///
    /// # Errors
    ///
    /// See [`open`](Self::open).
    pub fn open_with(
        snapshot_path: impl AsRef<Path>,
        wal_path: impl AsRef<Path>,
        load: &LoadOptions,
    ) -> Result<Self, WalError> {
        let snapshot_path = snapshot_path.as_ref().to_path_buf();
        let wal_path = wal_path.as_ref().to_path_buf();

        let (mut graph, snap_gen) = if snapshot_path.exists() {
            let (g, generation) = Graph::load_snapshot(&snapshot_path, *load)?;
            (g, Some(generation))
        } else {
            (Graph::new(), None)
        };

        let file = match File::open(&wal_path) {
            Ok(f) => Some(f),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let Some(file) = file else {
            let generation = snap_gen.unwrap_or(0);
            return Self::fresh(graph, snapshot_path, wal_path, generation, false);
        };

        let mut reader = BufReader::new(file);
        let (header, prefix) = read_header(&mut reader)?;
        match header {
            Header::Missing => {
                let generation = snap_gen.unwrap_or(0);
                Self::fresh(graph, snapshot_path, wal_path, generation, false)
            }
            Header::Legacy => {
                let mut chained = prefix.as_slice().chain(reader);
                while let Some((op, _)) = next_frame(&mut chained, false)? {
                    apply_op(&mut graph, op).map_err(WalError::Apply)?;
                }
                // Fold the old-format log into a new snapshot right away.
                let generation = next_generation(snap_gen.unwrap_or(0))?;
                Self::fresh(graph, snapshot_path, wal_path, generation, true)
            }
            Header::V1 {
                generation: wal_gen,
            } => {
                match snap_gen {
                    Some(s) if wal_gen < s => {
                        // Crash after the snapshot was written but before the
                        // WAL was reset: the log is already in the snapshot.
                        return Self::fresh(graph, snapshot_path, wal_path, s, false);
                    }
                    Some(s) if wal_gen > s => {
                        return Err(WalError::GenerationMismatch {
                            snapshot: s,
                            wal: wal_gen,
                        });
                    }
                    _ => {}
                }
                let mut good = WAL_HEADER_LEN;
                while let Some((op, len)) = next_frame(&mut reader, true)? {
                    apply_op(&mut graph, op).map_err(WalError::Apply)?;
                    good += len;
                }
                drop(reader);
                let file = OpenOptions::new().write(true).open(&wal_path)?;
                if file.metadata()?.len() > good {
                    file.set_len(good)?;
                    file.sync_all()?;
                }
                drop(file);
                Ok(Self {
                    file: open_append(&wal_path)?,
                    len: good,
                    broken: false,
                    graph,
                    snapshot_path,
                    wal_path,
                    generation: wal_gen,
                    sync_on_write: false,
                })
            }
        }
    }

    fn fresh(
        graph: Graph,
        snapshot_path: PathBuf,
        wal_path: PathBuf,
        generation: u64,
        write_snapshot: bool,
    ) -> Result<Self, WalError> {
        if write_snapshot || !snapshot_path.exists() {
            graph.save_snapshot(&snapshot_path, generation)?;
        }
        write_wal_header(&wal_path, generation)?;
        Ok(Self {
            file: open_append(&wal_path)?,
            len: WAL_HEADER_LEN,
            broken: false,
            graph,
            snapshot_path,
            wal_path,
            generation,
            sync_on_write: false,
        })
    }

    /// Read-only access to the underlying graph.
    #[must_use]
    pub const fn graph(&self) -> &Graph {
        &self.graph
    }

    /// Consume the writer and return the in-memory graph. Every frame is
    /// already written; nothing else is.
    #[must_use]
    pub fn into_graph(self) -> Graph {
        self.graph
    }

    /// When `true`, every frame is synced to disk (`fdatasync`) before the
    /// mutation returns. Slower, but survives power loss as well as crashes.
    pub const fn set_sync_on_write(&mut self, on: bool) {
        self.sync_on_write = on;
    }

    /// Sync all logged frames to stable storage.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Io`] if flushing or syncing fails.
    pub fn sync(&mut self) -> Result<(), WalError> {
        self.file.sync_data()?;
        Ok(())
    }

    /// Write the graph to a new snapshot and reset the WAL.
    ///
    /// The snapshot is replaced atomically, then the WAL is replaced by an
    /// empty one; a crash at any point leaves a state that
    /// [`open`](Self::open) recovers without loss or double application.
    ///
    /// # Errors
    ///
    /// Returns [`WalError`] if either file cannot be written, or
    /// [`WalError::Io`] if the generation counter is exhausted (only possible
    /// with a damaged or hand-edited snapshot).
    pub fn checkpoint(&mut self) -> Result<(), WalError> {
        let next = next_generation(self.generation)?;
        self.graph.save_snapshot(&self.snapshot_path, next)?;
        // The snapshot is now ahead of the log, so frames appended to the old
        // log would be skipped on open. Refuse writes until the reset is done.
        self.broken = true;
        write_wal_header(&self.wal_path, next)?;
        self.file = open_append(&self.wal_path)?;
        self.len = WAL_HEADER_LEN;
        self.generation = next;
        self.broken = false;
        Ok(())
    }

    fn log(&mut self, op: &WalOp) -> Result<(), WalError> {
        if self.broken {
            return Err(WalError::Io(std::io::Error::other(
                "an earlier write failed; checkpoint or reopen the WAL",
            )));
        }
        if op.too_deep() {
            // It would encode, but replay could not decode it and would stop
            // there, dropping every later frame.
            return Err(WalError::Encode(format!(
                "property value nested deeper than {} lists",
                Value::MAX_DEPTH
            )));
        }
        let payload = opts()
            .serialize(op)
            .map_err(|e| WalError::Encode(e.to_string()))?;
        let len = u32::try_from(payload.len())
            .ok()
            .filter(|&l| l <= MAX_FRAME_BYTES)
            .ok_or_else(|| {
                WalError::Encode(format!(
                    "operation of {} bytes exceeds the {MAX_FRAME_BYTES} byte frame limit",
                    payload.len()
                ))
            })?;
        let mut frame = Vec::with_capacity(payload.len() + 8);
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(&crc32(&payload).to_le_bytes());
        frame.extend_from_slice(&payload);
        let written = self.file.write_all(&frame).and_then(|()| {
            if self.sync_on_write {
                self.file.sync_data()
            } else {
                Ok(())
            }
        });
        if let Err(e) = written {
            // The operation is not applied, so it must not be in the log
            // either, whole or in part.
            if self.file.set_len(self.len).is_err() {
                self.broken = true;
            }
            return Err(e.into());
        }
        self.len += frame.len() as u64;
        Ok(())
    }

    fn need_node(&self, id: NodeId) -> Result<(), WalError> {
        if self.graph.contains_node(id) {
            Ok(())
        } else {
            Err(WalError::Apply(GraphError::NodeNotFound(id)))
        }
    }

    fn need_edge(&self, id: EdgeId) -> Result<(), WalError> {
        if self.graph.contains_edge(id) {
            Ok(())
        } else {
            Err(WalError::Apply(GraphError::EdgeNotFound(id)))
        }
    }

    fn log_and_apply(&mut self, op: WalOp) -> Result<(), WalError> {
        self.log(&op)?;
        apply_op(&mut self.graph, op).map_err(WalError::Apply)
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
        let labels = labels.iter().map(ToString::to_string).collect();
        self.log_and_apply(WalOp::AddNode { id, labels, props })?;
        Ok(id)
    }

    /// Remove a node and all its incident edges — writes to WAL first.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Apply`] if the node does not exist, or
    /// [`WalError::Io`] / [`WalError::Encode`] on WAL write failure.
    pub fn remove_node(&mut self, id: NodeId) -> Result<(), WalError> {
        self.need_node(id)?;
        self.log_and_apply(WalOp::RemoveNode { id })
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
        self.need_node(source)?;
        self.need_node(target)?;
        let id = self.graph.next_edge_id();
        self.log_and_apply(WalOp::AddEdge {
            id,
            source,
            target,
            label: label.to_string(),
            props,
        })?;
        Ok(id)
    }

    /// Remove an edge — writes to WAL first.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Apply`] if the edge does not exist.
    pub fn remove_edge(&mut self, id: EdgeId) -> Result<(), WalError> {
        self.need_edge(id)?;
        self.log_and_apply(WalOp::RemoveEdge { id })
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
        self.need_node(id)?;
        self.log_and_apply(WalOp::SetNodeProp {
            id,
            key: key.to_string(),
            value,
        })
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
        self.need_edge(id)?;
        self.log_and_apply(WalOp::SetEdgeProp {
            id,
            key: key.to_string(),
            value,
        })
    }

    /// Remove a node property — writes to WAL first. Returns the old value.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Apply`] if the node does not exist.
    pub fn remove_node_property(
        &mut self,
        id: NodeId,
        key: &str,
    ) -> Result<Option<Value>, WalError> {
        self.need_node(id)?;
        let old = self.graph.node(id).and_then(|n| n.get(key)).cloned();
        if old.is_some() {
            self.log_and_apply(WalOp::RemoveNodeProp {
                id,
                key: key.to_string(),
            })?;
        }
        Ok(old)
    }

    /// Remove an edge property — writes to WAL first. Returns the old value.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Apply`] if the edge does not exist.
    pub fn remove_edge_property(
        &mut self,
        id: EdgeId,
        key: &str,
    ) -> Result<Option<Value>, WalError> {
        self.need_edge(id)?;
        let old = self.graph.edge(id).and_then(|e| e.get(key)).cloned();
        if old.is_some() {
            self.log_and_apply(WalOp::RemoveEdgeProp {
                id,
                key: key.to_string(),
            })?;
        }
        Ok(old)
    }

    /// Add a label to a node — writes to WAL first. Returns `true` if added.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Apply`] if the node does not exist.
    pub fn add_node_label(&mut self, id: NodeId, label: &str) -> Result<bool, WalError> {
        self.need_node(id)?;
        if self.graph.node(id).is_some_and(|n| n.has_label(label)) {
            return Ok(false);
        }
        self.log_and_apply(WalOp::AddNodeLabel {
            id,
            label: label.to_string(),
        })?;
        Ok(true)
    }

    /// Remove a label from a node — writes to WAL first. Returns `true` if removed.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Apply`] if the node does not exist.
    pub fn remove_node_label(&mut self, id: NodeId, label: &str) -> Result<bool, WalError> {
        self.need_node(id)?;
        if !self.graph.node(id).is_some_and(|n| n.has_label(label)) {
            return Ok(false);
        }
        self.log_and_apply(WalOp::RemoveNodeLabel {
            id,
            label: label.to_string(),
        })?;
        Ok(true)
    }

    /// Create a property index (see [`Graph::create_index`]) — writes to WAL
    /// first. Returns `false` if it already existed.
    ///
    /// # Errors
    ///
    /// Returns [`WalError`] if the WAL write fails.
    pub fn create_index(&mut self, label: &str, key: &str) -> Result<bool, WalError> {
        if self.graph.has_index(label, key) {
            return Ok(false);
        }
        self.log_and_apply(WalOp::CreateIndex {
            label: label.to_string(),
            key: key.to_string(),
        })?;
        Ok(true)
    }

    /// Drop a property index — writes to WAL first. Returns `false` if it
    /// did not exist.
    ///
    /// # Errors
    ///
    /// Returns [`WalError`] if the WAL write fails.
    pub fn drop_index(&mut self, label: &str, key: &str) -> Result<bool, WalError> {
        if !self.graph.has_index(label, key) {
            return Ok(false);
        }
        self.log_and_apply(WalOp::DropIndex {
            label: label.to_string(),
            key: key.to_string(),
        })?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_write_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let (snap, wal) = (dir.path().join("g.bin"), dir.path().join("g.wal"));
        let mut w = WalWriter::create(&snap, &wal).unwrap();
        w.add_node(&["A"], HashMap::new()).unwrap();

        // Swap in a handle that cannot write, as a full disk would behave.
        let read_only = File::open(&wal).unwrap();
        let good = std::mem::replace(&mut w.file, read_only);
        assert!(w.add_node(&["B"], HashMap::new()).is_err());
        // The disk recovers.
        w.file = good;
        let _ = w.add_node(&["C"], HashMap::new());

        let expected: Vec<_> = {
            let mut v: Vec<_> = w
                .graph()
                .nodes()
                .map(|(id, n)| (id, n.labels().to_vec()))
                .collect();
            v.sort();
            v
        };
        drop(w);
        let reopened = WalWriter::open(&snap, &wal).unwrap();
        let mut got: Vec<_> = reopened
            .graph()
            .nodes()
            .map(|(id, n)| (id, n.labels().to_vec()))
            .collect();
        got.sort();
        assert_eq!(got, expected);
    }
}
