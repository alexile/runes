//! Snapshot persistence: versioned binary format, JSON, and serde impls.
//!
//! # Binary snapshot layout
//!
//! | Offset | Size | Field |
//! |-------:|-----:|-------|
//! | 0  | 8 | magic `RUNEGRPH` |
//! | 8  | 4 | format version (LE `u32`, currently 1) |
//! | 12 | 4 | flags (reserved, 0) |
//! | 16 | 8 | generation (LE `u64`, used by the WAL) |
//! | 24 | 8 | payload length in bytes (LE `u64`) |
//! | 32 | 4 | CRC-32 (IEEE) of the payload (LE `u32`) |
//! | 36 | n | bincode payload (fixed-width little-endian integers) |
//!
//! Files without the magic are read as the unversioned format written by
//! rune-graph 0.3 and earlier.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bincode::Options;
use serde::de::Error as _;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::checksum::Crc32;
use crate::entry::{EdgeEntry, NodeEntry};
use crate::graph::Graph;
use crate::id::{EdgeId, NodeId};
use crate::value::Value;

pub const MAGIC: &[u8; 8] = b"RUNEGRPH";
pub const FORMAT_VERSION: u32 = 1;
pub const HEADER_LEN: usize = 36;

/// Errors produced by save and load operations.
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "persist")]
/// # {
/// use rune_graph::{Graph, PersistError};
/// let result = Graph::load("/nonexistent/path.bin");
/// assert!(matches!(result, Err(PersistError::Io(_))));
/// # }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum PersistError {
    /// An I/O error occurred while reading or writing.
    Io(std::io::Error),
    /// The data could not be decoded (corrupt, truncated, or not a graph).
    Decode(String),
    /// The graph could not be encoded.
    Encode(String),
    /// The input is larger than the configured limit.
    TooLarge {
        /// The limit in bytes.
        limit: u64,
        /// The size that was found (or at least read) in bytes.
        actual: u64,
    },
    /// The payload checksum does not match the header.
    ChecksumMismatch {
        /// Checksum recorded in the header.
        expected: u32,
        /// Checksum of the payload actually read.
        actual: u32,
    },
    /// The snapshot was written by a newer, unknown format version.
    UnsupportedVersion(u32),
    /// The data decoded but describes an inconsistent graph (for example an
    /// edge pointing at a missing node, or a duplicate id).
    Invalid(String),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Decode(e) => write!(f, "decode error: {e}"),
            Self::Encode(e) => write!(f, "encode error: {e}"),
            Self::TooLarge { limit, actual } => {
                write!(f, "input of {actual} bytes exceeds the {limit} byte limit")
            }
            Self::ChecksumMismatch { expected, actual } => write!(
                f,
                "checksum mismatch: header says {expected:#010x}, payload is {actual:#010x}"
            ),
            Self::UnsupportedVersion(v) => write!(f, "unsupported snapshot format version {v}"),
            Self::Invalid(e) => write!(f, "invalid graph data: {e}"),
        }
    }
}

impl std::error::Error for PersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

impl From<std::io::Error> for PersistError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Limits applied when loading a snapshot with [`Graph::load_with`].
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "persist")]
/// # {
/// use rune_graph::LoadOptions;
/// let opts = LoadOptions::default().max_bytes(64 * 1024 * 1024);
/// assert_eq!(opts.max_bytes_limit(), 64 * 1024 * 1024);
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadOptions {
    max_bytes: u64,
}

impl LoadOptions {
    /// Default payload limit: 1 GiB.
    pub const DEFAULT_MAX_BYTES: u64 = 1 << 30;

    /// Refuse snapshots whose payload is larger than `bytes`.
    #[must_use]
    pub const fn max_bytes(mut self, bytes: u64) -> Self {
        self.max_bytes = bytes;
        self
    }

    /// The configured payload limit in bytes.
    #[must_use]
    pub const fn max_bytes_limit(&self) -> u64 {
        self.max_bytes
    }
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            max_bytes: Self::DEFAULT_MAX_BYTES,
        }
    }
}

// ── serde representation ─────────────────────────────────────────────────────

fn sorted_props(props: &HashMap<String, Value>) -> Vec<(&String, &Value)> {
    let mut v: Vec<_> = props.iter().collect();
    v.sort_unstable_by(|a, b| a.0.cmp(b.0));
    v
}

struct PropsSer<'a>(&'a HashMap<String, Value>);

impl Serialize for PropsSer<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(sorted_props(self.0))
    }
}

#[derive(Serialize)]
struct NodeRecordRef<'a> {
    id: NodeId,
    labels: &'a [String],
    properties: PropsSer<'a>,
}

#[derive(Serialize)]
struct EdgeRecordRef<'a> {
    id: EdgeId,
    source: NodeId,
    target: NodeId,
    label: &'a str,
    properties: PropsSer<'a>,
}

#[derive(Deserialize)]
struct NodeRecord {
    id: NodeId,
    labels: Vec<String>,
    properties: HashMap<String, Value>,
}

#[derive(Deserialize)]
struct EdgeRecord {
    id: EdgeId,
    source: NodeId,
    target: NodeId,
    label: String,
    properties: HashMap<String, Value>,
}

#[derive(Deserialize)]
struct GraphRepr {
    format: u32,
    nodes: Vec<NodeRecord>,
    edges: Vec<EdgeRecord>,
    next_node: u64,
    next_edge: u64,
    indexes: Vec<(String, String)>,
}

/// Layout of `Graph` as serialized by rune-graph 0.3 and earlier.
#[derive(Deserialize)]
struct LegacyGraph {
    nodes: HashMap<NodeId, NodeEntry>,
    edges: HashMap<EdgeId, EdgeEntry>,
    #[allow(dead_code, reason = "rebuilt from the edge list instead")]
    out_edges: HashMap<NodeId, Vec<EdgeId>>,
    #[allow(dead_code, reason = "rebuilt from the edge list instead")]
    in_edges: HashMap<NodeId, Vec<EdgeId>>,
    next_node: u64,
    next_edge: u64,
}

struct SeqSer<I>(std::cell::Cell<Option<I>>);

impl<I, T> Serialize for SeqSer<I>
where
    I: ExactSizeIterator<Item = T>,
    T: Serialize,
{
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let it = self
            .0
            .take()
            .ok_or_else(|| serde::ser::Error::custom("sequence serialized twice"))?;
        s.collect_seq(it)
    }
}

impl Serialize for Graph {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut nodes: Vec<(NodeId, &NodeEntry)> = self.nodes().collect();
        nodes.sort_unstable_by_key(|(id, _)| *id);
        let mut edges: Vec<(EdgeId, &EdgeEntry)> = self.edges().collect();
        edges.sort_unstable_by_key(|(id, _)| *id);
        let mut indexes: Vec<(&str, &str)> = self.indexes().collect();
        indexes.sort_unstable();

        let mut st = s.serialize_struct("Graph", 6)?;
        st.serialize_field("format", &FORMAT_VERSION)?;
        st.serialize_field(
            "nodes",
            &SeqSer(std::cell::Cell::new(Some(nodes.into_iter().map(
                |(id, n)| NodeRecordRef {
                    id,
                    labels: n.labels(),
                    properties: PropsSer(n.properties()),
                },
            )))),
        )?;
        st.serialize_field(
            "edges",
            &SeqSer(std::cell::Cell::new(Some(edges.into_iter().map(
                |(id, e)| EdgeRecordRef {
                    id,
                    source: e.source(),
                    target: e.target(),
                    label: e.label(),
                    properties: PropsSer(e.properties()),
                },
            )))),
        )?;
        st.serialize_field("next_node", &self.next_node)?;
        st.serialize_field("next_edge", &self.next_edge)?;
        st.serialize_field("indexes", &indexes)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for Graph {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let repr = GraphRepr::deserialize(d)?;
        Self::from_repr(repr).map_err(|e| D::Error::custom(e.to_string()))
    }
}

fn invalid(e: impl std::fmt::Display) -> PersistError {
    PersistError::Invalid(e.to_string())
}

fn has_non_finite(value: &Value) -> bool {
    let mut stack = vec![value];
    while let Some(v) = stack.pop() {
        match v {
            Value::Float(x) if !x.is_finite() => return true,
            Value::List(items) => stack.extend(items),
            _ => {}
        }
    }
    false
}

fn check_counter(next: u64, what: &str) -> Result<(), PersistError> {
    if next > crate::graph::MAX_RESTORED_ID {
        return Err(invalid(format!("next {what} id {next} is out of range")));
    }
    Ok(())
}

impl Graph {
    fn from_repr(repr: GraphRepr) -> Result<Self, PersistError> {
        if repr.format != FORMAT_VERSION {
            return Err(PersistError::UnsupportedVersion(repr.format));
        }
        check_counter(repr.next_node, "node")?;
        check_counter(repr.next_edge, "edge")?;
        let mut g = Self::new();
        for (label, key) in &repr.indexes {
            g.create_index(label, key);
        }
        for n in repr.nodes {
            g.insert_node_with_id(n.id, NodeEntry::from_parts(n.labels, n.properties))
                .map_err(invalid)?;
        }
        for e in repr.edges {
            g.insert_edge_with_id(
                e.id,
                EdgeEntry {
                    source: e.source,
                    target: e.target,
                    label: e.label,
                    properties: e.properties,
                },
            )
            .map_err(invalid)?;
        }
        g.next_node = g.next_node.max(repr.next_node);
        g.next_edge = g.next_edge.max(repr.next_edge);
        Ok(g)
    }

    fn from_legacy(legacy: LegacyGraph) -> Result<Self, PersistError> {
        check_counter(legacy.next_node, "node")?;
        check_counter(legacy.next_edge, "edge")?;
        let mut g = Self::new();
        let mut nodes: Vec<_> = legacy.nodes.into_iter().collect();
        nodes.sort_unstable_by_key(|(id, _)| *id);
        for (id, entry) in nodes {
            g.insert_node_with_id(id, entry).map_err(invalid)?;
        }
        // Edge ids are allocated in insertion order, so sorting by id
        // restores the original adjacency order.
        let mut edges: Vec<_> = legacy.edges.into_iter().collect();
        edges.sort_unstable_by_key(|(id, _)| *id);
        for (id, entry) in edges {
            g.insert_edge_with_id(id, entry).map_err(invalid)?;
        }
        g.next_node = g.next_node.max(legacy.next_node);
        g.next_edge = g.next_edge.max(legacy.next_edge);
        Ok(g)
    }
}

// ── binary snapshots ─────────────────────────────────────────────────────────

fn bincode_opts() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
}

struct CrcWriter<W> {
    inner: W,
    crc: Crc32,
    len: u64,
}

impl<W: Write> Write for CrcWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        if let Some(written) = buf.get(..n) {
            self.crc.update(written);
        }
        self.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(path: &Path) -> Result<PathBuf, PersistError> {
    let name = path.file_name().ok_or_else(|| {
        PersistError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "snapshot path has no file name",
        ))
    })?;
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(path.with_file_name(format!(
        ".{}.{}.{n}.tmp",
        name.to_string_lossy(),
        std::process::id()
    )))
}

fn sync_parent(path: &Path) {
    #[cfg(unix)]
    {
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        // Best effort: some filesystems refuse fsync on directories.
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Write a file by filling a temporary sibling, syncing it, and renaming it
/// over `path`. Readers see either the old file or the complete new one.
pub fn atomic_write(
    path: &Path,
    fill: impl FnOnce(&mut File) -> Result<(), PersistError>,
) -> Result<(), PersistError> {
    let tmp = temp_path(path)?;
    let result = (|| {
        let mut out = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        fill(&mut out)?;
        out.sync_all()?;
        drop(out);
        std::fs::rename(&tmp, path)?;
        sync_parent(path);
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn le_u64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

impl Graph {
    /// Write the graph to a binary snapshot file.
    ///
    /// The write is atomic: data goes to a temporary file next to `path`,
    /// which is synced and then renamed over `path`. A crash leaves either
    /// the previous file or the complete new one, never a torn mix. The
    /// snapshot carries a format version and a CRC-32 of the payload, and is
    /// byte-for-byte deterministic for a given graph.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] on encode failure or I/O error.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "persist")]
    /// # {
    /// use rune_graph::{Graph, props};
    ///
    /// let dir = std::env::temp_dir().join(format!("rune-graph-doc-save-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).unwrap();
    /// let path = dir.join("graph.bin");
    ///
    /// let mut g = Graph::new();
    /// g.add_node(&["Person"], props! { "name" => "Alice" });
    /// g.save(&path).unwrap();
    /// assert_eq!(Graph::load(&path).unwrap().node_count(), 1);
    /// # std::fs::remove_dir_all(&dir).unwrap();
    /// # }
    /// ```
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), PersistError> {
        self.save_snapshot(path.as_ref(), 0)
    }

    pub(crate) fn save_snapshot(&self, path: &Path, generation: u64) -> Result<(), PersistError> {
        atomic_write(path, |file| {
            let mut w = BufWriter::new(&mut *file);
            w.write_all(&[0u8; HEADER_LEN])?;
            let mut cw = CrcWriter {
                inner: &mut w,
                crc: Crc32::new(),
                len: 0,
            };
            bincode_opts()
                .serialize_into(&mut cw, self)
                .map_err(|e| PersistError::Encode(e.to_string()))?;
            let (crc, len) = (cw.crc.finish(), cw.len);
            w.flush()?;
            drop(w);

            let mut header = Vec::with_capacity(HEADER_LEN);
            header.extend_from_slice(MAGIC);
            header.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
            header.extend_from_slice(&0u32.to_le_bytes());
            header.extend_from_slice(&generation.to_le_bytes());
            header.extend_from_slice(&len.to_le_bytes());
            header.extend_from_slice(&crc.to_le_bytes());
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&header)?;
            Ok(())
        })
    }

    /// Load a snapshot written by [`save`](Self::save), with the default
    /// [`LoadOptions`] (1 GiB limit).
    ///
    /// Snapshots written by rune-graph 0.3 and earlier (no header) are also
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] if the file cannot be read, is larger than
    /// the limit, fails its checksum, or does not describe a valid graph.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "persist")]
    /// # {
    /// use rune_graph::Graph;
    ///
    /// let g = Graph::load("graph.bin").unwrap();
    /// println!("{} nodes loaded", g.node_count());
    /// # }
    /// ```
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PersistError> {
        Self::load_with(path, &LoadOptions::default())
    }

    /// Load a snapshot with explicit limits.
    ///
    /// The file size is checked before anything is read, and decoding is
    /// bounded by the payload size, so a hostile file cannot make the loader
    /// allocate much more than `max_bytes` (plus the graph it describes).
    ///
    /// # Errors
    ///
    /// Same as [`load`](Self::load); [`PersistError::TooLarge`] if the file
    /// exceeds `opts`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "persist")]
    /// # {
    /// use rune_graph::{Graph, LoadOptions, PersistError, props};
    ///
    /// let dir = std::env::temp_dir().join(format!("rune-graph-doc-limit-{}", std::process::id()));
    /// std::fs::create_dir_all(&dir).unwrap();
    /// let path = dir.join("graph.bin");
    /// let mut g = Graph::new();
    /// g.add_node(&["Big"], props! { "blob" => "x".repeat(1000) });
    /// g.save(&path).unwrap();
    ///
    /// let err = Graph::load_with(&path, &LoadOptions::default().max_bytes(100)).unwrap_err();
    /// assert!(matches!(err, PersistError::TooLarge { .. }));
    /// # std::fs::remove_dir_all(&dir).unwrap();
    /// # }
    /// ```
    pub fn load_with(path: impl AsRef<Path>, opts: &LoadOptions) -> Result<Self, PersistError> {
        Self::load_snapshot(path.as_ref(), *opts).map(|(g, _)| g)
    }

    pub(crate) fn load_snapshot(
        path: &Path,
        opts: LoadOptions,
    ) -> Result<(Self, u64), PersistError> {
        let file = File::open(path)?;
        let limit = opts.max_bytes.saturating_add(HEADER_LEN as u64);
        let size = file.metadata()?.len();
        if size > limit {
            return Err(PersistError::TooLarge {
                limit: opts.max_bytes,
                actual: size,
            });
        }
        let cap = usize::try_from(size).unwrap_or(0);
        let mut bytes = Vec::with_capacity(cap);
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(PersistError::TooLarge {
                limit: opts.max_bytes,
                actual: bytes.len() as u64,
            });
        }
        Self::decode_snapshot(&bytes)
    }

    fn decode_snapshot(bytes: &[u8]) -> Result<(Self, u64), PersistError> {
        if !bytes.starts_with(MAGIC) {
            let legacy: LegacyGraph = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(bytes.len() as u64)
                .deserialize(bytes)
                .map_err(|e| PersistError::Decode(e.to_string()))?;
            return Ok((Self::from_legacy(legacy)?, 0));
        }
        let short = || PersistError::Decode("snapshot header is truncated".into());
        let version = le_u32(bytes, 8).ok_or_else(short)?;
        if version != FORMAT_VERSION {
            return Err(PersistError::UnsupportedVersion(version));
        }
        let generation = le_u64(bytes, 16).ok_or_else(short)?;
        let len = le_u64(bytes, 24).ok_or_else(short)?;
        let expected = le_u32(bytes, 32).ok_or_else(short)?;
        let payload = bytes.get(HEADER_LEN..).ok_or_else(short)?;
        if payload.len() as u64 != len {
            return Err(PersistError::Decode(format!(
                "payload is {} bytes, header says {len}",
                payload.len()
            )));
        }
        let actual = crate::checksum::crc32(payload);
        if actual != expected {
            return Err(PersistError::ChecksumMismatch { expected, actual });
        }
        let repr: GraphRepr = bincode_opts()
            .with_limit(len)
            .deserialize(payload)
            .map_err(|e| PersistError::Decode(e.to_string()))?;
        Ok((Self::from_repr(repr)?, generation))
    }

    /// Serialize the graph to a JSON string.
    ///
    /// Nodes, edges and property keys are written in a stable order. For
    /// streaming or line-oriented exchange, see
    /// [`write_jsonl`](Self::write_jsonl).
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::Encode`] if serialization fails (for example
    /// a non-finite float, which JSON cannot represent).
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "persist")]
    /// # {
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// g.add_node(&["City"], props! { "name" => "Paris" });
    /// let json = g.to_json().unwrap();
    /// assert!(json.contains("Paris"));
    /// # }
    /// ```
    pub fn to_json(&self) -> Result<String, PersistError> {
        // serde_json writes NaN and infinities as `null`, which `from_json`
        // cannot read back, so refuse them up front.
        let props = self
            .nodes()
            .map(|(_, n)| n.properties())
            .chain(self.edges().map(|(_, e)| e.properties()));
        for map in props {
            for (key, value) in map {
                if has_non_finite(value) {
                    return Err(PersistError::Encode(format!(
                        "property `{key}` holds a non-finite float, which JSON cannot represent"
                    )));
                }
            }
        }
        serde_json::to_string(self).map_err(|e| PersistError::Encode(e.to_string()))
    }

    /// Deserialize a graph from a JSON string produced by
    /// [`to_json`](Self::to_json). JSON written by rune-graph 0.3 is also
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::Decode`] if the JSON is invalid or does not
    /// describe a consistent graph.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "persist")]
    /// # {
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// g.add_node(&["City"], props! { "name" => "Berlin" });
    /// let json = g.to_json().unwrap();
    /// let g2 = Graph::from_json(&json).unwrap();
    /// assert_eq!(g2.node_count(), 1);
    /// # }
    /// ```
    pub fn from_json(json: &str) -> Result<Self, PersistError> {
        match serde_json::from_str::<Self>(json) {
            Ok(g) => Ok(g),
            Err(err) => serde_json::from_str::<LegacyGraph>(json).map_or_else(
                |_| Err(PersistError::Decode(err.to_string())),
                Self::from_legacy,
            ),
        }
    }
}
