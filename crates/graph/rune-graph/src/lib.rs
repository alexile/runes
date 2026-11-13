//! Embedded directed property graph.
//!
//! `rune-graph` is an in-memory property graph you embed in your binary: no
//! server, no configuration. Nodes carry a set of labels, edges carry one
//! relationship label, and both carry key-value [`Value`] properties.
//! Forward and reverse adjacency lists make neighbour, predecessor and
//! traversal queries O(degree).
//!
//! # Features
//!
//! - [`Graph`]: CRUD for nodes and edges, label lookups in O(matches)
//! - Property indexes: [`Graph::create_index`] + [`Graph::nodes_by_property`],
//!   kept in sync by every mutation
//! - Lazy traversal: [`Graph::bfs_iter`] / [`Graph::dfs_iter`] with
//!   [`Direction`], edge-label filter and depth limit
//! - [`algo`]: Dijkstra, weighted and unweighted shortest paths, weakly and
//!   strongly connected components, topological sort with cycle witness,
//!   `PageRank`, degree and betweenness centrality, diameter, density
//! - `persist` feature: versioned, checksummed, atomically written binary
//!   snapshots with a load size limit; JSON; JSON Lines import/export
//! - `wal` feature: write-ahead log with crash recovery
//!
//! # Quick start
//!
//! ```rust
//! use rune_graph::{Direction, Graph, Value, algo, props};
//!
//! let mut g = Graph::new();
//! g.create_index("Person", "name");
//!
//! let alice = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
//! let bob   = g.add_node(&["Person"], props! { "name" => "Bob",   "age" => 25_i64 });
//! let corp  = g.add_node(&["Org"],    props! { "name" => "Acme"  });
//!
//! g.add_edge(alice, bob,  "KNOWS",    props! { "since" => 2020_i64 }).unwrap();
//! g.add_edge(alice, corp, "WORKS_AT", props! { "w" => 1.0_f64 }).unwrap();
//! g.add_edge(bob,   corp, "WORKS_AT", props! { "w" => 2.0_f64 }).unwrap();
//!
//! // Indexed lookup
//! let found: Vec<_> = g.nodes_by_property("Person", "name", &Value::from("Bob")).collect();
//! assert_eq!(found, vec![bob]);
//!
//! // Who works at Acme? Walk WORKS_AT edges backwards, one hop.
//! let staff: Vec<_> = g
//!     .bfs_iter(corp, Direction::Incoming)
//!     .edge_label("WORKS_AT")
//!     .max_depth(1)
//!     .skip(1)
//!     .collect();
//! assert_eq!(staff.len(), 2);
//!
//! // Algorithms
//! let dist = algo::dijkstra(&g, alice, "w");
//! assert_eq!(dist[&corp], 1.0);
//! assert!(algo::toposort(&g).is_ok());
//! ```
//!
//! # Persistence (`persist` feature)
//!
//! ```rust
//! # #[cfg(feature = "persist")]
//! # {
//! use rune_graph::{Graph, LoadOptions, props};
//!
//! let dir = std::env::temp_dir().join(format!("rune-graph-lib-doc-{}", std::process::id()));
//! std::fs::create_dir_all(&dir).unwrap();
//! let path = dir.join("cities.bin");
//!
//! let mut g = Graph::new();
//! g.add_node(&["City"], props! { "name" => "Tokyo" });
//! g.save(&path).unwrap(); // temp file + fsync + rename
//!
//! let g2 = Graph::load_with(&path, &LoadOptions::default().max_bytes(16 << 20)).unwrap();
//! assert_eq!(g2.node_count(), 1);
//!
//! // JSON Lines, one node or edge per line
//! let mut out = Vec::new();
//! g2.write_jsonl(&mut out).unwrap();
//! assert_eq!(Graph::read_jsonl(out.as_slice()).unwrap().node_count(), 1);
//! # std::fs::remove_dir_all(&dir).unwrap();
//! # }
//! ```
//!
//! Snapshots start with a header holding a magic number, a format version
//! and a CRC-32 of the payload; see [`Graph::save`]. Snapshots and JSON from
//! 0.3 still load.
//!
//! ## JSON Lines
//!
//! [`Graph::write_jsonl`] writes one object per line: index definitions,
//! then nodes, then edges, each sorted by id. Property values are plain JSON.
//! If the newest nodes or edges were removed, a leading `"type":"ids"` line
//! keeps the id counters so those ids are not reused after a reload.
//!
//! ```text
//! {"key":"name","label":"Person","type":"index"}
//! {"id":0,"labels":["Person"],"properties":{"age":30,"name":"Alice"},"type":"node"}
//! {"id":0,"label":"KNOWS","properties":{},"source":0,"target":1,"type":"edge"}
//! ```
//!
//! # Write-ahead log (`wal` feature)
//!
//! [`wal::WalWriter`] logs each mutation before applying it and replays the
//! log on open. See the [`wal`] module for the file format and durability
//! guarantees.
//!
//! # Thread safety
//!
//! [`Graph`] owns all its data and is `Send + Sync`. Any number of threads
//! may read a shared `&Graph` (or `Arc<Graph>`) at once; traversal iterators
//! only borrow it. For concurrent writers wrap it in `std::sync::RwLock`
//! (or `tokio::sync::RwLock` in async code): every mutation takes `&mut self`,
//! so the borrow checker guarantees indexes are never observed half-updated.
//!
//! ```rust
//! use std::sync::{Arc, RwLock};
//! use rune_graph::{Graph, props};
//!
//! let g = Arc::new(RwLock::new(Graph::new()));
//! let writer = {
//!     let g = Arc::clone(&g);
//!     std::thread::spawn(move || {
//!         g.write().unwrap().add_node(&["Job"], props! {});
//!     })
//! };
//! writer.join().unwrap();
//! assert_eq!(g.read().unwrap().node_count(), 1);
//! ```

/// Graph algorithms: traversal, shortest paths and components.
pub mod algo;
#[cfg(feature = "persist")]
mod checksum;
mod entry;
mod error;
mod graph;
mod id;
mod index;
#[cfg(feature = "persist")]
mod jsonl;
mod traverse;
mod value;

#[cfg(feature = "persist")]
mod persist;

#[cfg(feature = "wal")]
pub mod wal;

#[cfg(test)]
mod algo_tests;
#[cfg(test)]
mod persist_tests;
#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "wal"))]
mod wal_tests;

pub use entry::{EdgeEntry, NodeEntry};
pub use error::GraphError;
pub use graph::Graph;
pub use id::{EdgeId, NodeId};
pub use index::PropertyMatches;
pub use traverse::{Bfs, Dfs, Direction};
pub use value::Value;

#[cfg(feature = "persist")]
pub use jsonl::JsonlOptions;
#[cfg(feature = "persist")]
pub use persist::{LoadOptions, PersistError};

impl NodeId {
    /// Construct a `NodeId` from a raw integer. Useful for testing and
    /// serialisation round-trips; prefer [`Graph::add_node`] in production.
    #[must_use]
    pub const fn from(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw integer behind this id.
    ///
    /// ```rust
    /// assert_eq!(rune_graph::NodeId::from(3).as_u64(), 3);
    /// ```
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl EdgeId {
    /// Construct an `EdgeId` from a raw integer.
    #[must_use]
    pub const fn from(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw integer behind this id.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Build a property map from `key => value` pairs.
///
/// Keys are converted to `String`; values are converted via [`Value::from`].
/// Pass an empty invocation (`props! {}`) to produce an empty map.
///
/// # Example
///
/// ```rust
/// use rune_graph::{props, Value};
/// use std::collections::HashMap;
///
/// let p = props! {
///     "name"  => "Alice",
///     "age"   => 30_i64,
///     "admin" => false,
/// };
/// assert_eq!(p["name"],  Value::Str("Alice".to_string()));
/// assert_eq!(p["age"],   Value::Int(30));
/// assert_eq!(p["admin"], Value::Bool(false));
/// ```
#[macro_export]
macro_rules! props {
    () => {
        ::std::collections::HashMap::<String, $crate::Value>::new()
    };
    ($($key:expr => $val:expr),+ $(,)?) => {{
        let mut map = ::std::collections::HashMap::<String, $crate::Value>::new();
        $(map.insert($key.to_string(), $crate::Value::from($val));)+
        map
    }};
}
