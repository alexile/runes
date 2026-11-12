//! Embedded directed property graph — the `rune-graph` primitive.
//!
//! `rune-graph` is an in-memory property graph designed as a first-class data
//! primitive for the `rune-*` ecosystem. Think SQLite for graphs: embed it in
//! your binary and it just works — no server, no JVM, no configuration.
//!
//! Nodes and edges carry arbitrary key-value [`Value`] properties and string
//! labels / relationship types. Forward *and* reverse adjacency lists are
//! maintained so BFS, DFS, neighbor, and predecessor queries are all O(degree).
//!
//! # Features
//!
//! - [`Graph`] — directed property graph with full CRUD for nodes and edges
//! - [`NodeId`] / [`EdgeId`] — stable integer handles, never reused
//! - [`Value`] — property value type covering bool, int, float, string, list, null
//! - [`NodeEntry`] / [`EdgeEntry`] — inspectable node and edge data
//! - [`GraphError`] — typed errors for missing nodes / edges
//! - [`props!`] macro — ergonomic property map construction
//! - Traversal: BFS, DFS, `shortest_path` (unweighted), `has_path`
//! - [`algo`] module: Dijkstra, connected components, topological sort (strict + cycle-tolerant), `PageRank`, degree
//! - `persist` feature: `save` / `load` (bincode) + `to_json` / `from_json`
//!
//! # Quick Start
//!
//! ```rust
//! use rune_graph::{Graph, Value, algo, props};
//!
//! let mut g = Graph::new();
//!
//! let alice = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
//! let bob   = g.add_node(&["Person"], props! { "name" => "Bob",   "age" => 25_i64 });
//! let corp  = g.add_node(&["Org"],    props! { "name" => "Acme"  });
//!
//! g.add_edge(alice, bob,  "KNOWS",    props! { "since" => 2020_i64 }).unwrap();
//! g.add_edge(alice, corp, "WORKS_AT", props! { "w" => 1.0_f64 }).unwrap();
//! g.add_edge(bob,   corp, "WORKS_AT", props! { "w" => 2.0_f64 }).unwrap();
//!
//! // Traversal
//! let coworkers: Vec<_> = g.neighbors(alice).collect();
//! assert_eq!(coworkers.len(), 2);
//!
//! // Label filter
//! let people: Vec<_> = g.nodes_with_label("Person").collect();
//! assert_eq!(people.len(), 2);
//!
//! // Dijkstra
//! let dist = algo::dijkstra(&g, alice, "w");
//! assert_eq!(dist[&corp], 1.0);
//!
//! // PageRank
//! let scores = algo::page_rank(&g, 0.85, 50);
//! assert!(scores[&corp] > scores[&alice]);
//! ```
//!
//! # Persistence (optional feature)
//!
//! Enable the `persist` feature for save/load support:
//!
//! ```toml
//! rune-graph = { version = "0.2", features = ["persist"] }
//! ```
//!
//! ```rust,no_run
//! # #[cfg(feature = "persist")]
//! # {
//! use rune_graph::{Graph, props};
//! let mut g = Graph::new();
//! g.add_node(&["City"], props! { "name" => "Tokyo" });
//! g.save("cities.bin").unwrap();
//! let g2 = Graph::load("cities.bin").unwrap();
//! assert_eq!(g2.node_count(), 1);
//! # }
//! ```
//!
//! # WAL — crash-safe writes (optional feature)
//!
//! Enable the `wal` feature (implies `persist`) for write-ahead log support:
//!
//! ```toml
//! rune-graph = { version = "0.3", features = ["wal"] }
//! ```
//!
//! ```rust,no_run
//! # #[cfg(feature = "wal")]
//! # {
//! use rune_graph::{props, Value};
//! use rune_graph::wal::WalWriter;
//!
//! let mut w = WalWriter::create("graph.bin", "graph.wal").unwrap();
//! let alice = w.add_node(&["Person"], props! { "name" => "Alice" }).unwrap();
//! w.checkpoint().unwrap(); // compact WAL into snapshot
//!
//! // After any crash, open() replays the WAL on top of the snapshot:
//! // let w2 = WalWriter::open("graph.bin", "graph.wal").unwrap();
//! # }
//! ```
//!
//! # Roadmap
//!
//! | Phase | Description | Status |
//! |-------|-------------|--------|
//! | 1 | In-memory directed property graph | ✅ done |
//! | 2 | Algorithms + snapshot persistence (bincode + JSON) | ✅ done |
//! | 3 | Write-ahead log for crash recovery | ✅ done |
//! | 4 | Page-backed on-disk storage | planned |
//! | 5 | Query language (Cypher subset) | planned |

/// Graph algorithms: traversal, shortest paths and components.
pub mod algo;
mod entry;
mod error;
mod graph;
mod id;
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
pub use value::Value;

#[cfg(feature = "persist")]
pub use persist::PersistError;

impl NodeId {
    /// Construct a `NodeId` from a raw integer. Useful for testing and
    /// serialisation round-trips; prefer [`Graph::add_node`] in production.
    #[must_use]
    pub const fn from(raw: u64) -> Self {
        Self(raw)
    }
}

impl EdgeId {
    /// Construct an `EdgeId` from a raw integer.
    #[must_use]
    pub const fn from(raw: u64) -> Self {
        Self(raw)
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
