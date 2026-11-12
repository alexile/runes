# rune-graph

> Embedded directed property graph: nodes, edges, labels, key-value properties, property indexes, lazy traversal, algorithms, and safe snapshot persistence with an optional write-ahead log.

[![crates.io](https://img.shields.io/crates/v/rune-graph)](https://crates.io/crates/rune-graph)
[![docs.rs](https://img.shields.io/docsrs/rune-graph)](https://docs.rs/rune-graph)
[![license](https://img.shields.io/crates/l/rune-graph)](LICENSE)

## What it does

`rune-graph` is an in-memory directed property graph you embed in your binary. Nodes carry
a set of labels, edges carry one relationship label, and both carry key-value properties
(`Value`: null, bool, int, float, string, list). Forward and reverse adjacency lists keep
neighbour and predecessor queries at O(degree).

- **Indexes.** Node and edge labels are always indexed. Opt-in property indexes on
  `(label, key)` turn equality lookups into hash lookups, and every mutation keeps them in sync.
- **Lazy traversal.** `bfs_iter` and `dfs_iter` follow outgoing, incoming or both edges,
  with an optional edge-label filter and depth limit. They only borrow the graph and buffer
  just the frontier.
- **Algorithms.** Dijkstra, weighted and unweighted shortest paths, weakly and strongly
  connected components, topological sort with a cycle witness, PageRank, degree and
  betweenness centrality, diameter, and density.
- **Safe persistence** (`persist` feature). Snapshots are versioned, CRC-checked, and
  written atomically (temp file, fsync, rename). Loading is size-limited and rejects
  hostile nesting. Also supports JSON, plus JSON Lines import and export.
- **Write-ahead log** (`wal` feature). Every mutation is logged before it is applied.
  On reopen, torn tails are cut off and a crash during a checkpoint can't apply an
  operation twice.

## Installation

```toml
# Core (no dependencies)
rune-graph = "0.4"

# Snapshots, JSON and JSON Lines
rune-graph = { version = "0.4", features = ["persist"] }

# Write-ahead log (implies persist)
rune-graph = { version = "0.4", features = ["wal"] }
```

## Usage

```rust
use rune_graph::{Direction, Graph, Value, algo, props};

let mut g = Graph::new();
g.create_index("Person", "name");

let alice = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
let bob   = g.add_node(&["Person"], props! { "name" => "Bob",   "age" => 25_i64 });
let corp  = g.add_node(&["Org"],    props! { "name" => "Acme" });

g.add_edge(alice, bob,  "KNOWS",    props! { "since" => 2020_i64 }).unwrap();
g.add_edge(alice, corp, "WORKS_AT", props! {}).unwrap();
g.add_edge(bob,   corp, "WORKS_AT", props! {}).unwrap();

// Indexed property lookup
let bobs: Vec<_> = g.nodes_by_property("Person", "name", &Value::from("Bob")).collect();
assert_eq!(bobs, vec![bob]);

// Mutations keep indexes current
g.set_node_property(bob, "name", "Robert".into()).unwrap();
assert_eq!(g.nodes_by_property("Person", "name", &"Bob".into()).count(), 0);

// Several changes at once, still index-safe
g.update_node(alice, |n| {
    n.add_label("Admin");
    n.set("age", Value::Int(31));
}).unwrap();
assert_eq!(g.nodes_with_label("Admin").count(), 1);

// Lazy traversal: everyone who works at Acme (one hop, incoming WORKS_AT)
let staff: Vec<_> = g
    .bfs_iter(corp, Direction::Incoming)
    .edge_label("WORKS_AT")
    .max_depth(1)
    .skip(1)
    .collect();
assert_eq!(staff.len(), 2);

// Algorithms
assert_eq!(g.shortest_path(alice, corp).unwrap(), vec![alice, corp]);
assert!(algo::toposort(&g).is_ok());
let sccs = algo::strongly_connected_components(&g);
assert_eq!(sccs.len(), 3);
```

### Cycle detection

```rust
use rune_graph::{Graph, algo, props};

let mut g = Graph::new();
let a = g.add_node(&["Task"], props! {});
let b = g.add_node(&["Task"], props! {});
g.add_edge(a, b, "BEFORE", props! {}).unwrap();
g.add_edge(b, a, "BEFORE", props! {}).unwrap();

let cycle = algo::toposort(&g).unwrap_err();
assert_eq!(cycle.nodes().len(), 2); // a -> b -> a
```

### Persistence

```rust,no_run
use rune_graph::{Graph, LoadOptions, props};

let mut g = Graph::new();
g.add_node(&["City"], props! { "name" => "Tokyo" });

g.save("cities.bin").unwrap();                    // atomic, versioned, checksummed
let g2 = Graph::load("cities.bin").unwrap();      // default 1 GiB limit
let g3 = Graph::load_with("cities.bin", &LoadOptions::default().max_bytes(64 << 20)).unwrap();

// JSON Lines: one record per line, plain JSON values
let file = std::io::BufWriter::new(std::fs::File::create("cities.jsonl").unwrap());
g.write_jsonl(file).unwrap();
let reader = std::io::BufReader::new(std::fs::File::open("cities.jsonl").unwrap());
let g4 = Graph::read_jsonl(reader).unwrap();
```

```text
{"key":"name","label":"City","type":"index"}
{"id":0,"labels":["City"],"properties":{"name":"Tokyo"},"type":"node"}
{"id":0,"label":"IN","properties":{},"source":0,"target":1,"type":"edge"}
```

Binary snapshot layout: an 8-byte magic `RUNEGRPH`, a `u32` format version, `u32` flags,
a `u64` generation, a `u64` payload length, a `u32` CRC-32 of the payload, and then the
bincode payload. The loader checks the file size before reading anything and decodes
inside that bound. Lists nested deeper than `Value::MAX_DEPTH` are rejected.

### Write-ahead log

```rust,no_run
use rune_graph::{props, Value};
use rune_graph::wal::WalWriter;

let mut w = WalWriter::create("graph.bin", "graph.wal").unwrap();
let alice = w.add_node(&["Person"], props! { "name" => "Alice" }).unwrap();
w.create_index("Person", "name").unwrap();
w.set_node_property(alice, "age", Value::Int(30)).unwrap();
w.sync().unwrap();        // fsync, for power-loss durability
w.checkpoint().unwrap();  // fold the log into a new snapshot

// After a crash:
let w = WalWriter::open("graph.bin", "graph.wal").unwrap();
```

Each frame is flushed before the in-memory graph changes, which survives a process crash.
For power-loss durability, call `sync()` at commit points or use `set_sync_on_write(true)`.

## Thread safety

`Graph` owns all its data and is `Send + Sync`. Any number of threads can read a shared
`&Graph` or `Arc<Graph>` at once. For concurrent writers, wrap it in `RwLock`
(`std::sync` or `tokio::sync`). Mutations take `&mut self`, so no reader ever sees an index
half-updated. `WalWriter` is `Send`; put it behind a `Mutex` to share it.

## API overview

| Area | Items |
|------|-------|
| Nodes | `add_node`, `remove_node`, `node`, `update_node`, `set_node_property`, `remove_node_property`, `add_node_label`, `remove_node_label`, `nodes`, `nodes_with_label`, `find_nodes` |
| Edges | `add_edge`, `remove_edge`, `edge`, `edge_mut`, `set_edge_property`, `remove_edge_property`, `edges`, `edges_with_label`, `match_triples` |
| Indexes | `create_index`, `drop_index`, `has_index`, `indexes`, `nodes_by_property` |
| Traversal | `neighbors`, `predecessors`, `neighbors_directed`, `edges_directed`, `bfs_iter`, `dfs_iter`, `bfs`, `dfs`, `shortest_path`, `has_path`, `degree` |
| `algo` | `dijkstra`, `shortest_weighted_path`, `unweighted_distances`, `weakly_connected_components`, `strongly_connected_components`, `toposort`, `topological_sort`, `topological_sort_relaxed`, `find_cycle`, `has_cycle`, `page_rank`, `degree_centrality`, `betweenness_centrality`, `diameter`, `density`, `in_degree`, `out_degree` |
| `persist` | `save`, `load`, `load_with`, `to_json`, `from_json`, `write_jsonl`, `read_jsonl`, `read_jsonl_with` |
| `wal` | `WalWriter::{create, open, open_with, checkpoint, sync, set_sync_on_write, into_graph}` plus logged versions of every mutation |

For Gremlin-style pipelines (`out`, `in_`, `has`, `dedup`, `limit`, `repeat`), see
[`rune-graph-gremlin`](../rune-graph-gremlin). For triple pattern matching, see
[`rune-graph-match`](../rune-graph-match).

## Migrating from 0.3

- `Graph::node_mut` is gone, because direct mutable access could not keep indexes in sync.
  Use `update_node(id, |n| ...)`, `set_node_property`, `add_node_label` or `remove_node_label`.
- The snapshot format now has a header, so files written by 0.4 can't be read by 0.3.
  0.4 still loads 0.3 snapshots and JSON. A 0.3 WAL is replayed once and rewritten in the
  new format.
- The serialized shape of `Graph` (`to_json`, serde) changed: nodes and edges are now
  lists of records, with sorted keys.
- `WalWriter::create` now writes an empty snapshot and WAL immediately, replacing existing
  files. Before, it appended to an existing WAL.
- `GraphError`, `PersistError` and `WalError` are `#[non_exhaustive]` and have new
  variants (`DuplicateNode`, `DuplicateEdge`, `IdSpaceExhausted`, `TooLarge`,
  `ChecksumMismatch`, `UnsupportedVersion`, `Invalid`, `GenerationMismatch`).
- `topological_sort` is still available. Its tie order is now deterministic (ascending ids).
  The new `toposort` returns the cycle it finds.
- Repeated labels passed to `add_node` are collapsed into one.

## License

MIT
