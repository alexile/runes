# rune-graph

> Embedded directed property graph with algorithms, snapshot persistence, and crash-safe write-ahead log.

[![crates.io](https://img.shields.io/crates/v/rune-graph)](https://crates.io/crates/rune-graph)
[![docs.rs](https://img.shields.io/docsrs/rune-graph)](https://docs.rs/rune-graph)
[![license](https://img.shields.io/crates/l/rune-graph)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-graph` is a zero-dependency in-memory directed property graph. Nodes and edges carry
arbitrary key-value properties (`Value` enum) and string labels / relationship types.
Forward and reverse adjacency lists are maintained, making BFS, DFS, neighbor, and
predecessor queries all O(degree).

Designed as a first-class data primitive for the `rune-*` ecosystem: embed it as a
knowledge store for LLM agents, a graph-structured memory backend, or a lightweight
audit trail — no server, no JVM, no configuration required.

## Installation

```toml
# Core (zero dependencies)
rune-graph = "0.3"

# With snapshot persistence (bincode + JSON)
rune-graph = { version = "0.3", features = ["persist"] }

# With crash-safe WAL (implies persist)
rune-graph = { version = "0.3", features = ["wal"] }
```

## Usage

```rust
use rune_graph::{Graph, Value, props};

let mut g = Graph::new();

let alice = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
let bob   = g.add_node(&["Person"], props! { "name" => "Bob",   "age" => 25_i64 });
let corp  = g.add_node(&["Org"],    props! { "name" => "Acme" });

g.add_edge(alice, bob,  "KNOWS",    props! { "since" => 2020_i64 }).unwrap();
g.add_edge(alice, corp, "WORKS_AT", props! {}).unwrap();
g.add_edge(bob,   corp, "WORKS_AT", props! {}).unwrap();

// Traverse
let coworkers: Vec<_> = g.neighbors(alice).collect();
assert_eq!(coworkers.len(), 2);

// Filter by label
let people: Vec<_> = g.nodes_with_label("Person").collect();
assert_eq!(people.len(), 2);

// Shortest path
let path = g.shortest_path(bob, corp).unwrap();
assert_eq!(path.len(), 2); // [bob, corp]
```

## API highlights

**Core graph**

| Method | Description |
|--------|-------------|
| `add_node(&[label], props!)` | Insert a node, returns `NodeId` |
| `add_edge(src, dst, "TYPE", props!)` | Insert a directed edge, returns `EdgeId` |
| `remove_node(id)` | Remove node and all incident edges |
| `neighbors(id)` / `predecessors(id)` | Direct successors / predecessors |
| `bfs(start)` / `dfs(start)` | Full traversal, returns visit order |
| `shortest_path(from, to)` | Unweighted BFS shortest path |
| `has_path(from, to)` | Reachability check |
| `nodes_with_label(l)` / `edges_with_label(l)` | Filter by label / type |
| `find_nodes(predicate)` | Filter nodes by property predicate |

**Algorithms (`rune_graph::algo`)**

| Function | Description |
|----------|-------------|
| `dijkstra(&g, start, "weight")` | Shortest distances from start to all reachable nodes |
| `shortest_weighted_path(&g, from, to, "weight")` | Optimal path + total distance |
| `weakly_connected_components(&g)` | Partition into clusters (edges treated as undirected) |
| `topological_sort(&g)` | Kahn's algorithm — returns `None` on cycles |
| `page_rank(&g, damping, iterations)` | Importance scores (sum to 1.0) |
| `in_degree(&g, node)` / `out_degree(&g, node)` | Edge count per direction |

**Persistence (`persist` feature)**

| Method | Description |
|--------|-------------|
| `g.save("file.bin")` | Write bincode snapshot |
| `Graph::load("file.bin")` | Read bincode snapshot |
| `g.to_json()` | Serialise to JSON string |
| `Graph::from_json(&s)` | Deserialise from JSON string |

**WAL — crash-safe writes (`wal` feature)**

`WalWriter` wraps a `Graph` and records every mutation to an append-only WAL file *before* applying it. On restart, `WalWriter::open` replays the WAL on top of the last snapshot, recovering all completed operations automatically.

```rust,no_run
use rune_graph::{props, Value};
use rune_graph::wal::WalWriter;

// Create (or re-open after a crash):
let mut w = WalWriter::create("graph.bin", "graph.wal").unwrap();
let alice = w.add_node(&["Person"], props! { "name" => "Alice" }).unwrap();
let bob   = w.add_node(&["Person"], props! { "name" => "Bob"   }).unwrap();
w.add_edge(alice, bob, "KNOWS", props! {}).unwrap();

// Compact WAL into snapshot periodically:
w.checkpoint().unwrap();
```

| Method | Description |
|--------|-------------|
| `WalWriter::create(snap, wal)` | New empty graph, WAL-backed |
| `WalWriter::open(snap, wal)` | Load snapshot + replay WAL |
| `w.add_node(labels, props)` | Write-before-apply |
| `w.add_edge(src, dst, label, props)` | Write-before-apply |
| `w.remove_node(id)` | Write-before-apply |
| `w.remove_edge(id)` | Write-before-apply |
| `w.set_node_property(id, key, val)` | Write-before-apply |
| `w.set_edge_property(id, key, val)` | Write-before-apply |
| `w.checkpoint()` | Save snapshot, truncate WAL |
| `w.graph()` | Read-only access to inner `Graph` |

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | In-memory directed property graph | ✅ done |
| 2 | Algorithms + snapshot persistence (bincode + JSON) | ✅ done |
| 3 | Write-ahead log for crash recovery | ✅ done |
| 4 | Page-backed on-disk storage | planned |
| 5 | Query language (Cypher subset) | planned |

## License

MIT
