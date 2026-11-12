# rune-graph-gremlin

> Gremlin-inspired graph traversal DSL for `rune-graph` — fluent, typed, lazy step pipelines.

[![crates.io](https://img.shields.io/crates/v/rune-graph-gremlin)](https://crates.io/crates/rune-graph-gremlin)
[![docs.rs](https://img.shields.io/docsrs/rune-graph-gremlin)](https://docs.rs/rune-graph-gremlin)
[![license](https://img.shields.io/crates/l/rune-graph-gremlin)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-graph-gremlin` is a native Rust traversal engine for [`rune-graph`](https://crates.io/crates/rune-graph),
modelled on [Apache TinkerPop's Gremlin](https://tinkerpop.apache.org/gremlin.html).
Steps are chained on typed values (`VertexTraversal`, `EdgeTraversal`, `ValueTraversal`); the
Rust type system enforces which steps are valid at each stage. Nothing executes until you call
a terminal step — the pipeline is fully lazy.

## Installation

```toml
[dependencies]
rune-graph-gremlin = "0.1"
rune-graph         = "0.2"
```

## Usage

```rust
use rune_graph::{Graph, Value, props};
use rune_graph_gremlin::{GraphTraversalSource, P};

let mut g = Graph::new();
let alice = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
let bob   = g.add_node(&["Person"], props! { "name" => "Bob",   "age" => 22_i64 });
let acme  = g.add_node(&["Company"], props! { "name" => "Acme" });
g.add_edge(alice, bob,  "knows",    props! {}).unwrap();
g.add_edge(bob,   acme, "works_at", props! {}).unwrap();

let src = GraphTraversalSource::new(&g);

// Who does Alice know?
let knows: Vec<_> = src.v_id(alice).out("knows").values("name").collect();
assert_eq!(knows, vec![Value::Str("Bob".into())]);

// Adults only (age ≥ 25)
let count = src.v().has_label("Person").has_p("age", P::gte(25_i64)).count();
assert_eq!(count, 1);

// Two-hop traversal: Alice → knows → Bob → works_at → Acme
let two_hop = src.v_id(alice).repeat_times(2, |t| t.out_any()).collect();
assert_eq!(two_hop, vec![acme]);
```

## Step reference

### Vertex steps

| Step | Description |
|------|-------------|
| `out(label)` | follow outgoing edges with the given label |
| `out_any()` | follow all outgoing edges |
| `in_(label)` | follow incoming edges with the given label |
| `in_any()` | follow all incoming edges |
| `both(label)` | follow edges in either direction |
| `out_e(label)` | move to outgoing edges (produces `EdgeTraversal`) |
| `in_e(label)` | move to incoming edges (produces `EdgeTraversal`) |
| `has(key, val)` | keep nodes where `props[key] == val` |
| `has_p(key, pred)` | keep nodes where `props[key]` satisfies predicate `P` |
| `has_label(l)` | keep nodes with the given label |
| `filter(fn)` | keep nodes where `fn(NodeId, &NodeEntry) == true` |
| `dedup()` | remove duplicate node ids |
| `values(key)` | extract property values (produces `ValueTraversal`) |
| `limit(n)` | keep at most `n` nodes |
| `repeat_times(n, step)` | apply `step` n times (fixed-depth BFS) |
| `repeat_until(cond, step)` | apply `step` until `cond` returns true |
| `paths()` | collect every reachable path as `Vec<NodeId>` |

### Edge steps

| Step | Description |
|------|-------------|
| `in_v()` | move to the target vertex |
| `out_v()` | move to the source vertex |
| `has_label(l)` | keep edges with the given label |
| `has(key, val)` | keep edges where `props[key] == val` |
| `has_p(key, pred)` | keep edges where `props[key]` satisfies predicate `P` |
| `values(key)` | extract edge property values |
| `label()` | extract edge labels as strings |
| `limit(n)` | keep at most `n` edges |

### Terminal steps

| Step | Returns |
|------|---------|
| `collect()` | `Vec<T>` |
| `next()` | `Option<T>` |
| `count()` | `usize` |
| `any()` | `bool` |

### Predicates (`P`)

```rust
P::eq(v)      // == v
P::neq(v)     // != v
P::lt(v)      // < v
P::lte(v)     // <= v
P::gt(v)      // > v
P::gte(v)     // >= v
P::within(vs) // in set vs
P::without(vs)// not in set vs
```

## License

MIT
