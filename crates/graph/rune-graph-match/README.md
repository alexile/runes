# rune-graph-match

> Declarative pattern matching for `rune-graph` — describe what you want, not how to find it.

[![crates.io](https://img.shields.io/crates/v/rune-graph-match)](https://crates.io/crates/rune-graph-match)
[![docs.rs](https://img.shields.io/docsrs/rune-graph-match)](https://docs.rs/rune-graph-match)
[![license](https://img.shields.io/crates/l/rune-graph-match)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-graph-match` adds a declarative query layer on top of [`rune-graph`](https://crates.io/crates/rune-graph).
You describe a triple pattern — `(source filter) -[edge filter]-> (target filter)` — and the engine
returns every matching `(NodeId, EdgeId, NodeId)` triple from the graph.
Chain multiple patterns together with [`chain`] to find multi-hop paths without writing traversal loops.

## Installation

```toml
[dependencies]
rune-graph-match = "0.3"
rune-graph       = "0.4"
```

## Usage

```rust
use rune_graph::{Graph, props};
use rune_graph_match::{NodeFilter, RelFilter, Pattern, match_pattern};

let mut g = Graph::new();
let alice = g.add_node(&["Person"], props! { "name" => "Alice" });
let bob   = g.add_node(&["Person"], props! { "name" => "Bob"   });
let acme  = g.add_node(&["Org"],    props! { "name" => "Acme"  });
g.add_edge(alice, bob,  "KNOWS",    props! {}).unwrap();
g.add_edge(bob,   acme, "WORKS_AT", props! {}).unwrap();
g.add_edge(alice, acme, "WORKS_AT", props! {}).unwrap();

// Who works at Acme?
let pat = Pattern {
    from: NodeFilter::Any,
    rel:  RelFilter::Label("WORKS_AT".into()),
    to:   NodeFilter::Id(acme),
};
let hits = match_pattern(&g, &pat);
assert_eq!(hits.len(), 2);
println!("source={:?} edge={:?} target={:?}", hits[0].source, hits[0].edge, hits[0].target);

// Filter by property value
let pat = Pattern {
    from: NodeFilter::Property { key: "name".into(), value: "Alice".into() },
    rel:  RelFilter::Any,
    to:   NodeFilter::Any,
};
let hits = match_pattern(&g, &pat);
assert_eq!(hits.len(), 2); // Alice → Bob and Alice → Acme
```

## Filters

| Filter | Matches |
|--------|---------|
| `NodeFilter::Any` | every node |
| `NodeFilter::Id(id)` | one specific node |
| `NodeFilter::HasLabel(l)` | nodes carrying that label |
| `NodeFilter::Property { key, value }` | nodes where `props[key] == value` |
| `RelFilter::Any` | every edge |
| `RelFilter::Label(l)` | edges with that relationship type |

## Multi-pattern chains

String patterns together to find multi-hop paths:

```rust
use rune_graph::{Graph, props};
use rune_graph_match::{NodeFilter, RelFilter, Pattern, chain};

let mut g = Graph::new();
let a = g.add_node(&[], props! { "name" => "A" });
let b = g.add_node(&[], props! { "name" => "B" });
let c = g.add_node(&[], props! { "name" => "C" });
g.add_edge(a, b, "step", props! {}).unwrap();
g.add_edge(b, c, "step", props! {}).unwrap();

// All (X)-[:step]->(Y)-[:step]->(Z) chains
let p1 = Pattern { from: NodeFilter::Any, rel: RelFilter::Label("step".into()), to: NodeFilter::Any };
let p2 = Pattern { from: NodeFilter::Any, rel: RelFilter::Label("step".into()), to: NodeFilter::Any };
let chains = chain(&g, &[p1, p2]);
assert_eq!(chains[0], vec![a, b, c]);
```

## Migrating from 0.2

- Built on `rune-graph` 0.4, which is a breaking release; upgrade both together. The
  traversal API of this crate is unchanged. See the
  [rune-graph migration notes](https://crates.io/crates/rune-graph).

## License

MIT
