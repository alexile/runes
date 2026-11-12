//! Pattern matching engine for [`rune_graph`].
//!
//! `rune-graph-match` lets you query a property graph by expressing what you're
//! looking for — not how to find it. Describe a triple pattern:
//! `(source filter) -[edge filter]-> (target filter)` and the engine returns
//! every matching `(NodeId, EdgeId, NodeId)` triple.
//!
//! # Filters
//!
//! | Filter | Matches |
//! |--------|---------|
//! | [`NodeFilter::Any`] | every node |
//! | [`NodeFilter::Id`] | one specific node |
//! | [`NodeFilter::HasLabel`] | nodes carrying that label |
//! | [`NodeFilter::Property`] | nodes where `props[key] == value` |
//! | [`RelFilter::Any`] | every edge |
//! | [`RelFilter::Label`] | edges with that relationship type |
//!
//! # Quick Start
//!
//! ```rust
//! use rune_graph::{Graph, Value, props};
//! use rune_graph_match::{NodeFilter, RelFilter, Pattern, match_pattern};
//!
//! let mut g = Graph::new();
//! let alice = g.add_node(&["Person"], props! { "name" => "Alice" });
//! let bob   = g.add_node(&["Person"], props! { "name" => "Bob"   });
//! let acme  = g.add_node(&["Org"],    props! { "name" => "Acme"  });
//! g.add_edge(alice, bob,  "KNOWS",    props! {}).unwrap();
//! g.add_edge(bob,   acme, "WORKS_AT", props! {}).unwrap();
//! g.add_edge(alice, acme, "WORKS_AT", props! {}).unwrap();
//!
//! // Who works at Acme?
//! let pat = Pattern {
//!     from: NodeFilter::Any,
//!     rel:  RelFilter::Label("WORKS_AT".into()),
//!     to:   NodeFilter::Id(acme),
//! };
//! let hits = match_pattern(&g, &pat);
//! assert_eq!(hits.len(), 2);
//!
//! // All Person nodes that know someone
//! let pat = Pattern {
//!     from: NodeFilter::HasLabel("Person".into()),
//!     rel:  RelFilter::Label("KNOWS".into()),
//!     to:   NodeFilter::Any,
//! };
//! let hits = match_pattern(&g, &pat);
//! assert_eq!(hits.len(), 1);
//! assert_eq!(hits[0].source, alice);
//!
//! // Find by property value
//! let pat = Pattern {
//!     from: NodeFilter::Property { key: "name".into(), value: rune_graph::Value::Str("Alice".into()) },
//!     rel:  RelFilter::Any,
//!     to:   NodeFilter::Any,
//! };
//! let hits = match_pattern(&g, &pat);
//! assert_eq!(hits.len(), 2); // Alice → Bob, Alice → Acme
//! ```
//!
//! # Multi-pattern Chains
//!
//! String patterns together with [`chain`] to find paths through the graph:
//!
//! ```rust
//! use rune_graph::{Graph, props};
//! use rune_graph_match::{NodeFilter, RelFilter, Pattern, chain};
//!
//! let mut g = Graph::new();
//! let a = g.add_node(&[], props! { "name" => "A" });
//! let b = g.add_node(&[], props! { "name" => "B" });
//! let c = g.add_node(&[], props! { "name" => "C" });
//! g.add_edge(a, b, "step", props! {}).unwrap();
//! g.add_edge(b, c, "step", props! {}).unwrap();
//!
//! // Find all (X)-[:step]->(Y)-[:step]->(Z) chains
//! let p1 = Pattern { from: NodeFilter::Any, rel: RelFilter::Label("step".into()), to: NodeFilter::Any };
//! let p2 = Pattern { from: NodeFilter::Any, rel: RelFilter::Label("step".into()), to: NodeFilter::Any };
//! let chains = chain(&g, &[p1, p2]);
//! assert_eq!(chains.len(), 1);
//! assert_eq!(chains[0], vec![a, b, c]);
//! ```

mod filter;
mod matcher;
#[cfg(test)]
mod tests;

pub use filter::{NodeFilter, RelFilter};
pub use matcher::{Match, Pattern, chain, match_pattern};
