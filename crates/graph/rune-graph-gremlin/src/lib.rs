//! Gremlin-inspired graph traversal engine for [`rune-graph`](rune_graph).
//!
//! Provides a fluent, type-safe traversal DSL modelled on
//! [Apache TinkerPop's Gremlin](https://tinkerpop.apache.org/gremlin.html) — a
//! native Rust pipeline API, not a string query language.  Steps are chained on
//! typed traversal values (`VertexTraversal`, `EdgeTraversal`, `ValueTraversal`);
//! nothing executes until you call a terminal step.
//!
//! # Features
//!
//! - **Typed pipeline**: `VertexTraversal` → `EdgeTraversal` → `VertexTraversal`
//!   or `ValueTraversal`. The Rust type system enforces which steps are valid at
//!   each stage.
//! - **Vertex steps**: `out`, `in_`, `both`, `out_e`, `in_e`, `has`, `has_p`,
//!   `has_label`, `filter`, `dedup`, `values`, `properties`, `limit`
//! - **Repeat steps**: `repeat_times` (fixed-depth BFS), `repeat_until` (BFS
//!   until condition)
//! - **Path tracking**: `paths` — collect every reachable path as `Vec<NodeId>`
//! - **Edge steps**: `in_v`, `out_v`, `has_label`, `has`, `has_p`, `values`,
//!   `label`, `limit`
//! - **Predicates** (`P`): `eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `within`,
//!   `without` — composable value comparisons used in `has_p`
//! - **Terminal steps**: `collect`, `next`, `count`, `any`
//! - Lazy — all intermediate steps return new traversal values without touching
//!   the graph; only terminals drain the pipeline.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_graph::{Graph, Value, props};
//! use rune_graph_gremlin::{GraphTraversalSource, P};
//!
//! let mut g = Graph::new();
//! let alice = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
//! let bob   = g.add_node(&["Person"], props! { "name" => "Bob",   "age" => 22_i64 });
//! let acme  = g.add_node(&["Company"], props! { "name" => "Acme" });
//! g.add_edge(alice, bob,  "knows",    props! {}).unwrap();
//! g.add_edge(bob,   acme, "works_at", props! {}).unwrap();
//!
//! let src = GraphTraversalSource::new(&g);
//!
//! // Who does Alice know?
//! let knows: Vec<_> = src.v_id(alice).out("knows").values("name").collect();
//! assert_eq!(knows, vec![Value::Str("Bob".into())]);
//!
//! // Adults (age ≥ 25)
//! let adults = src.v().has_label("Person").has_p("age", P::gte(25_i64)).count();
//! assert_eq!(adults, 1);
//!
//! // Two-hop traversal: Alice → ??? → ???
//! let two_hop = src.v_id(alice).repeat_times(2, |t| t.out_any()).collect();
//! assert_eq!(two_hop, vec![acme]);
//! ```

/// Value predicates for `has`-style filters.
pub mod predicate;
/// Traversal entry point.
pub mod source;
#[cfg(test)]
mod tests;
/// Traversal steps.
pub mod traversal;

pub use predicate::P;
pub use source::GraphTraversalSource;
pub use traversal::{EdgeTraversal, ValueTraversal, VertexTraversal};
