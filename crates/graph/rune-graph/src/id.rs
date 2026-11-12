use std::fmt;

/// Stable identifier for a node in the graph.
///
/// `NodeId`s are assigned by [`Graph::add_node`](crate::Graph::add_node) and remain valid for the
/// lifetime of the graph. Removing a node invalidates its `NodeId`; the slot
/// is never reused.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, props};
///
/// let mut g = Graph::new();
/// let id = g.add_node(&["Person"], props! { "name" => "Alice" });
/// assert!(g.contains_node(id));
/// ```
#[cfg_attr(feature = "persist", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub(crate) u64);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "N{}", self.0)
    }
}

/// Stable identifier for an edge in the graph.
///
/// `EdgeId`s are assigned by [`Graph::add_edge`](crate::Graph::add_edge) and remain valid until the
/// edge (or either of its endpoint nodes) is removed.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let eid = g.add_edge(a, b, "LINKS", props! {}).unwrap();
/// assert!(g.contains_edge(eid));
/// ```
#[cfg_attr(feature = "persist", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EdgeId(pub(crate) u64);

impl fmt::Display for EdgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "E{}", self.0)
    }
}
