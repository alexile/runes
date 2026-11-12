use crate::id::{EdgeId, NodeId};

/// Errors produced by graph mutation operations.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, GraphError, props};
///
/// let mut g = Graph::new();
/// let missing = rune_graph::NodeId::from(999);
/// let err = g.remove_node(missing).unwrap_err();
/// assert!(matches!(err, GraphError::NodeNotFound(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    /// The referenced node does not exist in the graph.
    NodeNotFound(NodeId),
    /// The referenced edge does not exist in the graph.
    EdgeNotFound(EdgeId),
    /// Attempted to add a self-loop where one is not permitted.
    SelfLoop(NodeId),
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NodeNotFound(id) => write!(f, "node {id} not found"),
            Self::EdgeNotFound(id) => write!(f, "edge {id} not found"),
            Self::SelfLoop(id) => write!(f, "self-loop on node {id} is not allowed"),
        }
    }
}

impl std::error::Error for GraphError {}
