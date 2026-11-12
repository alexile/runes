use rune_graph::{EdgeId, Graph, NodeId};

use crate::traversal::{EdgeTraversal, Traversal, VertexTraversal};

/// Entry point for all Gremlin-inspired traversals.
///
/// Mirrors `g` in Apache `TinkerPop` — create one from a [`Graph`] reference and
/// use `.v()` or `.e()` to start a traversal pipeline.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, props};
/// use rune_graph_gremlin::GraphTraversalSource;
///
/// let mut g = Graph::new();
/// g.add_node(&["Person"], props! { "name" => "Alice" });
/// g.add_node(&["Person"], props! { "name" => "Bob" });
///
/// let src = GraphTraversalSource::new(&g);
/// let count = src.v().count();
/// assert_eq!(count, 2);
/// ```
pub struct GraphTraversalSource<'g> {
    graph: &'g Graph,
}

impl<'g> GraphTraversalSource<'g> {
    /// Create a traversal source bound to `graph`.
    #[must_use]
    pub const fn new(graph: &'g Graph) -> Self {
        Self { graph }
    }

    /// Start a traversal over **all** vertices in the graph.
    #[must_use]
    pub fn v(&self) -> VertexTraversal<'g> {
        VertexTraversal(Traversal {
            graph: self.graph,
            inner: Box::new(self.graph.nodes().map(|(id, _)| id)),
        })
    }

    /// Start a traversal seeded with a **single** vertex by id.
    ///
    /// If `id` does not exist in the graph the traversal is immediately empty.
    #[must_use]
    pub fn v_id(&self, id: NodeId) -> VertexTraversal<'g> {
        let ids: Vec<NodeId> = if self.graph.node(id).is_some() {
            vec![id]
        } else {
            vec![]
        };
        VertexTraversal(Traversal {
            graph: self.graph,
            inner: Box::new(ids.into_iter()),
        })
    }

    /// Start a traversal seeded with **multiple** vertices by id.
    pub fn v_ids(&self, ids: impl IntoIterator<Item = NodeId>) -> VertexTraversal<'g> {
        let graph = self.graph;
        // Collected eagerly: the caller's iterator is not bound by `'g`.
        #[allow(
            clippy::needless_collect,
            reason = "the caller's iterator is not bound by 'g"
        )]
        let ids: Vec<NodeId> = ids
            .into_iter()
            .filter(|&id| graph.node(id).is_some())
            .collect();
        VertexTraversal(Traversal {
            graph: self.graph,
            inner: Box::new(ids.into_iter()),
        })
    }

    /// Start a traversal over **all** edges in the graph.
    #[must_use]
    pub fn e(&self) -> EdgeTraversal<'g> {
        EdgeTraversal(Traversal {
            graph: self.graph,
            inner: Box::new(self.graph.edges().map(|(id, _)| id)),
        })
    }

    /// Start a traversal seeded with a **single** edge by id.
    #[must_use]
    pub fn e_id(&self, id: EdgeId) -> EdgeTraversal<'g> {
        let ids: Vec<EdgeId> = if self.graph.edge(id).is_some() {
            vec![id]
        } else {
            vec![]
        };
        EdgeTraversal(Traversal {
            graph: self.graph,
            inner: Box::new(ids.into_iter()),
        })
    }
}
