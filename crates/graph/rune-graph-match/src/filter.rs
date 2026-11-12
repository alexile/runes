use rune_graph::{NodeId, Value};

/// Filter applied to nodes (source or target) in a [`Pattern`](crate::Pattern).
#[derive(Debug, Clone, PartialEq)]
pub enum NodeFilter {
    /// Match any node.
    Any,
    /// Match one specific node by its [`NodeId`].
    Id(NodeId),
    /// Match nodes that carry `label` in their label set.
    HasLabel(String),
    /// Match nodes where property `key` equals `value`.
    Property {
        /// Property name.
        key: String,
        /// Required property value.
        value: Value,
    },
}

/// Filter applied to edges in a [`Pattern`](crate::Pattern).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelFilter {
    /// Match any edge.
    Any,
    /// Match edges whose relationship type equals `label`.
    Label(String),
}
