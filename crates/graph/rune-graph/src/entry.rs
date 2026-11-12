use std::collections::HashMap;

use crate::id::NodeId;
use crate::value::Value;

/// A node stored in the graph: a set of labels and a property map.
///
/// Mutable access is only available through
/// [`Graph::update_node`](crate::Graph::update_node), which keeps the label
/// and property indexes in sync with your changes.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, props};
///
/// let mut g = Graph::new();
/// let id = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
/// let node = g.node(id).unwrap();
/// assert!(node.has_label("Person"));
/// assert_eq!(node.get("name"), Some(&rune_graph::Value::Str("Alice".into())));
/// ```
#[cfg_attr(feature = "persist", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub(crate) labels: Vec<String>,
    pub(crate) properties: HashMap<String, Value>,
}

impl NodeEntry {
    pub(crate) fn new(labels: &[&str], properties: HashMap<String, Value>) -> Self {
        let mut entry = Self {
            labels: labels
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            properties,
        };
        entry.dedup_labels();
        entry
    }

    #[cfg(feature = "persist")]
    pub(crate) fn from_parts(labels: Vec<String>, properties: HashMap<String, Value>) -> Self {
        let mut entry = Self { labels, properties };
        entry.dedup_labels();
        entry
    }

    /// Drop repeated labels, keeping the first occurrence.
    pub(crate) fn dedup_labels(&mut self) {
        let mut seen = std::collections::HashSet::new();
        self.labels.retain(|l| seen.insert(l.clone()));
    }

    /// The labels attached to this node.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// Return `true` if this node carries `label`.
    #[must_use]
    pub fn has_label(&self, label: &str) -> bool {
        self.labels.iter().any(|l| l == label)
    }

    /// Look up a property by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.properties.get(key)
    }

    /// The full property map.
    #[must_use]
    pub const fn properties(&self) -> &HashMap<String, Value> {
        &self.properties
    }

    /// Insert or overwrite a property.
    pub fn set(&mut self, key: impl Into<String>, value: Value) {
        self.properties.insert(key.into(), value);
    }

    /// Remove a property, returning its old value.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        self.properties.remove(key)
    }

    /// Add a label if not already present.
    pub fn add_label(&mut self, label: impl Into<String>) {
        let label = label.into();
        if !self.labels.contains(&label) {
            self.labels.push(label);
        }
    }

    /// Remove a label. Returns `true` if it was present.
    pub fn remove_label(&mut self, label: &str) -> bool {
        let before = self.labels.len();
        self.labels.retain(|l| l != label);
        self.labels.len() != before
    }
}

/// An edge stored in the graph: source, target, a relationship label, and a
/// property map.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let eid = g.add_edge(a, b, "KNOWS", props! { "since" => 2020_i64 }).unwrap();
/// let edge = g.edge(eid).unwrap();
/// assert_eq!(edge.label(), "KNOWS");
/// assert_eq!(edge.source(), a);
/// assert_eq!(edge.target(), b);
/// ```
#[cfg_attr(feature = "persist", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct EdgeEntry {
    pub(crate) source: NodeId,
    pub(crate) target: NodeId,
    pub(crate) label: String,
    pub(crate) properties: HashMap<String, Value>,
}

impl EdgeEntry {
    pub(crate) fn new(
        source: NodeId,
        target: NodeId,
        label: &str,
        properties: HashMap<String, Value>,
    ) -> Self {
        Self {
            source,
            target,
            label: label.to_string(),
            properties,
        }
    }

    /// The source (tail) node of this edge.
    #[must_use]
    pub const fn source(&self) -> NodeId {
        self.source
    }

    /// The target (head) node of this edge.
    #[must_use]
    pub const fn target(&self) -> NodeId {
        self.target
    }

    /// The relationship type label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Look up a property by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.properties.get(key)
    }

    /// The full property map.
    #[must_use]
    pub const fn properties(&self) -> &HashMap<String, Value> {
        &self.properties
    }

    /// Insert or overwrite a property.
    pub fn set(&mut self, key: impl Into<String>, value: Value) {
        self.properties.insert(key.into(), value);
    }

    /// Remove a property, returning its old value.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        self.properties.remove(key)
    }
}
