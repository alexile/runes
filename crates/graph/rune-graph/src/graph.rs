use std::collections::{HashMap, HashSet, VecDeque};

use crate::entry::{EdgeEntry, NodeEntry};
use crate::error::GraphError;
use crate::id::{EdgeId, NodeId};
use crate::index::{MatchesInner, PropertyIndexes, PropertyMatches};
use crate::traverse::{Bfs, Dfs, Direction};
use crate::value::Value;

/// An in-memory directed property graph.
///
/// Nodes and edges carry arbitrary key-value properties ([`Value`]) and string
/// labels / relationship types. The graph is built for fast traversal: forward
/// and reverse adjacency lists are maintained so that both outgoing and
/// incoming edge queries are O(degree).
///
/// Node labels and edge labels are always indexed, so
/// [`nodes_with_label`](Self::nodes_with_label) and
/// [`edges_with_label`](Self::edges_with_label) cost O(matches). Property
/// indexes on `(label, key)` pairs are opt-in via
/// [`create_index`](Self::create_index) and are kept up to date by every
/// mutation method.
///
/// `Graph` owns all of its data and is `Send + Sync`: share `&Graph` across
/// threads freely, and wrap it in `std::sync::RwLock` (or an async lock) when
/// threads also need to write.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, props};
///
/// let mut g = Graph::new();
/// let alice = g.add_node(&["Person"], props! { "name" => "Alice" });
/// let bob   = g.add_node(&["Person"], props! { "name" => "Bob" });
/// g.add_edge(alice, bob, "KNOWS", props! { "since" => 2020_i64 }).unwrap();
///
/// assert_eq!(g.node_count(), 2);
/// assert_eq!(g.edge_count(), 1);
///
/// let names: Vec<_> = g.neighbors(alice).collect();
/// assert_eq!(names, vec![bob]);
/// ```
#[derive(Debug, Clone)]
pub struct Graph {
    nodes: HashMap<NodeId, NodeEntry>,
    edges: HashMap<EdgeId, EdgeEntry>,
    out_edges: HashMap<NodeId, Vec<EdgeId>>,
    in_edges: HashMap<NodeId, Vec<EdgeId>>,
    node_labels: HashMap<String, HashSet<NodeId>>,
    edge_labels: HashMap<String, HashSet<EdgeId>>,
    indexes: PropertyIndexes,
    pub(crate) next_node: u64,
    pub(crate) next_edge: u64,
}

/// Largest id accepted from snapshots, JSON Lines or WAL replay. Keeping
/// restored ids below 2^63 leaves the id counters 2^63 allocations of
/// headroom.
#[cfg(feature = "persist")]
pub const MAX_RESTORED_ID: u64 = 1 << 63;

fn index_labels(map: &mut HashMap<String, HashSet<NodeId>>, id: NodeId, entry: &NodeEntry) {
    for label in entry.labels() {
        map.entry(label.clone()).or_default().insert(id);
    }
}

struct Reindex<'a> {
    labels: &'a mut HashMap<String, HashSet<NodeId>>,
    indexes: &'a mut PropertyIndexes,
    id: NodeId,
    entry: &'a mut NodeEntry,
}

impl Drop for Reindex<'_> {
    fn drop(&mut self) {
        index_labels(self.labels, self.id, self.entry);
        self.indexes.insert_node(self.id, self.entry);
    }
}

fn unindex_labels(map: &mut HashMap<String, HashSet<NodeId>>, id: NodeId, entry: &NodeEntry) {
    for label in entry.labels() {
        if let Some(set) = map.get_mut(label) {
            set.remove(&id);
            if set.is_empty() {
                map.remove(label);
            }
        }
    }
}

impl Default for Graph {
    fn default() -> Self {
        Self::new()
    }
}

impl Graph {
    /// Create an empty graph.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::Graph;
    ///
    /// let g = Graph::new();
    /// assert_eq!(g.node_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            out_edges: HashMap::new(),
            in_edges: HashMap::new(),
            node_labels: HashMap::new(),
            edge_labels: HashMap::new(),
            indexes: PropertyIndexes::default(),
            next_node: 0,
            next_edge: 0,
        }
    }

    // ── Node operations ──────────────────────────────────────────────────────

    /// Add a node with the given labels and properties. Returns its stable [`NodeId`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let id = g.add_node(&["User"], props! { "email" => "a@b.com" });
    /// assert_eq!(g.node(id).unwrap().get("email").unwrap().to_string(), "a@b.com");
    /// ```
    pub fn add_node(&mut self, labels: &[&str], properties: HashMap<String, Value>) -> NodeId {
        let id = NodeId(self.next_node);
        // Ids handed out here start below 2^63 (loaders reject anything
        // larger), so this cannot saturate in practice.
        self.next_node = self.next_node.saturating_add(1);
        self.attach_node(id, NodeEntry::new(labels, properties));
        id
    }

    #[cfg(feature = "persist")]
    /// Insert a node under a caller-chosen id (snapshot load, WAL replay).
    pub(crate) fn insert_node_with_id(
        &mut self,
        id: NodeId,
        mut entry: NodeEntry,
    ) -> Result<(), GraphError> {
        if self.nodes.contains_key(&id) {
            return Err(GraphError::DuplicateNode(id));
        }
        if id.0 > MAX_RESTORED_ID {
            return Err(GraphError::IdSpaceExhausted);
        }
        entry.dedup_labels();
        self.attach_node(id, entry);
        self.next_node = self.next_node.max(id.0 + 1);
        Ok(())
    }

    fn attach_node(&mut self, id: NodeId, entry: NodeEntry) {
        index_labels(&mut self.node_labels, id, &entry);
        self.indexes.insert_node(id, &entry);
        self.nodes.insert(id, entry);
        self.out_edges.insert(id, Vec::new());
        self.in_edges.insert(id, Vec::new());
    }

    /// Remove a node and all edges incident to it.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::NodeNotFound`] if `id` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let id = g.add_node(&[], props! {});
    /// g.remove_node(id).unwrap();
    /// assert!(!g.contains_node(id));
    /// ```
    pub fn remove_node(&mut self, id: NodeId) -> Result<(), GraphError> {
        if !self.nodes.contains_key(&id) {
            return Err(GraphError::NodeNotFound(id));
        }
        // Collect all incident edges before mutating adjacency.
        let incident: Vec<EdgeId> = self
            .out_edges
            .get(&id)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .chain(self.in_edges.get(&id).map_or(&[][..], Vec::as_slice))
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        for eid in incident {
            self.remove_edge_internal(eid);
        }
        if let Some(entry) = self.nodes.remove(&id) {
            unindex_labels(&mut self.node_labels, id, &entry);
            self.indexes.remove_node(id, &entry);
        }
        self.out_edges.remove(&id);
        self.in_edges.remove(&id);
        Ok(())
    }

    /// Return `true` if the graph contains a node with this `id`.
    #[must_use]
    pub fn contains_node(&self, id: NodeId) -> bool {
        self.nodes.contains_key(&id)
    }

    /// Borrow a node entry by id.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&NodeEntry> {
        self.nodes.get(&id)
    }

    /// Modify a node in place through a closure, keeping label and property
    /// indexes in sync with whatever the closure changes.
    ///
    /// This replaces direct mutable access to the [`NodeEntry`], which could
    /// not keep indexes consistent.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::NodeNotFound`] if `id` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, Value, props};
    ///
    /// let mut g = Graph::new();
    /// let id = g.add_node(&["Draft"], props! { "title" => "Hi" });
    /// g.update_node(id, |n| {
    ///     n.remove_label("Draft");
    ///     n.add_label("Post");
    ///     n.set("views", Value::Int(0));
    /// }).unwrap();
    /// assert_eq!(g.nodes_with_label("Post").count(), 1);
    /// assert_eq!(g.nodes_with_label("Draft").count(), 0);
    /// ```
    pub fn update_node<R>(
        &mut self,
        id: NodeId,
        f: impl FnOnce(&mut NodeEntry) -> R,
    ) -> Result<R, GraphError> {
        let entry = self
            .nodes
            .get_mut(&id)
            .ok_or(GraphError::NodeNotFound(id))?;
        unindex_labels(&mut self.node_labels, id, entry);
        self.indexes.remove_node(id, entry);
        // Reindex from a drop guard so a panicking closure, caught further
        // up, still leaves the indexes matching the node.
        let guard = Reindex {
            labels: &mut self.node_labels,
            indexes: &mut self.indexes,
            id,
            entry,
        };
        Ok(f(guard.entry))
    }

    /// Add `label` to a node. Returns `true` if the label was not already present.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::NodeNotFound`] if `id` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let id = g.add_node(&["A"], props! {});
    /// assert!(g.add_node_label(id, "B").unwrap());
    /// assert!(!g.add_node_label(id, "B").unwrap());
    /// assert!(g.node(id).unwrap().has_label("B"));
    /// ```
    pub fn add_node_label(&mut self, id: NodeId, label: &str) -> Result<bool, GraphError> {
        if self
            .node(id)
            .ok_or(GraphError::NodeNotFound(id))?
            .has_label(label)
        {
            return Ok(false);
        }
        self.update_node(id, |n| n.add_label(label)).map(|()| true)
    }

    /// Remove `label` from a node. Returns `true` if the label was present.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::NodeNotFound`] if `id` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let id = g.add_node(&["A", "B"], props! {});
    /// assert!(g.remove_node_label(id, "A").unwrap());
    /// assert_eq!(g.nodes_with_label("A").count(), 0);
    /// ```
    pub fn remove_node_label(&mut self, id: NodeId, label: &str) -> Result<bool, GraphError> {
        if !self
            .node(id)
            .ok_or(GraphError::NodeNotFound(id))?
            .has_label(label)
        {
            return Ok(false);
        }
        self.update_node(id, |n| n.remove_label(label))
    }

    /// Remove a property from a node, returning its old value.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::NodeNotFound`] if `id` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, Value, props};
    ///
    /// let mut g = Graph::new();
    /// let id = g.add_node(&[], props! { "tmp" => 1_i64 });
    /// assert_eq!(g.remove_node_property(id, "tmp").unwrap(), Some(Value::Int(1)));
    /// assert_eq!(g.node(id).unwrap().get("tmp"), None);
    /// ```
    pub fn remove_node_property(
        &mut self,
        id: NodeId,
        key: &str,
    ) -> Result<Option<Value>, GraphError> {
        if self
            .node(id)
            .ok_or(GraphError::NodeNotFound(id))?
            .get(key)
            .is_none()
        {
            return Ok(None);
        }
        self.update_node(id, |n| n.remove(key))
    }

    /// The total number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Iterate over all `(NodeId, &NodeEntry)` pairs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// g.add_node(&["A"], props! {});
    /// g.add_node(&["B"], props! {});
    /// assert_eq!(g.nodes().count(), 2);
    /// ```
    pub fn nodes(&self) -> impl Iterator<Item = (NodeId, &NodeEntry)> {
        self.nodes.iter().map(|(&id, entry)| (id, entry))
    }

    /// Iterate over all nodes that carry `label`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// g.add_node(&["Person"], props! { "name" => "Alice" });
    /// g.add_node(&["Robot"],  props! { "name" => "R2D2"  });
    /// let people: Vec<_> = g.nodes_with_label("Person").collect();
    /// assert_eq!(people.len(), 1);
    /// ```
    pub fn nodes_with_label<'a>(&'a self, label: &'a str) -> impl Iterator<Item = NodeId> + 'a {
        self.node_labels
            .get(label)
            .into_iter()
            .flat_map(|set| set.iter().copied())
    }

    /// Iterate over all distinct node labels currently in use.
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// g.add_node(&["A", "B"], props! {});
    /// g.add_node(&["A"], props! {});
    /// let mut labels: Vec<_> = g.node_labels().collect();
    /// labels.sort_unstable();
    /// assert_eq!(labels, vec!["A", "B"]);
    /// ```
    pub fn node_labels(&self) -> impl Iterator<Item = &str> {
        self.node_labels.keys().map(String::as_str)
    }

    // ── Property indexes ─────────────────────────────────────────────────────

    /// Index the property `key` on nodes labelled `label`, so that
    /// [`nodes_by_property`](Self::nodes_by_property) with that pair is a hash
    /// lookup instead of a scan. Returns `false` if the index already existed.
    ///
    /// Indexes are maintained automatically by every mutation method
    /// ([`add_node`](Self::add_node), [`remove_node`](Self::remove_node),
    /// [`set_node_property`](Self::set_node_property),
    /// [`update_node`](Self::update_node), ...) and are saved in snapshots.
    ///
    /// Values compare the same way [`Value`] does: `Int(1)` does not match
    /// `Float(1.0)`, and `NaN` never matches anything.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, Value, props};
    ///
    /// let mut g = Graph::new();
    /// g.create_index("User", "email");
    /// let id = g.add_node(&["User"], props! { "email" => "a@x.io" });
    ///
    /// let hits: Vec<_> = g.nodes_by_property("User", "email", &Value::from("a@x.io")).collect();
    /// assert_eq!(hits, vec![id]);
    /// ```
    pub fn create_index(&mut self, label: &str, key: &str) -> bool {
        let candidates = self
            .node_labels
            .get(label)
            .into_iter()
            .flat_map(|set| set.iter())
            .filter_map(|id| self.nodes.get(id).map(|e| (*id, e)));
        self.indexes.create(label, key, candidates)
    }

    /// Drop a property index. Returns `false` if it did not exist.
    ///
    /// ```rust
    /// use rune_graph::Graph;
    ///
    /// let mut g = Graph::new();
    /// g.create_index("User", "email");
    /// assert!(g.drop_index("User", "email"));
    /// assert!(!g.has_index("User", "email"));
    /// ```
    pub fn drop_index(&mut self, label: &str, key: &str) -> bool {
        self.indexes.drop_index(label, key)
    }

    /// `true` if a property index exists for `(label, key)`.
    #[must_use]
    pub fn has_index(&self, label: &str, key: &str) -> bool {
        self.indexes.contains(label, key)
    }

    /// Iterate over the `(label, key)` pairs of all property indexes.
    ///
    /// ```rust
    /// use rune_graph::Graph;
    ///
    /// let mut g = Graph::new();
    /// g.create_index("User", "email");
    /// assert_eq!(g.indexes().collect::<Vec<_>>(), vec![("User", "email")]);
    /// ```
    pub fn indexes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.indexes.definitions()
    }

    /// Nodes labelled `label` whose property `key` equals `value`.
    ///
    /// Uses the property index for `(label, key)` when one exists (O(matches)),
    /// otherwise scans the nodes carrying `label`. Both paths return the same
    /// set of nodes, in unspecified order.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, Value, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&["City"], props! { "country" => "FR" });
    /// g.add_node(&["City"], props! { "country" => "DE" });
    ///
    /// // Works without an index (scan) ...
    /// let fr: Vec<_> = g.nodes_by_property("City", "country", &"FR".into()).collect();
    /// assert_eq!(fr, vec![a]);
    ///
    /// // ... and with one (hash lookup).
    /// g.create_index("City", "country");
    /// let fr: Vec<_> = g.nodes_by_property("City", "country", &"FR".into()).collect();
    /// assert_eq!(fr, vec![a]);
    /// ```
    #[must_use]
    pub fn nodes_by_property<'a>(
        &'a self,
        label: &'a str,
        key: &'a str,
        value: &Value,
    ) -> PropertyMatches<'a> {
        let inner = self.indexes.get(label, key).map_or_else(
            || MatchesInner::Scan {
                nodes: &self.nodes,
                ids: self.node_labels.get(label).map(HashSet::iter),
                key,
                value: value.clone(),
            },
            |map| {
                MatchesInner::Indexed(
                    crate::index::IndexKey::from_value(value)
                        .and_then(|k| map.get(&k))
                        .map(HashSet::iter),
                )
            },
        );
        PropertyMatches { inner }
    }

    /// Find nodes matching a predicate over their [`NodeEntry`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, Value, props};
    ///
    /// let mut g = Graph::new();
    /// g.add_node(&[], props! { "score" => 99_i64 });
    /// g.add_node(&[], props! { "score" => 10_i64 });
    /// let high: Vec<_> = g.find_nodes(|n| {
    ///     matches!(n.get("score"), Some(Value::Int(s)) if *s > 50)
    /// }).collect();
    /// assert_eq!(high.len(), 1);
    /// ```
    pub fn find_nodes<'a, F>(&'a self, predicate: F) -> impl Iterator<Item = NodeId> + 'a
    where
        F: Fn(&NodeEntry) -> bool + 'a,
    {
        self.nodes
            .iter()
            .filter(move |(_, entry)| predicate(entry))
            .map(|(&id, _)| id)
    }

    // ── Edge operations ──────────────────────────────────────────────────────

    /// Add a directed edge from `source` to `target` with a relationship `label`
    /// and optional properties. Returns its stable [`EdgeId`].
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::NodeNotFound`] if either endpoint does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let eid = g.add_edge(a, b, "FOLLOWS", props! {}).unwrap();
    /// assert!(g.contains_edge(eid));
    /// ```
    pub fn add_edge(
        &mut self,
        source: NodeId,
        target: NodeId,
        label: &str,
        properties: HashMap<String, Value>,
    ) -> Result<EdgeId, GraphError> {
        if !self.nodes.contains_key(&source) {
            return Err(GraphError::NodeNotFound(source));
        }
        if !self.nodes.contains_key(&target) {
            return Err(GraphError::NodeNotFound(target));
        }
        let id = EdgeId(self.next_edge);
        self.next_edge = self
            .next_edge
            .checked_add(1)
            .ok_or(GraphError::IdSpaceExhausted)?;
        self.attach_edge(id, EdgeEntry::new(source, target, label, properties));
        Ok(id)
    }

    #[cfg(feature = "persist")]
    /// Insert an edge under a caller-chosen id (snapshot load, WAL replay).
    pub(crate) fn insert_edge_with_id(
        &mut self,
        id: EdgeId,
        entry: EdgeEntry,
    ) -> Result<(), GraphError> {
        if self.edges.contains_key(&id) {
            return Err(GraphError::DuplicateEdge(id));
        }
        for n in [entry.source, entry.target] {
            if !self.nodes.contains_key(&n) {
                return Err(GraphError::NodeNotFound(n));
            }
        }
        if id.0 > MAX_RESTORED_ID {
            return Err(GraphError::IdSpaceExhausted);
        }
        self.attach_edge(id, entry);
        self.next_edge = self.next_edge.max(id.0 + 1);
        Ok(())
    }

    fn attach_edge(&mut self, id: EdgeId, entry: EdgeEntry) {
        self.out_edges.entry(entry.source).or_default().push(id);
        self.in_edges.entry(entry.target).or_default().push(id);
        self.edge_labels
            .entry(entry.label.clone())
            .or_default()
            .insert(id);
        self.edges.insert(id, entry);
    }

    /// Remove an edge by id.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::EdgeNotFound`] if `id` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let eid = g.add_edge(a, b, "X", props! {}).unwrap();
    /// g.remove_edge(eid).unwrap();
    /// assert!(!g.contains_edge(eid));
    /// ```
    pub fn remove_edge(&mut self, id: EdgeId) -> Result<(), GraphError> {
        if !self.edges.contains_key(&id) {
            return Err(GraphError::EdgeNotFound(id));
        }
        self.remove_edge_internal(id);
        Ok(())
    }

    fn remove_edge_internal(&mut self, id: EdgeId) {
        if let Some(edge) = self.edges.remove(&id) {
            if let Some(out) = self.out_edges.get_mut(&edge.source) {
                out.retain(|&e| e != id);
            }
            if let Some(inc) = self.in_edges.get_mut(&edge.target) {
                inc.retain(|&e| e != id);
            }
            if let Some(set) = self.edge_labels.get_mut(&edge.label) {
                set.remove(&id);
                if set.is_empty() {
                    self.edge_labels.remove(&edge.label);
                }
            }
        }
    }

    /// Return `true` if the graph contains an edge with this `id`.
    #[must_use]
    pub fn contains_edge(&self, id: EdgeId) -> bool {
        self.edges.contains_key(&id)
    }

    /// Borrow an edge entry by id.
    #[must_use]
    pub fn edge(&self, id: EdgeId) -> Option<&EdgeEntry> {
        self.edges.get(&id)
    }

    /// Mutably borrow an edge entry by id (properties only; the label and
    /// endpoints of an edge are fixed).
    pub fn edge_mut(&mut self, id: EdgeId) -> Option<&mut EdgeEntry> {
        self.edges.get_mut(&id)
    }

    /// The total number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Iterate over all `(EdgeId, &EdgeEntry)` pairs.
    pub fn edges(&self) -> impl Iterator<Item = (EdgeId, &EdgeEntry)> {
        self.edges.iter().map(|(&id, entry)| (id, entry))
    }

    /// Iterate over all edges whose relationship label equals `label`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "LIKES", props! {}).unwrap();
    /// g.add_edge(a, b, "FOLLOWS", props! {}).unwrap();
    /// assert_eq!(g.edges_with_label("LIKES").count(), 1);
    /// ```
    pub fn edges_with_label<'a>(&'a self, label: &'a str) -> impl Iterator<Item = EdgeId> + 'a {
        self.edge_labels
            .get(label)
            .into_iter()
            .flat_map(|set| set.iter().copied())
    }

    // ── Traversal ────────────────────────────────────────────────────────────

    /// Iterate over the [`EdgeId`]s of all outgoing edges from `node`.
    ///
    /// Returns an empty iterator if `node` does not exist.
    pub fn outgoing_edges(&self, node: NodeId) -> impl Iterator<Item = EdgeId> + '_ {
        self.out_edges
            .get(&node)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .copied()
    }

    /// Iterate over the [`EdgeId`]s of all incoming edges to `node`.
    ///
    /// Returns an empty iterator if `node` does not exist.
    pub fn incoming_edges(&self, node: NodeId) -> impl Iterator<Item = EdgeId> + '_ {
        self.in_edges
            .get(&node)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .copied()
    }

    /// Iterate over the direct successor nodes reachable from `node` via
    /// outgoing edges.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let c = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "E", props! {}).unwrap();
    /// g.add_edge(a, c, "E", props! {}).unwrap();
    /// assert_eq!(g.neighbors(a).count(), 2);
    /// ```
    pub fn neighbors(&self, node: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.outgoing_edges(node)
            .filter_map(|eid| self.edges.get(&eid).map(|e| e.target))
    }

    /// Iterate over the direct predecessor nodes of `node` (nodes that have
    /// an outgoing edge pointing to `node`).
    pub fn predecessors(&self, node: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.incoming_edges(node)
            .filter_map(|eid| self.edges.get(&eid).map(|e| e.source))
    }

    /// Iterate over `(edge, other endpoint)` pairs of the edges touching
    /// `node` in the given direction. With [`Direction::Both`], outgoing
    /// edges come first, then incoming ones; a self-loop appears twice.
    ///
    /// ```rust
    /// use rune_graph::{Direction, Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let e = g.add_edge(a, b, "E", props! {}).unwrap();
    /// assert_eq!(g.edges_directed(b, Direction::Incoming).collect::<Vec<_>>(), vec![(e, a)]);
    /// ```
    pub fn edges_directed(
        &self,
        node: NodeId,
        direction: Direction,
    ) -> impl Iterator<Item = (EdgeId, NodeId)> + '_ {
        let out = matches!(direction, Direction::Outgoing | Direction::Both);
        let inc = matches!(direction, Direction::Incoming | Direction::Both);
        let outs = self
            .outgoing_edges(node)
            .take_while(move |_| out)
            .filter_map(|eid| self.edges.get(&eid).map(|e| (eid, e.target)));
        let ins = self
            .incoming_edges(node)
            .take_while(move |_| inc)
            .filter_map(|eid| self.edges.get(&eid).map(|e| (eid, e.source)));
        outs.chain(ins)
    }

    /// Iterate over adjacent nodes in the given direction (see
    /// [`edges_directed`](Self::edges_directed)).
    pub fn neighbors_directed(
        &self,
        node: NodeId,
        direction: Direction,
    ) -> impl Iterator<Item = NodeId> + '_ {
        self.edges_directed(node, direction).map(|(_, n)| n)
    }

    /// Lazy breadth-first traversal from `start` (see [`Bfs`]).
    #[must_use]
    pub fn bfs_iter(&self, start: NodeId, direction: Direction) -> Bfs<'_> {
        Bfs::new(self, start, direction)
    }

    /// Lazy depth-first traversal from `start` (see [`Dfs`]).
    #[must_use]
    pub fn dfs_iter(&self, start: NodeId, direction: Direction) -> Dfs<'_> {
        Dfs::new(self, start, direction)
    }

    /// Breadth-first traversal from `start`. Returns nodes in the order they
    /// are first visited; `start` itself is always first.
    ///
    /// Returns an empty `Vec` if `start` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let c = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "E", props! {}).unwrap();
    /// g.add_edge(b, c, "E", props! {}).unwrap();
    /// let order = g.bfs(a);
    /// assert_eq!(order, vec![a, b, c]);
    /// ```
    #[must_use]
    pub fn bfs(&self, start: NodeId) -> Vec<NodeId> {
        self.bfs_iter(start, Direction::Outgoing).collect()
    }

    /// Depth-first traversal from `start`. Returns nodes in the order they
    /// are first visited; `start` itself is always first.
    ///
    /// Returns an empty `Vec` if `start` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let c = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "E", props! {}).unwrap();
    /// g.add_edge(b, c, "E", props! {}).unwrap();
    /// let order = g.dfs(a);
    /// assert_eq!(order[0], a);
    /// assert!(order.contains(&b));
    /// assert!(order.contains(&c));
    /// ```
    #[must_use]
    pub fn dfs(&self, start: NodeId) -> Vec<NodeId> {
        self.dfs_iter(start, Direction::Outgoing).collect()
    }

    /// Find the shortest unweighted path from `from` to `to` via BFS.
    ///
    /// Returns `None` if no path exists or either node is absent.
    /// The returned `Vec` includes both endpoints.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let c = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "E", props! {}).unwrap();
    /// g.add_edge(b, c, "E", props! {}).unwrap();
    /// let path = g.shortest_path(a, c).unwrap();
    /// assert_eq!(path, vec![a, b, c]);
    /// ```
    #[must_use]
    pub fn shortest_path(&self, from: NodeId, to: NodeId) -> Option<Vec<NodeId>> {
        if !self.nodes.contains_key(&from) || !self.nodes.contains_key(&to) {
            return None;
        }
        if from == to {
            return Some(vec![from]);
        }

        // Parent pointers instead of per-node path copies: O(V) memory.
        let mut parent: HashMap<NodeId, NodeId> = HashMap::new();
        let mut queue = VecDeque::from([from]);
        while let Some(node) = queue.pop_front() {
            for next in self.neighbors(node) {
                if next == from || parent.contains_key(&next) {
                    continue;
                }
                parent.insert(next, node);
                if next == to {
                    let mut path = vec![to];
                    let mut cur = to;
                    while let Some(&p) = parent.get(&cur) {
                        path.push(p);
                        cur = p;
                    }
                    path.reverse();
                    return Some(path);
                }
                queue.push_back(next);
            }
        }
        None
    }

    /// Return `true` if there is any directed path from `from` to `to`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let c = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "E", props! {}).unwrap();
    /// assert!(g.has_path(a, b));
    /// assert!(!g.has_path(b, c));
    /// ```
    #[must_use]
    pub fn has_path(&self, from: NodeId, to: NodeId) -> bool {
        self.contains_node(to) && self.bfs_iter(from, Direction::Outgoing).any(|n| n == to)
    }

    /// Pattern-match across every edge in the graph.
    ///
    /// Any `None` argument acts as a wildcard. Returns matching
    /// `(source NodeId, edge label, target NodeId)` triples.
    ///
    /// This is the graph-level primitive; higher-level crates translate between
    /// node names and `NodeId`s before calling this.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&["Person"], props! { "name" => "Alice" });
    /// let b = g.add_node(&["Person"], props! { "name" => "Bob" });
    /// let c = g.add_node(&["Org"],    props! { "name" => "Acme" });
    /// g.add_edge(a, b, "KNOWS",    props! {}).unwrap();
    /// g.add_edge(b, c, "WORKS_AT", props! {}).unwrap();
    ///
    /// // All outgoing edges from Alice
    /// let hits = g.match_triples(Some(a), None, None);
    /// assert_eq!(hits.len(), 1);
    ///
    /// // All KNOWS edges regardless of direction
    /// let hits = g.match_triples(None, Some("KNOWS"), None);
    /// assert_eq!(hits.len(), 1);
    ///
    /// // Who works at Acme?
    /// let hits = g.match_triples(None, Some("WORKS_AT"), Some(c));
    /// assert_eq!(hits[0].0, b);
    /// ```
    #[must_use]
    pub fn match_triples(
        &self,
        from: Option<NodeId>,
        label: Option<&str>,
        to: Option<NodeId>,
    ) -> Vec<(NodeId, &str, NodeId)> {
        let keep = |e: &&EdgeEntry| {
            from.is_none_or(|f| e.source() == f)
                && label.is_none_or(|l| e.label() == l)
                && to.is_none_or(|t| e.target() == t)
        };
        // Start from the most selective structure available.
        let ids: Box<dyn Iterator<Item = EdgeId> + '_> = match (from, label, to) {
            (Some(f), _, _) => Box::new(self.outgoing_edges(f)),
            (None, _, Some(t)) => Box::new(self.incoming_edges(t)),
            (None, Some(l), None) => Box::new(self.edges_with_label(l)),
            (None, None, None) => Box::new(self.edges.keys().copied()),
        };
        ids.filter_map(|id| self.edges.get(&id))
            .filter(keep)
            .map(|e| (e.source(), e.label.as_str(), e.target()))
            .collect()
    }

    /// Return the `(in_degree, out_degree)` of a node.
    ///
    /// Returns `None` if the node does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let c = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "e", props! {}).unwrap();
    /// g.add_edge(c, b, "e", props! {}).unwrap();
    ///
    /// let (in_b, out_b) = g.degree(b).unwrap();
    /// assert_eq!(in_b, 2);
    /// assert_eq!(out_b, 0);
    /// ```
    #[must_use]
    pub fn degree(&self, node: NodeId) -> Option<(usize, usize)> {
        if !self.contains_node(node) {
            return None;
        }
        let out = self.out_edges.get(&node).map_or(0, std::vec::Vec::len);
        let inc = self.in_edges.get(&node).map_or(0, std::vec::Vec::len);
        Some((inc, out))
    }

    /// Return `true` if the graph has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Remove all nodes and edges. Index definitions are kept (and empty);
    /// ids are not reused afterwards.
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.edges.clear();
        self.out_edges.clear();
        self.in_edges.clear();
        self.node_labels.clear();
        self.edge_labels.clear();
        self.indexes.clear_entries();
    }

    /// Set or overwrite a property on a node.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::NodeNotFound`] if `id` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, Value, props};
    ///
    /// let mut g = Graph::new();
    /// let id = g.add_node(&["User"], props! { "score" => 10_i64 });
    /// g.set_node_property(id, "score", Value::Int(99)).unwrap();
    /// assert_eq!(g.node(id).unwrap().get("score"), Some(&Value::Int(99)));
    /// ```
    pub fn set_node_property(
        &mut self,
        id: NodeId,
        key: &str,
        value: Value,
    ) -> Result<(), GraphError> {
        self.update_node(id, |n| n.set(key, value))
    }

    /// Set or overwrite a property on an edge.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::EdgeNotFound`] if `id` does not exist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, Value, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let eid = g.add_edge(a, b, "KNOWS", props! { "weight" => 1_i64 }).unwrap();
    /// g.set_edge_property(eid, "weight", Value::Int(5)).unwrap();
    /// assert_eq!(g.edge(eid).unwrap().get("weight"), Some(&Value::Int(5)));
    /// ```
    pub fn set_edge_property(
        &mut self,
        id: EdgeId,
        key: &str,
        value: Value,
    ) -> Result<(), GraphError> {
        self.edges
            .get_mut(&id)
            .ok_or(GraphError::EdgeNotFound(id))
            .map(|e| e.set(key, value))
    }

    /// Remove a property from an edge, returning its old value.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::EdgeNotFound`] if `id` does not exist.
    pub fn remove_edge_property(
        &mut self,
        id: EdgeId,
        key: &str,
    ) -> Result<Option<Value>, GraphError> {
        self.edges
            .get_mut(&id)
            .ok_or(GraphError::EdgeNotFound(id))
            .map(|e| e.remove(key))
    }

    #[cfg(feature = "wal")]
    pub(crate) const fn next_node_id(&self) -> NodeId {
        NodeId(self.next_node)
    }

    #[cfg(feature = "wal")]
    pub(crate) const fn next_edge_id(&self) -> EdgeId {
        EdgeId(self.next_edge)
    }
}
