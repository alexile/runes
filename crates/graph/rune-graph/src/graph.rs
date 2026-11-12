use std::collections::{HashMap, HashSet, VecDeque};

use crate::entry::{EdgeEntry, NodeEntry};
use crate::error::GraphError;
use crate::id::{EdgeId, NodeId};
use crate::value::Value;

#[cfg_attr(feature = "persist", derive(serde::Serialize, serde::Deserialize))]
/// An in-memory directed property graph.
///
/// Nodes and edges carry arbitrary key-value properties ([`Value`]) and string
/// labels / relationship types. The graph is built for fast traversal: forward
/// and reverse adjacency lists are maintained so that both outgoing and
/// incoming edge queries are O(degree).
///
/// This is Phase 1 of `rune-graph`. Future phases will add snapshot
/// persistence, WAL crash recovery, and page-backed on-disk storage.
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
pub struct Graph {
    nodes: HashMap<NodeId, NodeEntry>,
    edges: HashMap<EdgeId, EdgeEntry>,
    out_edges: HashMap<NodeId, Vec<EdgeId>>,
    in_edges: HashMap<NodeId, Vec<EdgeId>>,
    next_node: u64,
    next_edge: u64,
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
        self.next_node += 1;
        self.nodes.insert(id, NodeEntry::new(labels, properties));
        self.out_edges.insert(id, Vec::new());
        self.in_edges.insert(id, Vec::new());
        id
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
        self.nodes.remove(&id);
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

    /// Mutably borrow a node entry by id.
    pub fn node_mut(&mut self, id: NodeId) -> Option<&mut NodeEntry> {
        self.nodes.get_mut(&id)
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
        self.nodes
            .iter()
            .filter(move |(_, entry)| entry.has_label(label))
            .map(|(&id, _)| id)
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
        self.next_edge += 1;
        self.edges
            .insert(id, EdgeEntry::new(source, target, label, properties));
        self.out_edges.entry(source).or_default().push(id);
        self.in_edges.entry(target).or_default().push(id);
        Ok(id)
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

    /// Mutably borrow an edge entry by id.
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
        self.edges
            .iter()
            .filter(move |(_, entry)| entry.label == label)
            .map(|(&id, _)| id)
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
        if !self.nodes.contains_key(&start) {
            return Vec::new();
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        visited.insert(start);
        queue.push_back(start);

        while let Some(node) = queue.pop_front() {
            result.push(node);
            for neighbor in self.neighbors(node) {
                if visited.insert(neighbor) {
                    queue.push_back(neighbor);
                }
            }
        }
        result
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
        if !self.nodes.contains_key(&start) {
            return Vec::new();
        }
        // Iterative pre-order DFS with an explicit stack, so deep graphs
        // (long chains) cannot overflow the call stack. Successors are pushed
        // in reverse so they are visited in adjacency order, matching a
        // recursive traversal.
        let mut visited = HashSet::new();
        let mut result = Vec::new();
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            if !visited.insert(node) {
                continue;
            }
            result.push(node);
            let succ = self
                .out_edges
                .get(&node)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .rev()
                .filter_map(|eid| self.edges.get(eid).map(|e| e.target))
                .filter(|n| !visited.contains(n));
            stack.extend(succ);
        }
        result
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

        let mut visited = HashSet::new();
        let mut queue: VecDeque<(NodeId, Vec<NodeId>)> = VecDeque::new();

        visited.insert(from);
        queue.push_back((from, vec![from]));

        while let Some((node, path)) = queue.pop_front() {
            for neighbor in self.neighbors(node) {
                if neighbor == to {
                    let mut full = path;
                    full.push(neighbor);
                    return Some(full);
                }
                if visited.insert(neighbor) {
                    let mut next_path = path.clone();
                    next_path.push(neighbor);
                    queue.push_back((neighbor, next_path));
                }
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
        self.shortest_path(from, to).is_some()
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
        self.edges
            .values()
            .filter(|e| {
                from.is_none_or(|f| e.source() == f)
                    && label.is_none_or(|l| e.label() == l)
                    && to.is_none_or(|t| e.target() == t)
            })
            .map(|e| (e.source(), e.label(), e.target()))
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

    /// Remove all nodes and edges.
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.edges.clear();
        self.out_edges.clear();
        self.in_edges.clear();
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
        self.nodes
            .get_mut(&id)
            .ok_or(GraphError::NodeNotFound(id))
            .map(|n| n.set(key, value))
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

    // ── WAL helpers (pub(crate)) ──────────────────────────────────────────────

    #[cfg(feature = "wal")]
    pub(crate) const fn next_node_id(&self) -> NodeId {
        NodeId(self.next_node)
    }

    #[cfg(feature = "wal")]
    pub(crate) const fn next_edge_id(&self) -> EdgeId {
        EdgeId(self.next_edge)
    }

    /// Insert a node with a specific id, updating counter if needed.
    /// Used for WAL replay — bypasses normal ID allocation.
    #[cfg(feature = "wal")]
    pub(crate) fn restore_node(
        &mut self,
        id: NodeId,
        labels: Vec<String>,
        props: HashMap<String, Value>,
    ) {
        let entry = NodeEntry {
            labels,
            properties: props,
        };
        self.nodes.insert(id, entry);
        self.out_edges.entry(id).or_default();
        self.in_edges.entry(id).or_default();
        if id.0 >= self.next_node {
            self.next_node = id.0 + 1;
        }
    }

    /// Insert an edge with a specific id, updating counter and adjacency if needed.
    /// Used for WAL replay.
    #[cfg(feature = "wal")]
    pub(crate) fn restore_edge(
        &mut self,
        id: EdgeId,
        source: NodeId,
        target: NodeId,
        label: String,
        props: HashMap<String, Value>,
    ) {
        let entry = EdgeEntry {
            source,
            target,
            label,
            properties: props,
        };
        self.edges.insert(id, entry);
        self.out_edges.entry(source).or_default().push(id);
        self.in_edges.entry(target).or_default().push(id);
        if id.0 >= self.next_edge {
            self.next_edge = id.0 + 1;
        }
    }
}
