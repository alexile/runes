//! Lazy breadth-first and depth-first traversal iterators.

use std::collections::{HashSet, VecDeque};

use crate::graph::Graph;
use crate::id::NodeId;

/// Which edges a traversal follows from a node.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Direction, Graph, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// g.add_edge(a, b, "E", props! {}).unwrap();
///
/// assert_eq!(g.neighbors_directed(b, Direction::Incoming).collect::<Vec<_>>(), vec![a]);
/// assert_eq!(g.neighbors_directed(a, Direction::Both).count(), 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Direction {
    /// Follow edges from source to target.
    #[default]
    Outgoing,
    /// Follow edges from target back to source.
    Incoming,
    /// Follow edges both ways, as if the graph were undirected.
    Both,
}

#[derive(Debug, Clone)]
struct Filter<'g> {
    direction: Direction,
    edge_label: Option<&'g str>,
    max_depth: Option<usize>,
}

impl Filter<'_> {
    fn step<'a>(&'a self, graph: &'a Graph, node: NodeId) -> impl Iterator<Item = NodeId> + 'a {
        graph
            .edges_directed(node, self.direction)
            .filter_map(move |(eid, other)| {
                let ok = self
                    .edge_label
                    .is_none_or(|l| graph.edge(eid).is_some_and(|e| e.label() == l));
                ok.then_some(other)
            })
    }

    fn may_expand(&self, depth: usize) -> bool {
        self.max_depth.is_none_or(|m| depth < m)
    }
}

/// Lazy breadth-first traversal, created by [`Graph::bfs_iter`].
///
/// Yields each reachable node once, starting with the start node, in
/// level order. Memory is proportional to the nodes visited so far, not to
/// the graph, so stopping early (`take`, `find`) is cheap.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Direction, Graph, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let c = g.add_node(&[], props! {});
/// g.add_edge(a, b, "E", props! {}).unwrap();
/// g.add_edge(b, c, "E", props! {}).unwrap();
///
/// // Only one hop away.
/// let near: Vec<_> = g.bfs_iter(a, Direction::Outgoing).max_depth(1).collect();
/// assert_eq!(near, vec![a, b]);
/// ```
#[derive(Debug, Clone)]
pub struct Bfs<'g> {
    graph: &'g Graph,
    filter: Filter<'g>,
    visited: HashSet<NodeId>,
    queue: VecDeque<(NodeId, usize)>,
}

impl<'g> Bfs<'g> {
    pub(crate) fn new(graph: &'g Graph, start: NodeId, direction: Direction) -> Self {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        if graph.contains_node(start) {
            visited.insert(start);
            queue.push_back((start, 0));
        }
        Self {
            graph,
            filter: Filter {
                direction,
                edge_label: None,
                max_depth: None,
            },
            visited,
            queue,
        }
    }

    /// Only follow edges whose label equals `label`.
    #[must_use]
    pub const fn edge_label(mut self, label: &'g str) -> Self {
        self.filter.edge_label = Some(label);
        self
    }

    /// Do not go further than `depth` hops from the start node.
    #[must_use]
    pub const fn max_depth(mut self, depth: usize) -> Self {
        self.filter.max_depth = Some(depth);
        self
    }

    /// Like [`Iterator::next`] but also returns the hop distance from the start.
    ///
    /// ```rust
    /// use rune_graph::{Direction, Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "E", props! {}).unwrap();
    /// let mut it = g.bfs_iter(a, Direction::Outgoing);
    /// assert_eq!(it.next_with_depth(), Some((a, 0)));
    /// assert_eq!(it.next_with_depth(), Some((b, 1)));
    /// assert_eq!(it.next_with_depth(), None);
    /// ```
    pub fn next_with_depth(&mut self) -> Option<(NodeId, usize)> {
        let (node, depth) = self.queue.pop_front()?;
        if self.filter.may_expand(depth) {
            for next in self.filter.step(self.graph, node) {
                if self.visited.insert(next) {
                    self.queue.push_back((next, depth + 1));
                }
            }
        }
        Some((node, depth))
    }
}

impl Iterator for Bfs<'_> {
    type Item = NodeId;

    fn next(&mut self) -> Option<NodeId> {
        self.next_with_depth().map(|(n, _)| n)
    }
}

/// Lazy pre-order depth-first traversal, created by [`Graph::dfs_iter`].
///
/// Uses an explicit stack, so long chains cannot overflow the call stack.
/// Successors are visited in adjacency order.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Direction, Graph, props};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let c = g.add_node(&[], props! {});
/// g.add_edge(a, b, "E", props! {}).unwrap();
/// g.add_edge(c, b, "E", props! {}).unwrap();
///
/// // Walking backwards from b reaches both a and c.
/// let up: Vec<_> = g.dfs_iter(b, Direction::Incoming).collect();
/// assert_eq!(up, vec![b, a, c]);
/// ```
#[derive(Debug, Clone)]
pub struct Dfs<'g> {
    graph: &'g Graph,
    filter: Filter<'g>,
    visited: HashSet<NodeId>,
    stack: Vec<(NodeId, usize)>,
}

impl<'g> Dfs<'g> {
    pub(crate) fn new(graph: &'g Graph, start: NodeId, direction: Direction) -> Self {
        let stack = if graph.contains_node(start) {
            vec![(start, 0)]
        } else {
            Vec::new()
        };
        Self {
            graph,
            filter: Filter {
                direction,
                edge_label: None,
                max_depth: None,
            },
            visited: HashSet::new(),
            stack,
        }
    }

    /// Only follow edges whose label equals `label`.
    #[must_use]
    pub const fn edge_label(mut self, label: &'g str) -> Self {
        self.filter.edge_label = Some(label);
        self
    }

    /// Do not go further than `depth` hops from the start node (measured
    /// along the DFS tree, not the shortest path).
    #[must_use]
    pub const fn max_depth(mut self, depth: usize) -> Self {
        self.filter.max_depth = Some(depth);
        self
    }
}

impl Iterator for Dfs<'_> {
    type Item = NodeId;

    fn next(&mut self) -> Option<NodeId> {
        while let Some((node, depth)) = self.stack.pop() {
            if !self.visited.insert(node) {
                continue;
            }
            if self.filter.may_expand(depth) {
                let start = self.stack.len();
                for next in self.filter.step(self.graph, node) {
                    if !self.visited.contains(&next) {
                        self.stack.push((next, depth + 1));
                    }
                }
                // Reverse so the first successor is popped first.
                self.stack[start..].reverse();
            }
            return Some(node);
        }
        None
    }
}
