use std::collections::HashSet;

use rune_graph::{EdgeId, Graph, NodeId, Value};

use crate::predicate::P;

// ── Traversal ─────────────────────────────────────────────────────────────────

/// A lazy traversal over a [`Graph`], parameterised by the type of element
/// currently in the pipeline.
///
/// Steps are chained by consuming `self` and returning a new `Traversal<T>`.
/// Nothing executes until a terminal step ([`collect`], [`next`], [`count`]) is
/// called. This mirrors the `TinkerPop` traversal machine model: steps build a
/// pipeline; the terminal drains it.
///
/// You obtain a `Traversal` from a [`GraphTraversalSource`]:
///
/// ```rust
/// use rune_graph::{Graph, Value, props};
/// use rune_graph_gremlin::GraphTraversalSource;
///
/// let mut g = Graph::new();
/// let a = g.add_node(&["Person"], props! { "name" => "Alice" });
/// let b = g.add_node(&["Person"], props! { "name" => "Bob" });
/// g.add_edge(a, b, "knows", props! {}).unwrap();
///
/// let src = GraphTraversalSource::new(&g);
/// let names: Vec<_> = src.v().has("name", "Alice").out("knows").values("name").collect();
/// assert_eq!(names, vec![Value::Str("Bob".into())]);
/// ```
///
/// [`GraphTraversalSource`]: crate::GraphTraversalSource
/// [`collect`]: VertexTraversal::collect
/// [`next`]: VertexTraversal::next
/// [`count`]: VertexTraversal::count
pub(crate) struct Traversal<'g, T> {
    pub(crate) graph: &'g Graph,
    pub(crate) inner: Box<dyn Iterator<Item = T> + 'g>,
}

// ── VertexTraversal ───────────────────────────────────────────────────────────

/// A traversal whose current elements are graph vertices ([`NodeId`]s).
///
/// Produced by [`GraphTraversalSource::v`] and by most vertex-to-vertex steps.
/// Use the step methods to move through the graph; call a terminal step to
/// materialise results.
///
/// [`GraphTraversalSource::v`]: crate::GraphTraversalSource::v
pub struct VertexTraversal<'g>(pub(crate) Traversal<'g, NodeId>);

impl<'g> VertexTraversal<'g> {
    // ── Vertex → Vertex steps ─────────────────────────────────────────────────

    /// Follow all outgoing edges, yielding the target vertices.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    /// use rune_graph_gremlin::GraphTraversalSource;
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "e", props! {}).unwrap();
    ///
    /// let src = GraphTraversalSource::new(&g);
    /// assert_eq!(src.v_id(a).out_any().collect(), vec![b]);
    /// ```
    #[must_use]
    pub fn out_any(self) -> Self {
        self.out_filtered(None)
    }

    /// Follow outgoing edges whose label equals `label`, yielding target vertices.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    /// use rune_graph_gremlin::GraphTraversalSource;
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let c = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "knows",   props! {}).unwrap();
    /// g.add_edge(a, c, "created", props! {}).unwrap();
    ///
    /// let src = GraphTraversalSource::new(&g);
    /// assert_eq!(src.v_id(a).out("knows").collect(), vec![b]);
    /// ```
    #[must_use]
    pub fn out(self, label: &'g str) -> Self {
        self.out_filtered(Some(label))
    }

    /// Follow all incoming edges, yielding the source vertices.
    #[must_use]
    pub fn in_any(self) -> Self {
        self.in_filtered(None)
    }

    /// Follow incoming edges whose label equals `label`, yielding source vertices.
    #[must_use]
    pub fn in_(self, label: &'g str) -> Self {
        self.in_filtered(Some(label))
    }

    /// Follow both outgoing and incoming edges, yielding adjacent vertices.
    #[must_use]
    pub fn both_any(self) -> Self {
        self.both_filtered(None)
    }

    /// Follow edges (in either direction) whose label equals `label`.
    #[must_use]
    pub fn both(self, label: &'g str) -> Self {
        self.both_filtered(Some(label))
    }

    // ── Vertex → Edge steps ───────────────────────────────────────────────────

    /// Yield all outgoing edges from each current vertex.
    #[must_use]
    pub fn out_e_any(self) -> EdgeTraversal<'g> {
        self.out_e_filtered(None)
    }

    /// Yield outgoing edges whose label equals `label`.
    #[must_use]
    pub fn out_e(self, label: &'g str) -> EdgeTraversal<'g> {
        self.out_e_filtered(Some(label))
    }

    /// Yield all incoming edges into each current vertex.
    #[must_use]
    pub fn in_e_any(self) -> EdgeTraversal<'g> {
        self.in_e_filtered(None)
    }

    /// Yield incoming edges whose label equals `label`.
    #[must_use]
    pub fn in_e(self, label: &'g str) -> EdgeTraversal<'g> {
        self.in_e_filtered(Some(label))
    }

    // ── Filter steps ──────────────────────────────────────────────────────────

    /// Keep only vertices that have a property `key` equal to `value`.
    ///
    /// `value` is converted via [`Value::from`], so you can pass `"Alice"`,
    /// `30_i64`, `true`, etc. directly.
    #[must_use]
    pub fn has(self, key: &'g str, value: impl Into<Value>) -> Self {
        let value = value.into();
        self.filter_nodes(move |g, nid| {
            g.node(nid)
                .and_then(|n| n.get(key))
                .is_some_and(|v| v == &value)
        })
    }

    /// Keep only vertices whose property `key` satisfies predicate `p`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    /// use rune_graph_gremlin::{GraphTraversalSource, P};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! { "score" => 42_i64 });
    /// let b = g.add_node(&[], props! { "score" => 10_i64 });
    ///
    /// let src = GraphTraversalSource::new(&g);
    /// let hits = src.v().has_p("score", P::gt(20_i64)).collect();
    /// assert_eq!(hits, vec![a]);
    /// ```
    #[must_use]
    pub fn has_p(self, key: &'g str, p: P) -> Self {
        self.filter_nodes(move |g, nid| {
            g.node(nid)
                .and_then(|n| n.get(key))
                .is_some_and(|v| p.test(v))
        })
    }

    /// Keep only vertices that carry `label` in their label set.
    #[must_use]
    pub fn has_label(self, label: &'g str) -> Self {
        self.filter_nodes(move |g, nid| g.node(nid).is_some_and(|n| n.has_label(label)))
    }

    /// Keep only vertices where `predicate(graph, node_id)` returns `true`.
    #[must_use]
    pub fn filter<F>(self, predicate: F) -> Self
    where
        F: Fn(&Graph, NodeId) -> bool + 'g,
    {
        self.filter_nodes(predicate)
    }

    /// Remove duplicate vertices from the stream.
    #[must_use]
    pub fn dedup(self) -> Self {
        let graph = self.0.graph;
        let mut seen = HashSet::new();
        VertexTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.filter(move |&nid| seen.insert(nid))),
        })
    }

    // ── Map / projection steps ────────────────────────────────────────────────

    /// Extract property `key` from each vertex, dropping vertices that lack it.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, Value, props};
    /// use rune_graph_gremlin::GraphTraversalSource;
    ///
    /// let mut g = Graph::new();
    /// g.add_node(&[], props! { "name" => "Alice" });
    ///
    /// let src = GraphTraversalSource::new(&g);
    /// let names: Vec<_> = src.v().values("name").collect();
    /// assert_eq!(names, vec![Value::Str("Alice".into())]);
    /// ```
    #[must_use]
    pub fn values(self, key: &'g str) -> ValueTraversal<'g> {
        let graph = self.0.graph;
        ValueTraversal(Traversal {
            graph,
            inner: Box::new(
                self.0
                    .inner
                    .filter_map(move |nid| graph.node(nid)?.get(key).cloned()),
            ),
        })
    }

    /// Extract all property values from each vertex as `(key, value)` pairs.
    #[must_use]
    pub fn properties(self) -> ValueTraversal<'g> {
        let graph = self.0.graph;
        ValueTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.flat_map(move |nid| {
                let props: Vec<Value> = graph
                    .node(nid)
                    .map(|n| n.properties().values().cloned().collect())
                    .unwrap_or_default();
                props.into_iter()
            })),
        })
    }

    /// Take at most `n` vertices from the stream.
    #[must_use]
    pub fn limit(self, n: usize) -> Self {
        let graph = self.0.graph;
        VertexTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.take(n)),
        })
    }

    // ── Repeat step ───────────────────────────────────────────────────────────

    /// Apply `step` exactly `times` times to the current vertex set.
    ///
    /// At each iteration the step function receives a fresh `VertexTraversal`
    /// seeded with the current batch of vertices. The final batch is returned
    /// as a new `VertexTraversal`. Useful for fixed-depth BFS expansions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    /// use rune_graph_gremlin::GraphTraversalSource;
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let c = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "e", props! {}).unwrap();
    /// g.add_edge(b, c, "e", props! {}).unwrap();
    ///
    /// let src = GraphTraversalSource::new(&g);
    /// // Two hops from `a`
    /// let result = src.v_id(a).repeat_times(2, |t| t.out_any()).collect();
    /// assert_eq!(result, vec![c]);
    /// ```
    #[must_use]
    pub fn repeat_times<F>(self, times: usize, step: F) -> Self
    where
        F: Fn(Self) -> Self,
    {
        let graph = self.0.graph;
        let mut current: Vec<NodeId> = self.0.inner.collect();
        for _ in 0..times {
            current = step(VertexTraversal(Traversal {
                graph,
                inner: Box::new(current.into_iter()),
            }))
            .0
            .inner
            .collect();
        }
        VertexTraversal(Traversal {
            graph,
            inner: Box::new(current.into_iter()),
        })
    }

    /// Expand outward until `condition(graph, node_id)` returns `true` for every
    /// current vertex, or until `max_depth` hops are exhausted.
    ///
    /// Uses BFS and deduplicates visited nodes. Returns the set of vertices
    /// where the condition first held.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, Value, props};
    /// use rune_graph_gremlin::GraphTraversalSource;
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! { "done" => false });
    /// let b = g.add_node(&[], props! { "done" => false });
    /// let c = g.add_node(&[], props! { "done" => true });
    /// g.add_edge(a, b, "e", props! {}).unwrap();
    /// g.add_edge(b, c, "e", props! {}).unwrap();
    ///
    /// let src = GraphTraversalSource::new(&g);
    /// let result = src.v_id(a)
    ///     .repeat_until(|t| t.out_any(), |g, nid| {
    ///         g.node(nid)
    ///             .and_then(|n| n.get("done"))
    ///             .map_or(false, |v| v == &Value::Bool(true))
    ///     }, 10)
    ///     .collect();
    /// assert_eq!(result, vec![c]);
    /// ```
    #[must_use]
    pub fn repeat_until<F, C>(self, step: F, condition: C, max_depth: usize) -> Self
    where
        F: Fn(Self) -> Self,
        C: Fn(&Graph, NodeId) -> bool,
    {
        let graph = self.0.graph;
        let mut current: Vec<NodeId> = self.0.inner.collect();
        let mut visited: HashSet<NodeId> = current.iter().copied().collect();

        for _ in 0..max_depth {
            let (done, pending): (Vec<_>, Vec<_>) =
                current.iter().partition(|&&nid| condition(graph, nid));

            if !done.is_empty() {
                return VertexTraversal(Traversal {
                    graph,
                    inner: Box::new(done.into_iter()),
                });
            }

            let next: Vec<NodeId> = step(VertexTraversal(Traversal {
                graph,
                inner: Box::new(pending.into_iter()),
            }))
            .0
            .inner
            .filter(|nid| visited.insert(*nid))
            .collect();

            if next.is_empty() {
                break;
            }
            current = next;
        }

        // Return any nodes satisfying the condition in the final batch.
        let hits: Vec<NodeId> = current
            .into_iter()
            .filter(|&nid| condition(graph, nid))
            .collect();
        VertexTraversal(Traversal {
            graph,
            inner: Box::new(hits.into_iter()),
        })
    }

    // ── Path step ─────────────────────────────────────────────────────────────

    /// Collect every reachable path from the current vertices via `step`,
    /// up to `max_depth` hops. Each path is a `Vec<NodeId>` starting at one
    /// of the seed vertices. Every prefix is reported once, including the
    /// zero-hop path of each seed; paths are emitted shortest first.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    /// use rune_graph_gremlin::GraphTraversalSource;
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&[], props! {});
    /// let b = g.add_node(&[], props! {});
    /// let c = g.add_node(&[], props! {});
    /// g.add_edge(a, b, "e", props! {}).unwrap();
    /// g.add_edge(b, c, "e", props! {}).unwrap();
    ///
    /// let src = GraphTraversalSource::new(&g);
    /// let paths = src.v_id(a).paths(|t| t.out_any(), 2);
    /// assert!(paths.contains(&vec![a, b, c]));
    /// ```
    pub fn paths<F>(self, step: F, max_depth: usize) -> Vec<Vec<NodeId>>
    where
        F: Fn(Self) -> Self,
    {
        let graph = self.0.graph;
        let seeds: Vec<NodeId> = self.0.inner.collect();
        let mut results: Vec<Vec<NodeId>> = Vec::new();
        let mut frontier: Vec<Vec<NodeId>> = seeds.iter().map(|&s| vec![s]).collect();

        for _ in 0..max_depth {
            let mut next_frontier = Vec::new();
            for path in &frontier {
                let Some(&last) = path.last() else {
                    continue;
                };
                let nexts: Vec<NodeId> = step(VertexTraversal(Traversal {
                    graph,
                    inner: Box::new(std::iter::once(last)),
                }))
                .0
                .inner
                .collect();

                // Every frontier path is added to `results` exactly once
                // (below), so dead ends need no special handling here.
                for next in nexts {
                    let mut new_path = path.clone();
                    new_path.push(next);
                    next_frontier.push(new_path);
                }
            }
            if next_frontier.is_empty() {
                break;
            }
            results.extend(frontier);
            frontier = next_frontier;
        }
        results.extend(frontier);
        results
    }

    // ── Terminal steps ────────────────────────────────────────────────────────

    /// Collect all vertices into a `Vec<NodeId>`.
    #[must_use]
    pub fn collect(self) -> Vec<NodeId> {
        self.0.inner.collect()
    }

    /// Return the first vertex, or `None` if the traversal is empty.
    #[must_use]
    pub fn next(mut self) -> Option<NodeId> {
        self.0.inner.next()
    }

    /// Count the number of vertices in the traversal.
    #[must_use]
    pub fn count(self) -> usize {
        self.0.inner.count()
    }

    /// Return `true` if the traversal yields at least one vertex.
    #[must_use]
    pub fn any(mut self) -> bool {
        self.0.inner.next().is_some()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn filter_nodes<F>(self, predicate: F) -> Self
    where
        F: Fn(&Graph, NodeId) -> bool + 'g,
    {
        let graph = self.0.graph;
        VertexTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.filter(move |&nid| predicate(graph, nid))),
        })
    }

    fn out_filtered(self, label: Option<&'g str>) -> Self {
        let graph = self.0.graph;
        VertexTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.flat_map(move |nid| {
                graph
                    .outgoing_edges(nid)
                    .filter(move |&eid| {
                        label.is_none_or(|l| graph.edge(eid).is_some_and(|e| e.label() == l))
                    })
                    .filter_map(|eid| graph.edge(eid).map(rune_graph::EdgeEntry::target))
            })),
        })
    }

    fn in_filtered(self, label: Option<&'g str>) -> Self {
        let graph = self.0.graph;
        VertexTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.flat_map(move |nid| {
                graph
                    .incoming_edges(nid)
                    .filter(move |&eid| {
                        label.is_none_or(|l| graph.edge(eid).is_some_and(|e| e.label() == l))
                    })
                    .filter_map(|eid| graph.edge(eid).map(rune_graph::EdgeEntry::source))
            })),
        })
    }

    fn both_filtered(self, label: Option<&'g str>) -> Self {
        let graph = self.0.graph;
        VertexTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.flat_map(move |nid| {
                let inc: Vec<NodeId> = graph
                    .incoming_edges(nid)
                    .filter(move |&eid| {
                        label.is_none_or(|l| graph.edge(eid).is_some_and(|e| e.label() == l))
                    })
                    .filter_map(|eid| graph.edge(eid).map(rune_graph::EdgeEntry::source))
                    .collect();
                graph
                    .outgoing_edges(nid)
                    .filter(move |&eid| {
                        label.is_none_or(|l| graph.edge(eid).is_some_and(|e| e.label() == l))
                    })
                    .filter_map(|eid| graph.edge(eid).map(rune_graph::EdgeEntry::target))
                    .chain(inc)
            })),
        })
    }

    fn out_e_filtered(self, label: Option<&'g str>) -> EdgeTraversal<'g> {
        let graph = self.0.graph;
        EdgeTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.flat_map(move |nid| {
                graph.outgoing_edges(nid).filter(move |&eid| {
                    label.is_none_or(|l| graph.edge(eid).is_some_and(|e| e.label() == l))
                })
            })),
        })
    }

    fn in_e_filtered(self, label: Option<&'g str>) -> EdgeTraversal<'g> {
        let graph = self.0.graph;
        EdgeTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.flat_map(move |nid| {
                graph.incoming_edges(nid).filter(move |&eid| {
                    label.is_none_or(|l| graph.edge(eid).is_some_and(|e| e.label() == l))
                })
            })),
        })
    }
}

// ── EdgeTraversal ─────────────────────────────────────────────────────────────

/// A traversal whose current elements are graph edges ([`EdgeId`]s).
///
/// Produced by edge-step methods on [`VertexTraversal`] such as [`out_e`] and
/// [`in_e`]. Convert back to vertices with [`in_v`] or [`out_v`].
///
/// [`out_e`]: VertexTraversal::out_e
/// [`in_e`]: VertexTraversal::in_e
/// [`in_v`]: EdgeTraversal::in_v
/// [`out_v`]: EdgeTraversal::out_v
pub struct EdgeTraversal<'g>(pub(crate) Traversal<'g, EdgeId>);

impl<'g> EdgeTraversal<'g> {
    // ── Edge → Vertex steps ───────────────────────────────────────────────────

    /// Yield the target (in-vertex) of each edge.
    #[must_use]
    pub fn in_v(self) -> VertexTraversal<'g> {
        let graph = self.0.graph;
        VertexTraversal(Traversal {
            graph,
            inner: Box::new(
                self.0
                    .inner
                    .filter_map(move |eid| graph.edge(eid).map(rune_graph::EdgeEntry::target)),
            ),
        })
    }

    /// Yield the source (out-vertex) of each edge.
    #[must_use]
    pub fn out_v(self) -> VertexTraversal<'g> {
        let graph = self.0.graph;
        VertexTraversal(Traversal {
            graph,
            inner: Box::new(
                self.0
                    .inner
                    .filter_map(move |eid| graph.edge(eid).map(rune_graph::EdgeEntry::source)),
            ),
        })
    }

    // ── Filter steps ──────────────────────────────────────────────────────────

    /// Keep only edges whose relationship type equals `label`.
    #[must_use]
    pub fn has_label(self, label: &'g str) -> Self {
        let graph = self.0.graph;
        EdgeTraversal(Traversal {
            graph,
            inner: Box::new(
                self.0
                    .inner
                    .filter(move |&eid| graph.edge(eid).is_some_and(|e| e.label() == label)),
            ),
        })
    }

    /// Keep only edges whose property `key` equals `value`.
    #[must_use]
    pub fn has(self, key: &'g str, value: impl Into<Value>) -> Self {
        let value = value.into();
        let graph = self.0.graph;
        EdgeTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.filter(move |&eid| {
                graph
                    .edge(eid)
                    .and_then(|e| e.get(key))
                    .is_some_and(|v| v == &value)
            })),
        })
    }

    /// Keep only edges whose property `key` satisfies predicate `p`.
    #[must_use]
    pub fn has_p(self, key: &'g str, p: P) -> Self {
        let graph = self.0.graph;
        EdgeTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.filter(move |&eid| {
                graph
                    .edge(eid)
                    .and_then(|e| e.get(key))
                    .is_some_and(|v| p.test(v))
            })),
        })
    }

    // ── Map / projection steps ────────────────────────────────────────────────

    /// Extract property `key` from each edge.
    #[must_use]
    pub fn values(self, key: &'g str) -> ValueTraversal<'g> {
        let graph = self.0.graph;
        ValueTraversal(Traversal {
            graph,
            inner: Box::new(
                self.0
                    .inner
                    .filter_map(move |eid| graph.edge(eid)?.get(key).cloned()),
            ),
        })
    }

    /// Extract the relationship label of each edge.
    #[must_use]
    pub fn label(self) -> ValueTraversal<'g> {
        let graph = self.0.graph;
        ValueTraversal(Traversal {
            graph,
            inner: Box::new(
                self.0.inner.filter_map(move |eid| {
                    graph.edge(eid).map(|e| Value::Str(e.label().to_string()))
                }),
            ),
        })
    }

    /// Take at most `n` edges.
    #[must_use]
    pub fn limit(self, n: usize) -> Self {
        let graph = self.0.graph;
        EdgeTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.take(n)),
        })
    }

    // ── Terminal steps ────────────────────────────────────────────────────────

    /// Collect all edges into a `Vec<EdgeId>`.
    #[must_use]
    pub fn collect(self) -> Vec<EdgeId> {
        self.0.inner.collect()
    }

    /// Return the first edge, or `None`.
    #[must_use]
    pub fn next(mut self) -> Option<EdgeId> {
        self.0.inner.next()
    }

    /// Count the edges in the traversal.
    #[must_use]
    pub fn count(self) -> usize {
        self.0.inner.count()
    }
}

// ── ValueTraversal ────────────────────────────────────────────────────────────

/// A traversal whose current elements are property [`Value`]s.
///
/// Produced by [`values`](VertexTraversal::values) and [`label`](EdgeTraversal::label).
pub struct ValueTraversal<'g>(pub(crate) Traversal<'g, Value>);

impl<'g> ValueTraversal<'g> {
    /// Keep only values that satisfy `predicate`.
    #[must_use]
    pub fn filter<F>(self, predicate: F) -> Self
    where
        F: Fn(&Value) -> bool + 'g,
    {
        let graph = self.0.graph;
        ValueTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.filter(move |v| predicate(v))),
        })
    }

    /// Take at most `n` values.
    #[must_use]
    pub fn limit(self, n: usize) -> Self {
        let graph = self.0.graph;
        ValueTraversal(Traversal {
            graph,
            inner: Box::new(self.0.inner.take(n)),
        })
    }

    /// Collect all values into a `Vec<Value>`.
    #[must_use]
    pub fn collect(self) -> Vec<Value> {
        self.0.inner.collect()
    }

    /// Return the first value, or `None`.
    #[must_use]
    pub fn next(mut self) -> Option<Value> {
        self.0.inner.next()
    }

    /// Count the values in the traversal.
    #[must_use]
    pub fn count(self) -> usize {
        self.0.inner.count()
    }
}
