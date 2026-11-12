use rune_graph::{EdgeId, Graph, NodeId};

use crate::filter::{NodeFilter, RelFilter};

/// A single `(source, edge, target)` triple matched by [`match_pattern`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Node the matched edge starts from.
    pub source: NodeId,
    /// The matched edge.
    pub edge: EdgeId,
    /// Node the matched edge points to.
    pub target: NodeId,
}

/// A triple pattern: source filter, relationship filter, target filter.
///
/// Build one and pass it to [`match_pattern`] to query a [`Graph`].
pub struct Pattern {
    /// Filter for the source node.
    pub from: NodeFilter,
    /// Filter for the relationship.
    pub rel: RelFilter,
    /// Filter for the target node.
    pub to: NodeFilter,
}

/// Return every `(source, edge, target)` triple in `graph` that satisfies `pattern`.
///
/// Iterates all edges once — O(E). Each edge is tested against `from`, `rel`,
/// and `to` in order; the first failing filter short-circuits.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, props};
/// use rune_graph_match::{NodeFilter, RelFilter, Pattern, match_pattern};
///
/// let mut g = Graph::new();
/// let alice = g.add_node(&["Person"], props! { "name" => "Alice" });
/// let bob   = g.add_node(&["Person"], props! { "name" => "Bob" });
/// g.add_edge(alice, bob, "KNOWS", props! {}).unwrap();
///
/// let pat = Pattern { from: NodeFilter::Any, rel: RelFilter::Any, to: NodeFilter::Id(bob) };
/// let hits = match_pattern(&g, &pat);
/// assert_eq!(hits.len(), 1);
/// assert_eq!(hits[0].source, alice);
/// assert_eq!(hits[0].target, bob);
/// ```
#[must_use]
pub fn match_pattern(graph: &Graph, pattern: &Pattern) -> Vec<Match> {
    graph
        .edges()
        .filter_map(|(eid, edge)| {
            let src = edge.source();
            let tgt = edge.target();

            node_matches(graph, src, &pattern.from).then_some(())?;
            rel_matches(edge.label(), &pattern.rel).then_some(())?;
            node_matches(graph, tgt, &pattern.to).then_some(())?;

            Some(Match {
                source: src,
                edge: eid,
                target: tgt,
            })
        })
        .collect()
}

/// Chain multiple patterns together, returning sequences of node ids that
/// satisfy them end-to-end.
///
/// Each pattern's target must equal the next pattern's source, and that shared
/// node must satisfy both the previous pattern's `to` filter and the next
/// pattern's `from` filter. The result is a `Vec` of node-id sequences of
/// length `patterns.len() + 1`, one per matching edge sequence (parallel
/// edges yield repeated node sequences).
///
/// Returns an empty `Vec` if `patterns` is empty.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, props};
/// use rune_graph_match::{NodeFilter, RelFilter, Pattern, chain};
///
/// let mut g = Graph::new();
/// let a = g.add_node(&[], props! {});
/// let b = g.add_node(&[], props! {});
/// let c = g.add_node(&[], props! {});
/// g.add_edge(a, b, "e", props! {}).unwrap();
/// g.add_edge(b, c, "e", props! {}).unwrap();
///
/// let step = || Pattern { from: NodeFilter::Any, rel: RelFilter::Any, to: NodeFilter::Any };
/// let paths = chain(&g, &[step(), step()]);
/// assert_eq!(paths.len(), 1);
/// assert_eq!(paths[0], vec![a, b, c]);
/// ```
#[must_use]
pub fn chain(graph: &Graph, patterns: &[Pattern]) -> Vec<Vec<NodeId>> {
    if patterns.is_empty() {
        return Vec::new();
    }

    // Seed with the first pattern's matches.
    let mut paths: Vec<Vec<NodeId>> = match_pattern(graph, &patterns[0])
        .into_iter()
        .map(|m| vec![m.source, m.target])
        .collect();

    // Extend each path with subsequent patterns.
    for pattern in &patterns[1..] {
        let mut extended = Vec::new();
        for path in &paths {
            let Some(&last) = path.last() else {
                continue;
            };
            // `last` must also satisfy this pattern's own `from` filter.
            if !node_matches(graph, last, &pattern.from) {
                continue;
            }
            for eid in graph.outgoing_edges(last) {
                let Some(edge) = graph.edge(eid) else {
                    continue;
                };
                if rel_matches(edge.label(), &pattern.rel)
                    && node_matches(graph, edge.target(), &pattern.to)
                {
                    let mut new_path = path.clone();
                    new_path.push(edge.target());
                    extended.push(new_path);
                }
            }
        }
        paths = extended;
    }

    paths
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn node_matches(graph: &Graph, node: NodeId, filter: &NodeFilter) -> bool {
    match filter {
        NodeFilter::Any => true,
        NodeFilter::Id(id) => node == *id,
        NodeFilter::HasLabel(label) => graph.node(node).is_some_and(|n| n.has_label(label)),
        NodeFilter::Property { key, value } => graph
            .node(node)
            .and_then(|n| n.get(key))
            .is_some_and(|v| v == value),
    }
}

fn rel_matches(label: &str, filter: &RelFilter) -> bool {
    match filter {
        RelFilter::Any => true,
        RelFilter::Label(l) => label == l,
    }
}
