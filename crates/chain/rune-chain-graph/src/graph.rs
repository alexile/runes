//! The graph builder and its validation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::{self, Write as _};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::Node;
use crate::checkpoint::{Checkpointer, DEFAULT_MAX_CHECKPOINT_BYTES};
use crate::error::GraphError;
use crate::node::{END, NodeContext, Route, START};
use crate::run::CompiledGraph;
use crate::state::GraphState;

/// Default superstep budget per run, as in `LangGraph`.
pub const DEFAULT_RECURSION_LIMIT: usize = 25;
/// Default cap on tasks in one superstep.
pub const DEFAULT_MAX_FANOUT: usize = 256;
/// Default number of tasks of one superstep running at once.
pub const DEFAULT_MAX_CONCURRENCY: usize = 16;
/// Longest accepted node name, in bytes.
pub const MAX_NODE_NAME_LEN: usize = 128;

pub type Router<S> = Arc<dyn Fn(&S) -> Route<S> + Send + Sync>;

pub enum Edge<S: GraphState> {
    Static(String),
    Conditional {
        router: Router<S>,
        /// Declared destinations; empty means "any node".
        targets: Vec<String>,
    },
}

pub struct NodeEntry<S: GraphState> {
    pub name: Arc<str>,
    pub node: Arc<dyn Node<S>>,
    /// Declared `goto` destinations (for validation and drawing only).
    pub destinations: Vec<String>,
}

/// Builds a graph of nodes over a state `S` (`LangGraph`'s `StateGraph`).
///
/// Mistakes made while building (duplicate or reserved names) are recorded
/// and reported by [`compile`](Self::compile), so the builder never panics.
pub struct StateGraph<S: GraphState> {
    pub(crate) nodes: Vec<NodeEntry<S>>,
    pub(crate) index: HashMap<String, usize>,
    /// Edges by source name (`START` included), in insertion order.
    pub(crate) edges: HashMap<String, Vec<Edge<S>>>,
    errors: Vec<String>,
}

impl<S: GraphState> Default for StateGraph<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: GraphState> fmt::Debug for StateGraph<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateGraph")
            .field(
                "nodes",
                &self.nodes.iter().map(|n| &*n.name).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_NODE_NAME_LEN || name.chars().any(char::is_control) {
        return Err(format!(
            "node names must be 1-{MAX_NODE_NAME_LEN} bytes without control characters"
        ));
    }
    if name == START || name == END {
        return Err(format!("`{name}` is reserved"));
    }
    Ok(())
}

impl<S: GraphState> StateGraph<S> {
    /// An empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            index: HashMap::new(),
            edges: HashMap::new(),
            errors: Vec::new(),
        }
    }

    /// Add a node from an async closure taking the state and a
    /// [`NodeContext`] and returning a partial update.
    ///
    /// ```rust
    /// # use std::sync::Arc;
    /// # use rune_chain_graph::{MessagesState, MessagesUpdate, StateGraph};
    /// # use rune_chain_core::Message;
    /// let mut g = StateGraph::<MessagesState>::new();
    /// g.add_node("greet", |_state, _ctx| async {
    ///     Ok(MessagesUpdate::new(vec![Message::ai("hello")]))
    /// });
    /// ```
    pub fn add_node<F, Fut>(&mut self, name: impl Into<String>, node: F) -> &mut Self
    where
        F: Fn(Arc<S>, NodeContext<S>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<S::Update, GraphError>> + Send + 'static,
    {
        self.add_node_with(name, node)
    }

    /// Add any [`Node`] implementation, such as an [`LlmNode`](crate::LlmNode),
    /// [`ToolNode`](crate::ToolNode) or [`ChainNode`](crate::ChainNode).
    pub fn add_node_with(
        &mut self,
        name: impl Into<String>,
        node: impl Node<S> + 'static,
    ) -> &mut Self {
        let name = name.into();
        if let Err(e) = check_name(&name) {
            self.errors.push(e);
            return self;
        }
        if self.index.contains_key(&name) {
            self.errors.push(format!("node `{name}` is added twice"));
            return self;
        }
        self.index.insert(name.clone(), self.nodes.len());
        self.nodes.push(NodeEntry {
            name: Arc::from(name),
            node: Arc::new(node),
            destinations: Vec::new(),
        });
        self
    }

    /// Always go from `from` to `to`. `from` may be [`START`] and `to` may be
    /// [`END`]. Several edges out of one node fan out: their targets run in
    /// parallel in the next superstep.
    pub fn add_edge(&mut self, from: impl Into<String>, to: impl Into<String>) -> &mut Self {
        let (from, to) = (from.into(), to.into());
        self.edges.entry(from).or_default().push(Edge::Static(to));
        self
    }

    /// After `from`, call `router` on the updated state and go where it
    /// says: a node name, several names (run in parallel), [`END`], or
    /// [`SendTo`](crate::SendTo)s for a dynamic map.
    ///
    /// `targets` lists the nodes the router may return (plus `END`). It is
    /// used to check reachability and draw the diagram, and a router that
    /// returns anything else fails the run. Pass an empty list to allow any
    /// node.
    pub fn add_conditional_edges<R, I, T>(
        &mut self,
        from: impl Into<String>,
        router: impl Fn(&S) -> R + Send + Sync + 'static,
        targets: I,
    ) -> &mut Self
    where
        R: Into<Route<S>>,
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let router: Router<S> = Arc::new(move |s: &S| router(s).into());
        self.edges
            .entry(from.into())
            .or_default()
            .push(Edge::Conditional {
                router,
                targets: targets.into_iter().map(Into::into).collect(),
            });
        self
    }

    /// Shorthand for `add_edge(START, node)`.
    pub fn set_entry_point(&mut self, node: impl Into<String>) -> &mut Self {
        self.add_edge(START, node)
    }

    /// Shorthand for `add_edge(node, END)`.
    pub fn set_finish_point(&mut self, node: impl Into<String>) -> &mut Self {
        self.add_edge(node, END)
    }

    /// Declare where `node` may jump with [`NodeContext::goto`]. Only used to
    /// check reachability and draw the diagram.
    pub fn add_destinations<I, T>(&mut self, node: &str, targets: I) -> &mut Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        match self.index.get(node) {
            Some(&i) => self.nodes[i]
                .destinations
                .extend(targets.into_iter().map(Into::into)),
            None => self
                .errors
                .push(format!("destinations declared for unknown node `{node}`")),
        }
        self
    }

    /// Validate with default options and freeze the graph.
    ///
    /// # Errors
    ///
    /// [`GraphError::InvalidGraph`] for duplicate or reserved node names, a
    /// missing entry point, edges to or from unknown nodes, or nodes that
    /// cannot be reached from `START`.
    pub fn compile(self) -> Result<CompiledGraph<S>, GraphError> {
        self.compile_with(CompileOptions::default())
    }

    /// Validate with `options` (checkpointer, interrupts, limits) and freeze
    /// the graph.
    ///
    /// # Errors
    ///
    /// As for [`compile`](Self::compile), plus unknown interrupt nodes and
    /// zero limits.
    pub fn compile_with(self, options: CompileOptions) -> Result<CompiledGraph<S>, GraphError> {
        self.validate(&options)?;
        Ok(CompiledGraph::new(self, options))
    }

    fn known(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }

    fn validate(&self, options: &CompileOptions) -> Result<(), GraphError> {
        let invalid = |m: String| Err(GraphError::InvalidGraph(m));
        if let Some(e) = self.errors.first() {
            return invalid(e.clone());
        }
        if self.edges.get(START).is_none_or(Vec::is_empty) {
            return invalid("no entry point: add an edge from START".into());
        }
        let mut sources: Vec<&String> = self.edges.keys().collect();
        sources.sort_unstable();
        for from in sources {
            if from == END {
                return invalid("END cannot have outgoing edges".into());
            }
            if from != START && !self.known(from) {
                return invalid(format!("edge from unknown node `{from}`"));
            }
            for edge in &self.edges[from] {
                let targets: &[String] = match edge {
                    Edge::Static(to) => std::slice::from_ref(to),
                    Edge::Conditional { targets, .. } => targets,
                };
                for to in targets {
                    if to == START {
                        return invalid(format!("edge from `{from}` into START"));
                    }
                    if to != END && !self.known(to) {
                        return invalid(format!("edge from `{from}` to unknown node `{to}`"));
                    }
                }
            }
        }
        for n in &self.nodes {
            if let Some(bad) = n.destinations.iter().find(|d| *d != END && !self.known(d)) {
                return invalid(format!("`{}` declares unknown destination `{bad}`", n.name));
            }
        }
        if let Some(name) = options.node_timeouts.keys().find(|n| !self.known(n)) {
            return invalid(format!("timeout for unknown node `{name}`"));
        }
        for name in options
            .interrupt_before
            .iter()
            .chain(&options.interrupt_after)
        {
            if !self.known(name) {
                return invalid(format!("interrupt on unknown node `{name}`"));
            }
        }
        if options.recursion_limit == 0 || options.max_fanout == 0 || options.max_concurrency == 0 {
            return invalid(
                "recursion_limit, max_fanout and max_concurrency must be at least 1".into(),
            );
        }

        let reachable = self.reachable();
        if let Some(n) = self.nodes.iter().find(|n| !reachable.contains(&*n.name)) {
            return invalid(format!("node `{}` is unreachable from START", n.name));
        }
        Ok(())
    }

    /// Successors of `from` as far as the static structure says. `None`
    /// means "any node" (a router or node without declared targets).
    fn successors(&self, from: &str) -> Option<Vec<&str>> {
        let mut out = Vec::new();
        for edge in self.edges.get(from).into_iter().flatten() {
            match edge {
                Edge::Static(to) => out.push(to.as_str()),
                Edge::Conditional { targets, .. } if targets.is_empty() => return None,
                Edge::Conditional { targets, .. } => out.extend(targets.iter().map(String::as_str)),
            }
        }
        if let Some(&i) = self.index.get(from) {
            out.extend(self.nodes[i].destinations.iter().map(String::as_str));
        }
        Some(out)
    }

    fn reachable(&self) -> HashSet<&str> {
        let mut seen: HashSet<&str> = HashSet::new();
        let mut queue = VecDeque::from([START]);
        while let Some(at) = queue.pop_front() {
            let Some(next) = self.successors(at) else {
                return self.nodes.iter().map(|n| &*n.name).collect();
            };
            for to in next {
                if to != END && seen.insert(to) {
                    queue.push_back(to);
                }
            }
        }
        seen
    }

    /// The graph as a Mermaid flowchart. Solid arrows are fixed edges,
    /// dotted ones are router or `goto` destinations.
    #[must_use]
    pub fn draw_mermaid(&self) -> String {
        let mut out = String::from("flowchart TD\n");
        let id = |name: &str| -> String {
            match name {
                START => "__start__".to_owned(),
                END => "__end__".to_owned(),
                _ => self
                    .index
                    .get(name)
                    .map_or_else(|| "unknown".to_owned(), |i| format!("n{i}")),
            }
        };
        let _ = writeln!(out, "    __start__([\"__start__\"])");
        for (i, n) in self.nodes.iter().enumerate() {
            let _ = writeln!(out, "    n{i}[\"{}\"]", escape(&n.name));
        }
        let _ = writeln!(out, "    __end__([\"__end__\"])");

        let mut sources: Vec<&str> = vec![START];
        sources.extend(self.nodes.iter().map(|n| &*n.name));
        let all: Vec<&str> = self.nodes.iter().map(|n| &*n.name).chain([END]).collect();
        for from in sources {
            for edge in self.edges.get(from).into_iter().flatten() {
                match edge {
                    Edge::Static(to) => {
                        let _ = writeln!(out, "    {} --> {}", id(from), id(to));
                    }
                    Edge::Conditional { targets, .. } => {
                        let list: Vec<&str> = if targets.is_empty() {
                            all.clone()
                        } else {
                            targets.iter().map(String::as_str).collect()
                        };
                        for to in list {
                            let _ = writeln!(out, "    {} -.-> {}", id(from), id(to));
                        }
                    }
                }
            }
            if let Some(&i) = self.index.get(from) {
                for to in &self.nodes[i].destinations {
                    let _ = writeln!(out, "    {} -. goto .-> {}", id(from), id(to));
                }
            }
        }
        out
    }
}

/// Make a label safe inside a quoted Mermaid string.
fn escape(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for c in label.chars() {
        match c {
            '"' => out.push_str("#quot;"),
            '<' => out.push_str("#lt;"),
            '>' => out.push_str("#gt;"),
            '#' => out.push_str("#35;"),
            _ => out.push(c),
        }
    }
    out
}

/// Settings fixed at compile time: checkpointer, interrupts and limits.
///
/// ```rust
/// use std::{sync::Arc, time::Duration};
/// use rune_chain_graph::{CompileOptions, InMemoryCheckpointer};
///
/// let options = CompileOptions::default()
///     .checkpointer(Arc::new(InMemoryCheckpointer::new()))
///     .interrupt_before(["tools"])
///     .recursion_limit(10)
///     .node_timeout(Some(Duration::from_secs(30)));
/// assert_eq!(options.recursion_limit, 10);
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct CompileOptions {
    /// Where checkpoints go. Needed for interrupts, resume and history.
    pub checkpointer: Option<Arc<dyn Checkpointer>>,
    /// Pause before these nodes run.
    pub interrupt_before: Vec<String>,
    /// Pause after these nodes run.
    pub interrupt_after: Vec<String>,
    /// Supersteps per run before [`GraphError::RecursionLimit`] (default 25).
    pub recursion_limit: usize,
    /// Most tasks in one superstep (default 256).
    pub max_fanout: usize,
    /// Most tasks of one superstep running at once (default 16).
    pub max_concurrency: usize,
    /// Timeout for every node (default none).
    pub node_timeout: Option<Duration>,
    /// Per-node timeouts, overriding `node_timeout`.
    pub node_timeouts: HashMap<String, Duration>,
    /// Largest serialized checkpoint accepted (default 16 MiB).
    pub max_checkpoint_bytes: usize,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            checkpointer: None,
            interrupt_before: Vec::new(),
            interrupt_after: Vec::new(),
            recursion_limit: DEFAULT_RECURSION_LIMIT,
            max_fanout: DEFAULT_MAX_FANOUT,
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            node_timeout: None,
            node_timeouts: HashMap::new(),
            max_checkpoint_bytes: DEFAULT_MAX_CHECKPOINT_BYTES,
        }
    }
}

impl fmt::Debug for CompileOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompileOptions")
            .field("checkpointer", &self.checkpointer.is_some())
            .field("interrupt_before", &self.interrupt_before)
            .field("interrupt_after", &self.interrupt_after)
            .field("recursion_limit", &self.recursion_limit)
            .field("max_fanout", &self.max_fanout)
            .field("max_concurrency", &self.max_concurrency)
            .field("node_timeout", &self.node_timeout)
            .field("node_timeouts", &self.node_timeouts)
            .field("max_checkpoint_bytes", &self.max_checkpoint_bytes)
            .finish()
    }
}

impl CompileOptions {
    /// Persist checkpoints to `checkpointer`.
    #[must_use]
    pub fn checkpointer(mut self, checkpointer: Arc<dyn Checkpointer>) -> Self {
        self.checkpointer = Some(checkpointer);
        self
    }

    /// Pause before these nodes.
    #[must_use]
    pub fn interrupt_before<I: IntoIterator<Item = T>, T: Into<String>>(
        mut self,
        nodes: I,
    ) -> Self {
        self.interrupt_before
            .extend(nodes.into_iter().map(Into::into));
        self
    }

    /// Pause after these nodes.
    #[must_use]
    pub fn interrupt_after<I: IntoIterator<Item = T>, T: Into<String>>(mut self, nodes: I) -> Self {
        self.interrupt_after
            .extend(nodes.into_iter().map(Into::into));
        self
    }

    /// Set [`recursion_limit`](Self::recursion_limit).
    #[must_use]
    pub const fn recursion_limit(mut self, steps: usize) -> Self {
        self.recursion_limit = steps;
        self
    }

    /// Set [`max_fanout`](Self::max_fanout).
    #[must_use]
    pub const fn max_fanout(mut self, tasks: usize) -> Self {
        self.max_fanout = tasks;
        self
    }

    /// Set [`max_concurrency`](Self::max_concurrency).
    #[must_use]
    pub const fn max_concurrency(mut self, tasks: usize) -> Self {
        self.max_concurrency = tasks;
        self
    }

    /// Set [`node_timeout`](Self::node_timeout).
    #[must_use]
    pub const fn node_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.node_timeout = timeout;
        self
    }

    /// Give `node` its own timeout.
    #[must_use]
    pub fn timeout_for(mut self, node: impl Into<String>, timeout: Duration) -> Self {
        self.node_timeouts.insert(node.into(), timeout);
        self
    }

    /// Set [`max_checkpoint_bytes`](Self::max_checkpoint_bytes).
    #[must_use]
    pub const fn max_checkpoint_bytes(mut self, bytes: usize) -> Self {
        self.max_checkpoint_bytes = bytes;
        self
    }
}
