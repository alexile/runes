//! Nodes, routing targets and the per-call node context.

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{mpsc, watch};

use crate::error::{GraphError, Interrupt, InterruptKind};
use crate::run::Event;
use crate::state::GraphState;

/// The graph's entry point. Edges from `START` pick the first nodes.
pub const START: &str = "__start__";
/// The graph's exit. Routing to `END` finishes that branch.
pub const END: &str = "__end__";

/// One unit of work in a graph.
///
/// Closures are added with [`StateGraph::add_node`](crate::StateGraph::add_node);
/// implement this trait for reusable nodes and add them with
/// [`StateGraph::add_node_with`](crate::StateGraph::add_node_with).
#[async_trait]
pub trait Node<S: GraphState>: Send + Sync {
    /// Read `state` and return a partial update.
    async fn run(&self, state: Arc<S>, ctx: NodeContext<S>) -> Result<S::Update, GraphError>;
}

#[async_trait]
impl<S, F, Fut> Node<S> for F
where
    S: GraphState,
    F: Fn(Arc<S>, NodeContext<S>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<S::Update, GraphError>> + Send,
{
    async fn run(&self, state: Arc<S>, ctx: NodeContext<S>) -> Result<S::Update, GraphError> {
        self(state, ctx).await
    }
}

/// Run `node` with its own copy of the state, with `update` merged in
/// (`LangGraph`'s `Send`). Return several from a router to map a node over
/// dynamic items; each runs as its own task in the next superstep.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SendTo<S: GraphState> {
    /// Target node.
    pub node: String,
    /// Merged into the task's private copy of the state.
    pub update: S::Update,
}

impl<S: GraphState> SendTo<S> {
    /// Send `update` to `node`.
    pub fn new(node: impl Into<String>, update: S::Update) -> Self {
        Self {
            node: node.into(),
            update,
        }
    }
}

impl<S: GraphState> fmt::Debug for SendTo<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendTo")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

/// Where control goes next: a node by name (or [`END`]), or a [`SendTo`].
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Target<S: GraphState> {
    /// Run this node (or stop, for [`END`]).
    Node(String),
    /// Run a node with a private state update.
    Send(SendTo<S>),
}

impl<S: GraphState> Target<S> {
    /// The node this target runs.
    #[must_use]
    pub fn node(&self) -> &str {
        match self {
            Self::Node(n) => n,
            Self::Send(s) => &s.node,
        }
    }
}

impl<S: GraphState> fmt::Debug for Target<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(n) => f.debug_tuple("Node").field(n).finish(),
            Self::Send(s) => f.debug_tuple("Send").field(s).finish(),
        }
    }
}

/// What a router returns: zero or more [`Target`]s. Converts from a node
/// name, a list of names, a [`SendTo`] or a list of them.
pub struct Route<S: GraphState>(pub Vec<Target<S>>);

impl<S: GraphState> From<&str> for Route<S> {
    fn from(node: &str) -> Self {
        Self(vec![Target::Node(node.to_owned())])
    }
}

impl<S: GraphState> From<String> for Route<S> {
    fn from(node: String) -> Self {
        Self(vec![Target::Node(node)])
    }
}

impl<S: GraphState> From<Vec<&str>> for Route<S> {
    fn from(nodes: Vec<&str>) -> Self {
        Self(
            nodes
                .into_iter()
                .map(|n| Target::Node(n.to_owned()))
                .collect(),
        )
    }
}

impl<S: GraphState, const N: usize> From<[&str; N]> for Route<S> {
    fn from(nodes: [&str; N]) -> Self {
        Self(
            nodes
                .into_iter()
                .map(|n| Target::Node(n.to_owned()))
                .collect(),
        )
    }
}

impl<S: GraphState> From<Vec<String>> for Route<S> {
    fn from(nodes: Vec<String>) -> Self {
        Self(nodes.into_iter().map(Target::Node).collect())
    }
}

impl<S: GraphState> From<SendTo<S>> for Route<S> {
    fn from(send: SendTo<S>) -> Self {
        Self(vec![Target::Send(send)])
    }
}

impl<S: GraphState> From<Vec<SendTo<S>>> for Route<S> {
    fn from(sends: Vec<SendTo<S>>) -> Self {
        Self(sends.into_iter().map(Target::Send).collect())
    }
}

impl<S: GraphState> From<Vec<Target<S>>> for Route<S> {
    fn from(targets: Vec<Target<S>>) -> Self {
        Self(targets)
    }
}

/// Cancels a run from outside. Clones share the same flag.
///
/// ```rust
/// let token = rune_chain_graph::CancelToken::new();
/// let clone = token.clone();
/// clone.cancel();
/// assert!(token.is_cancelled());
/// ```
#[derive(Debug, Clone)]
pub struct CancelToken(Arc<watch::Sender<bool>>);

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelToken {
    /// A token that has not fired.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(watch::Sender::new(false)))
    }

    /// Fire the token. Running nodes are dropped at their next await point.
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }

    /// Whether [`cancel`](Self::cancel) was called.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves once the token fires.
    pub async fn cancelled(&self) {
        let mut rx = self.0.subscribe();
        // The sender lives in `self`, so this only ends when the value flips.
        let _ = rx.wait_for(|fired| *fired).await;
    }
}

pub type EventSender<S> = mpsc::Sender<Result<Event<S>, GraphError>>;

/// Per-call handle a node gets next to the state: its name and step, the
/// `interrupt` call, `goto`/`send` control flow and token streaming.
pub struct NodeContext<S: GraphState> {
    pub(crate) node: Arc<str>,
    pub(crate) step: usize,
    pub(crate) task: usize,
    pub(crate) resume: Arc<[Value]>,
    pub(crate) interrupts: AtomicUsize,
    pub(crate) goto: Arc<Mutex<Vec<Target<S>>>>,
    pub(crate) events: Option<EventSender<S>>,
    pub(crate) cancel: CancelToken,
}

impl<S: GraphState> fmt::Debug for NodeContext<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeContext")
            .field("node", &self.node)
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}

impl<S: GraphState> NodeContext<S> {
    /// Name of the running node.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Current superstep, from 1.
    #[must_use]
    pub const fn step(&self) -> usize {
        self.step
    }

    /// Pause the run and hand `value` to the caller (`LangGraph`'s
    /// `interrupt`).
    ///
    /// The first time, this returns [`GraphError::Interrupted`]; propagate it
    /// with `?`. The run stops with a checkpoint, and the caller resumes it
    /// with [`Command::resume`](crate::Command::resume). The node then runs
    /// again from the top, and this call returns the resume value instead.
    /// A node may interrupt several times; resume values are matched to the
    /// calls in order. Keep side effects after the last `interrupt`, or make
    /// them idempotent.
    ///
    /// # Errors
    ///
    /// [`GraphError::Interrupted`] to pause, or [`GraphError::Serde`] if the
    /// value or the resume value does not (de)serialize.
    pub fn interrupt<T: Serialize, R: DeserializeOwned>(&self, value: T) -> Result<R, GraphError> {
        let n = self.interrupts.fetch_add(1, Ordering::Relaxed);
        if let Some(answer) = self.resume.get(n) {
            return R::deserialize(answer)
                .map_err(|e| GraphError::Serde(format!("resume value for `{}`: {e}", self.node)));
        }
        Err(GraphError::Interrupted(Box::new(Interrupt {
            node: self.node.to_string(),
            value: serde_json::to_value(value)?,
            step: self.step,
            kind: InterruptKind::Node,
            task: self.task,
        })))
    }

    /// Go to `node` after this one instead of following its edges
    /// (`LangGraph`'s `Command(goto=..)`). Call it several times to fan out.
    pub fn goto(&self, node: impl Into<String>) {
        self.push(Target::Node(node.into()));
    }

    /// Like [`goto`](Self::goto) with a private state update for the target.
    pub fn send(&self, send: SendTo<S>) {
        self.push(Target::Send(send));
    }

    fn push(&self, target: Target<S>) {
        self.goto
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(target);
    }

    /// Whether someone is consuming [`Event::Token`]s.
    #[must_use]
    pub const fn is_streaming(&self) -> bool {
        self.events.is_some()
    }

    /// Stream a chunk of output to [`CompiledGraph::stream`](crate::CompiledGraph::stream)
    /// consumers. A no-op under `invoke`.
    pub async fn emit_token(&self, text: impl Into<String>) {
        if let Some(tx) = &self.events {
            let _ = tx
                .send(Ok(Event::Token {
                    step: self.step,
                    node: self.node.to_string(),
                    text: text.into(),
                }))
                .await;
        }
    }

    /// The run's cancel token, for long-running nodes that want to check it.
    #[must_use]
    pub const fn cancel_token(&self) -> &CancelToken {
        &self.cancel
    }
}
