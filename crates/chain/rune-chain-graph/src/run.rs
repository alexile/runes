//! The compiled graph and its superstep runner.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::future::BoxFuture;
use futures::{FutureExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::checkpoint::{Checkpoint, CheckpointSource, Checkpointer, check_thread_id, json_size};
use crate::error::{GraphError, Interrupt, InterruptKind};
use crate::graph::{CompileOptions, Edge, NodeEntry, StateGraph};
use crate::node::{CancelToken, END, EventSender, NodeContext, START, SendTo, Target};
use crate::state::GraphState;

/// Per-call settings: the thread to persist under, a checkpoint to replay
/// from, and cancellation.
///
/// ```rust
/// use rune_chain_graph::RunConfig;
///
/// let config = RunConfig::thread("user-42").recursion_limit(50);
/// assert_eq!(config.thread_id.as_deref(), Some("user-42"));
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RunConfig {
    /// Thread to read and write checkpoints under.
    pub thread_id: Option<String>,
    /// Start from this checkpoint instead of the thread's latest (time
    /// travel). Later checkpoints fork from it.
    pub checkpoint_id: Option<String>,
    /// Overrides the compiled recursion limit for this call.
    pub recursion_limit: Option<usize>,
    /// Cancels the run when fired.
    pub cancel: Option<CancelToken>,
}

impl RunConfig {
    /// A config for `thread_id`.
    pub fn thread(thread_id: impl Into<String>) -> Self {
        Self {
            thread_id: Some(thread_id.into()),
            ..Self::default()
        }
    }

    /// Replay from `checkpoint_id`.
    #[must_use]
    pub fn checkpoint(mut self, checkpoint_id: impl Into<String>) -> Self {
        self.checkpoint_id = Some(checkpoint_id.into());
        self
    }

    /// Override the recursion limit.
    #[must_use]
    pub const fn recursion_limit(mut self, steps: usize) -> Self {
        self.recursion_limit = Some(steps);
        self
    }

    /// Cancel the run with `token`.
    #[must_use]
    pub fn cancel_token(mut self, token: CancelToken) -> Self {
        self.cancel = Some(token);
        self
    }
}

/// Continue a checkpointed thread: answer an interrupt, jump to a node,
/// and/or apply an update first (`LangGraph`'s `Command`).
///
/// `Command::default()` just continues from the latest checkpoint (`LangGraph`'s
/// `invoke(None)`).
pub struct Command<S: GraphState> {
    resume: Option<Value>,
    goto: Vec<Target<S>>,
    update: Option<S::Update>,
}

impl<S: GraphState> Default for Command<S> {
    fn default() -> Self {
        Self {
            resume: None,
            goto: Vec::new(),
            update: None,
        }
    }
}

impl<S: GraphState> fmt::Debug for Command<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Command")
            .field("resume", &self.resume)
            .field("goto", &self.goto)
            .field("update", &self.update.is_some())
            .finish()
    }
}

impl<S: GraphState> Command<S> {
    /// Answer the pending `interrupt(..)` with `value`.
    pub fn resume(value: impl Into<Value>) -> Self {
        Self::default().with_resume(value)
    }

    /// Run `node` next instead of the pending tasks.
    pub fn goto(node: impl Into<String>) -> Self {
        Self::default().with_goto(node)
    }

    /// Merge `update` into the state before continuing. On a finished
    /// thread this starts a new turn from `START`.
    pub fn update(update: S::Update) -> Self {
        Self::default().with_update(update)
    }

    /// Set the resume value.
    #[must_use]
    pub fn with_resume(mut self, value: impl Into<Value>) -> Self {
        self.resume = Some(value.into());
        self
    }

    /// Add a node to jump to.
    #[must_use]
    pub fn with_goto(mut self, node: impl Into<String>) -> Self {
        self.goto.push(Target::Node(node.into()));
        self
    }

    /// Add a [`SendTo`] to jump to.
    #[must_use]
    pub fn with_send(mut self, send: SendTo<S>) -> Self {
        self.goto.push(Target::Send(send));
        self
    }

    /// Set the update.
    #[must_use]
    pub fn with_update(mut self, update: S::Update) -> Self {
        self.update = Some(update);
        self
    }
}

/// What to run: a fresh state from `START`, or a [`Command`] on a
/// checkpointed thread. Both convert with `.into()`.
#[derive(Debug)]
pub enum Input<S: GraphState> {
    /// Start a new run from `START` with this state.
    State(S),
    /// Continue the thread's latest (or the configured) checkpoint.
    Command(Command<S>),
}

impl<S: GraphState> From<S> for Input<S> {
    fn from(state: S) -> Self {
        Self::State(state)
    }
}

impl<S: GraphState> From<Command<S>> for Input<S> {
    fn from(command: Command<S>) -> Self {
        Self::Command(command)
    }
}

/// How a run ended: finished, or paused at an interrupt.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Outcome<S> {
    /// The state at the end (or at the pause).
    pub state: S,
    /// Set when the run paused.
    pub interrupt: Option<Interrupt>,
    /// Supersteps run by this call.
    pub steps: usize,
    /// The last checkpoint written, when a checkpointer and thread are set.
    pub checkpoint_id: Option<String>,
}

impl<S> Outcome<S> {
    /// Whether the run paused instead of finishing.
    #[must_use]
    pub const fn is_interrupted(&self) -> bool {
        self.interrupt.is_some()
    }

    /// The final state.
    #[must_use]
    pub fn into_state(self) -> S {
        self.state
    }
}

/// An item of [`CompiledGraph::stream`].
#[non_exhaustive]
pub enum Event<S: GraphState> {
    /// A node finished and its update was merged. Updates of one superstep
    /// arrive in task order.
    Update {
        /// Superstep.
        step: usize,
        /// The node.
        node: String,
        /// Its update.
        update: S::Update,
    },
    /// A chunk of streamed model output.
    Token {
        /// Superstep.
        step: usize,
        /// The node producing it.
        node: String,
        /// The chunk.
        text: String,
    },
    /// The run ended; always the last event of a successful stream.
    Done(Outcome<S>),
}

impl<S> fmt::Debug for Event<S>
where
    S: GraphState + fmt::Debug,
    S::Update: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Update { step, node, update } => f
                .debug_struct("Update")
                .field("step", step)
                .field("node", node)
                .field("update", update)
                .finish(),
            Self::Token { step, node, text } => f
                .debug_struct("Token")
                .field("step", step)
                .field("node", node)
                .field("text", text)
                .finish(),
            Self::Done(outcome) => f.debug_tuple("Done").field(outcome).finish(),
        }
    }
}

/// A thread's state at one checkpoint (`LangGraph`'s `StateSnapshot`).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StateSnapshot<S> {
    /// The state.
    pub state: S,
    /// Nodes that run next; empty when the run finished.
    pub next: Vec<String>,
    /// The checkpoint.
    pub checkpoint_id: String,
    /// The checkpoint it continued from.
    pub parent_id: Option<String>,
    /// Supersteps completed on the thread.
    pub step: usize,
    /// Set when the thread is paused here.
    pub interrupt: Option<Interrupt>,
    /// What wrote the checkpoint.
    pub source: CheckpointSource,
    /// Unix time in milliseconds.
    pub created_at_ms: u64,
}

/// A task queued for a superstep.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
struct Task<S: GraphState> {
    node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    send: Option<S::Update>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    resume: Vec<Value>,
}

impl<S: GraphState> Task<S> {
    const fn plain(node: String) -> Self {
        Self {
            node,
            send: None,
            resume: Vec::new(),
        }
    }
}

struct Topology<S: GraphState> {
    nodes: Vec<NodeEntry<S>>,
    index: HashMap<String, usize>,
    edges: HashMap<String, Vec<Edge<S>>>,
    interrupt_before: HashSet<String>,
    interrupt_after: HashSet<String>,
    mermaid: String,
}

/// A validated, runnable graph. Cheap to clone; clones share nodes and
/// options.
pub struct CompiledGraph<S: GraphState> {
    topo: Arc<Topology<S>>,
    options: Arc<CompileOptions>,
}

impl<S: GraphState> Clone for CompiledGraph<S> {
    fn clone(&self) -> Self {
        Self {
            topo: Arc::clone(&self.topo),
            options: Arc::clone(&self.options),
        }
    }
}

impl<S: GraphState> fmt::Debug for CompiledGraph<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledGraph")
            .field(
                "nodes",
                &self.topo.nodes.iter().map(|n| &*n.name).collect::<Vec<_>>(),
            )
            .field("options", &self.options)
            .finish()
    }
}

/// Where the run writes checkpoints.
type StoreRef = (Arc<dyn Checkpointer>, String);

struct Saver {
    store: Arc<dyn Checkpointer>,
    thread: String,
    seq: u64,
    parent: Option<String>,
}

/// The result of one task.
enum TaskResult<S: GraphState> {
    Done(S::Update, Vec<Target<S>>),
    Failed(GraphError),
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl<S: GraphState> CompiledGraph<S> {
    pub(crate) fn new(graph: StateGraph<S>, options: CompileOptions) -> Self {
        let mermaid = graph.draw_mermaid();
        let StateGraph {
            nodes,
            index,
            edges,
            ..
        } = graph;
        let topo = Topology {
            nodes,
            index,
            edges,
            interrupt_before: options.interrupt_before.iter().cloned().collect(),
            interrupt_after: options.interrupt_after.iter().cloned().collect(),
            mermaid,
        };
        Self {
            topo: Arc::new(topo),
            options: Arc::new(options),
        }
    }

    /// The graph as a Mermaid flowchart (see
    /// [`StateGraph::draw_mermaid`]).
    #[must_use]
    pub fn draw_mermaid(&self) -> String {
        self.topo.mermaid.clone()
    }

    /// The options it was compiled with.
    #[must_use]
    pub fn options(&self) -> &CompileOptions {
        &self.options
    }

    /// Node names in the order they were added.
    #[must_use]
    pub fn node_names(&self) -> Vec<&str> {
        self.topo.nodes.iter().map(|n| &*n.name).collect()
    }

    /// Run until `END` or an interrupt.
    ///
    /// # Errors
    ///
    /// Node failures and timeouts, router mistakes ([`GraphError::UnknownNode`],
    /// [`GraphError::UndeclaredRoute`]), the recursion and fan-out limits,
    /// cancellation, and checkpoint problems. A `Command` needs a
    /// checkpointer and a thread id.
    pub async fn invoke(
        &self,
        input: impl Into<Input<S>>,
        config: &RunConfig,
    ) -> Result<Outcome<S>, GraphError> {
        self.run(input.into(), config, None).await
    }

    /// Like [`invoke`](Self::invoke), but stream [`Event`]s as the run goes:
    /// one `Update` per finished node, `Token`s from streaming nodes, then
    /// `Done`. An error ends the stream. Dropping the stream cancels the run.
    ///
    /// The run is spawned on the current Tokio runtime.
    pub fn stream(&self, input: impl Into<Input<S>>, config: &RunConfig) -> GraphStream<S> {
        let (tx, rx) = mpsc::channel(64);
        let graph = self.clone();
        let input = input.into();
        let config = config.clone();
        let handle = tokio::spawn(async move {
            let result = graph.run(input, &config, Some(tx.clone())).await;
            let _ = tx.send(result.map(Event::Done)).await;
        });
        GraphStream { rx, handle }
    }

    fn checkpoint_target(&self, config: &RunConfig) -> Result<Option<StoreRef>, GraphError> {
        match (&self.options.checkpointer, &config.thread_id) {
            (Some(store), Some(thread)) => {
                check_thread_id(thread)?;
                Ok(Some((Arc::clone(store), thread.clone())))
            }
            _ => Ok(None),
        }
    }

    async fn load(
        &self,
        config: &RunConfig,
    ) -> Result<(Arc<dyn Checkpointer>, String, Checkpoint), GraphError> {
        let Some((store, thread)) = self.checkpoint_target(config)? else {
            return Err(GraphError::InvalidInput(
                "this needs a checkpointer and a thread id".into(),
            ));
        };
        let cp = store
            .get(&thread, config.checkpoint_id.as_deref())
            .await?
            .ok_or_else(|| {
                GraphError::Checkpoint(config.checkpoint_id.as_ref().map_or_else(
                    || format!("thread `{thread}` has no checkpoints"),
                    |id| format!("no checkpoint `{id}` in thread `{thread}`"),
                ))
            })?;
        Ok((store, thread, cp))
    }

    fn decode(cp: &Checkpoint) -> Result<(S, Vec<Task<S>>), GraphError> {
        let state = S::deserialize(&cp.state)?;
        let tasks = Vec::<Task<S>>::deserialize(&cp.tasks)?;
        Ok((state, tasks))
    }

    async fn next_seq(store: &dyn Checkpointer, thread: &str) -> Result<u64, GraphError> {
        Ok(store
            .get(thread, None)
            .await?
            .and_then(|c| c.seq())
            .map_or(1, |s| s.saturating_add(1)))
    }

    /// The thread's state at its latest checkpoint, or at
    /// `config.checkpoint_id`. `None` when the thread has no checkpoints.
    ///
    /// # Errors
    ///
    /// No checkpointer or thread id, or a checkpoint that does not decode.
    pub async fn get_state(
        &self,
        config: &RunConfig,
    ) -> Result<Option<StateSnapshot<S>>, GraphError> {
        let Some((store, thread)) = self.checkpoint_target(config)? else {
            return Err(GraphError::InvalidInput(
                "get_state needs a checkpointer and a thread id".into(),
            ));
        };
        match store.get(&thread, config.checkpoint_id.as_deref()).await? {
            Some(cp) => Ok(Some(Self::snapshot(cp)?)),
            None => Ok(None),
        }
    }

    /// Up to `limit` snapshots of the thread, newest first.
    ///
    /// # Errors
    ///
    /// As for [`get_state`](Self::get_state).
    pub async fn get_state_history(
        &self,
        config: &RunConfig,
        limit: usize,
    ) -> Result<Vec<StateSnapshot<S>>, GraphError> {
        let Some((store, thread)) = self.checkpoint_target(config)? else {
            return Err(GraphError::InvalidInput(
                "get_state_history needs a checkpointer and a thread id".into(),
            ));
        };
        store
            .list(&thread, limit)
            .await?
            .into_iter()
            .map(Self::snapshot)
            .collect()
    }

    fn snapshot(cp: Checkpoint) -> Result<StateSnapshot<S>, GraphError> {
        Ok(StateSnapshot {
            state: S::deserialize(&cp.state)?,
            next: cp.next,
            checkpoint_id: cp.id,
            parent_id: cp.parent_id,
            step: cp.step,
            interrupt: cp.interrupt,
            source: cp.source,
            created_at_ms: cp.created_at_ms,
        })
    }

    /// Merge `update` into the thread's latest (or configured) checkpoint and
    /// save the result as a new checkpoint, returning its id.
    ///
    /// With `as_node`, the update counts as that node's output: the pending
    /// tasks become the node's successors. Otherwise the pending tasks and
    /// any interrupt are kept, so a paused run continues where it was.
    ///
    /// # Errors
    ///
    /// No checkpoint, an unknown `as_node`, a router error, or a checkpoint
    /// above the size cap.
    pub async fn update_state(
        &self,
        config: &RunConfig,
        update: S::Update,
        as_node: Option<&str>,
    ) -> Result<String, GraphError> {
        let (store, thread, cp) = self.load(config).await?;
        let (mut state, mut tasks) = Self::decode(&cp)?;
        state.merge(update);
        let interrupt = if let Some(node) = as_node {
            if !self.topo.index.contains_key(node) {
                return Err(GraphError::UnknownNode(node.to_owned()));
            }
            tasks = self.successors(&state, std::iter::once((node, Vec::new())))?;
            None
        } else {
            cp.interrupt.clone()
        };
        let mut saver = Saver {
            seq: Self::next_seq(&*store, &thread).await?,
            store,
            thread,
            parent: Some(cp.id),
        };
        self.save(
            &mut saver,
            &state,
            &tasks,
            cp.step,
            interrupt,
            CheckpointSource::Update,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn save(
        &self,
        saver: &mut Saver,
        state: &S,
        tasks: &[Task<S>],
        step: usize,
        interrupt: Option<Interrupt>,
        source: CheckpointSource,
    ) -> Result<String, GraphError> {
        let cp = Checkpoint {
            thread_id: saver.thread.clone(),
            id: Checkpoint::format_id(saver.seq),
            parent_id: saver.parent.clone(),
            step,
            state: serde_json::to_value(state)?,
            next: tasks.iter().map(|t| t.node.clone()).collect(),
            tasks: serde_json::to_value(tasks)?,
            interrupt,
            source,
            created_at_ms: now_ms(),
        };
        let size = json_size(&cp)?;
        if size > self.options.max_checkpoint_bytes {
            return Err(GraphError::CheckpointTooLarge {
                size,
                limit: self.options.max_checkpoint_bytes,
            });
        }
        saver.store.put(&cp).await?;
        saver.seq = saver.seq.saturating_add(1);
        saver.parent = Some(cp.id.clone());
        Ok(cp.id)
    }

    /// Turn a list of targets into tasks, checking names.
    fn push_target(
        &self,
        tasks: &mut Vec<Task<S>>,
        seen: &mut HashSet<String>,
        target: Target<S>,
    ) -> Result<(), GraphError> {
        let node = target.node();
        if node == END {
            return Ok(());
        }
        if !self.topo.index.contains_key(node) {
            return Err(GraphError::UnknownNode(node.chars().take(128).collect()));
        }
        match target {
            Target::Node(n) => {
                if seen.insert(n.clone()) {
                    tasks.push(Task::plain(n));
                }
            }
            Target::Send(SendTo { node, update }) => tasks.push(Task {
                node,
                send: Some(update),
                resume: Vec::new(),
            }),
        }
        if tasks.len() > self.options.max_fanout {
            return Err(GraphError::FanOutLimit {
                got: tasks.len(),
                limit: self.options.max_fanout,
            });
        }
        Ok(())
    }

    /// The tasks that follow `finished` nodes, in order: each node's `goto`
    /// targets if it set any, else its edges evaluated on `state`.
    fn successors<'n>(
        &self,
        state: &S,
        finished: impl Iterator<Item = (&'n str, Vec<Target<S>>)>,
    ) -> Result<Vec<Task<S>>, GraphError> {
        let mut tasks = Vec::new();
        let mut seen = HashSet::new();
        for (node, goto) in finished {
            if !goto.is_empty() {
                for t in goto {
                    self.push_target(&mut tasks, &mut seen, t)?;
                }
                continue;
            }
            for edge in self.topo.edges.get(node).into_iter().flatten() {
                match edge {
                    Edge::Static(to) => {
                        self.push_target(&mut tasks, &mut seen, Target::Node(to.clone()))?;
                    }
                    Edge::Conditional { router, targets } => {
                        let route = std::panic::catch_unwind(AssertUnwindSafe(|| router(state)))
                            .map_err(|_| GraphError::NodeFailed {
                                node: node.to_owned(),
                                source: Box::new(GraphError::other("router panicked")),
                            })?;
                        if route.0.len() > self.options.max_fanout {
                            return Err(GraphError::FanOutLimit {
                                got: route.0.len(),
                                limit: self.options.max_fanout,
                            });
                        }
                        for t in route.0 {
                            if !targets.is_empty() && !targets.iter().any(|d| d == t.node()) {
                                return Err(GraphError::UndeclaredRoute {
                                    from: node.to_owned(),
                                    to: t.node().chars().take(128).collect(),
                                });
                            }
                            self.push_target(&mut tasks, &mut seen, t)?;
                        }
                    }
                }
            }
        }
        Ok(tasks)
    }

    #[allow(clippy::too_many_lines)]
    async fn run(
        &self,
        input: Input<S>,
        config: &RunConfig,
        events: Option<EventSender<S>>,
    ) -> Result<Outcome<S>, GraphError> {
        let limit = config
            .recursion_limit
            .unwrap_or(self.options.recursion_limit);
        let cancel = config.cancel.clone().unwrap_or_default();
        let target = self.checkpoint_target(config)?;

        let (mut state, mut tasks, mut step, mut skip_before, mut saver) = match input {
            Input::State(state) => {
                let tasks = self.successors(&state, std::iter::once((START, Vec::new())))?;
                let saver = match target {
                    Some((store, thread)) => {
                        let latest = store.get(&thread, None).await?;
                        let seq = latest
                            .as_ref()
                            .and_then(Checkpoint::seq)
                            .map_or(1, |s| s.saturating_add(1));
                        Some(Saver {
                            store,
                            thread,
                            seq,
                            parent: latest.map(|c| c.id),
                        })
                    }
                    None => None,
                };
                (state, tasks, 0, false, saver)
            }
            Input::Command(cmd) => {
                let (store, thread, cp) = self.load(config).await?;
                let (mut state, mut tasks) = Self::decode(&cp)?;
                let had_update = cmd.update.is_some();
                if let Some(update) = cmd.update {
                    state.merge(update);
                }
                let mut skip_before = false;
                if cmd.goto.is_empty() {
                    match &cp.interrupt {
                        Some(i) if i.kind == InterruptKind::Before => skip_before = true,
                        Some(i) if i.kind == InterruptKind::Node => {
                            skip_before = true;
                            if let Some(value) = cmd.resume {
                                match tasks.get_mut(i.task) {
                                    Some(t) if t.node == i.node => t.resume.push(value),
                                    _ => {
                                        return Err(GraphError::Checkpoint(
                                            "the interrupted task is missing from the checkpoint"
                                                .into(),
                                        ));
                                    }
                                }
                            }
                        }
                        Some(_) => {}
                        None => {
                            if cmd.resume.is_some() {
                                return Err(GraphError::InvalidInput(
                                    "nothing to resume: the thread is not interrupted".into(),
                                ));
                            }
                        }
                    }
                    if tasks.is_empty() && had_update {
                        tasks = self.successors(&state, std::iter::once((START, Vec::new())))?;
                    }
                } else {
                    let mut fresh = Vec::new();
                    let mut seen = HashSet::new();
                    for t in cmd.goto {
                        self.push_target(&mut fresh, &mut seen, t)?;
                    }
                    tasks = fresh;
                }
                let seq = Self::next_seq(&*store, &thread).await?;
                let saver = Saver {
                    store,
                    thread,
                    seq,
                    parent: Some(cp.id.clone()),
                };
                (state, tasks, cp.step, skip_before, Some(saver))
            }
        };

        let mut last_id = match saver.as_mut() {
            Some(saver) => Some(
                self.save(saver, &state, &tasks, step, None, CheckpointSource::Input)
                    .await?,
            ),
            None => None,
        };

        let mut steps_run = 0;
        loop {
            if tasks.is_empty() {
                return Ok(Outcome {
                    state,
                    interrupt: None,
                    steps: steps_run,
                    checkpoint_id: last_id,
                });
            }
            if cancel.is_cancelled() {
                return Err(GraphError::Cancelled);
            }
            if !skip_before
                && let Some(t) = tasks
                    .iter()
                    .position(|t| self.topo.interrupt_before.contains(&t.node))
            {
                let interrupt = Interrupt {
                    node: tasks[t].node.clone(),
                    value: Value::Null,
                    step,
                    kind: InterruptKind::Before,
                    task: t,
                };
                return self
                    .pause(saver.as_mut(), state, &tasks, step, interrupt, steps_run)
                    .await;
            }
            skip_before = false;
            if steps_run >= limit {
                return Err(GraphError::RecursionLimit(limit));
            }
            steps_run += 1;
            step += 1;

            let results = self
                .run_step(&state, &tasks, step, events.as_ref(), &cancel)
                .await?;

            // A real failure wins over a pause; the first pause in task order
            // is the one reported.
            let mut paused = None;
            for r in &results {
                match r {
                    TaskResult::Failed(GraphError::Interrupted(i)) => {
                        if paused.is_none() {
                            paused = Some((**i).clone());
                        }
                    }
                    TaskResult::Failed(_) | TaskResult::Done(..) => {}
                }
            }
            let mut finished = Vec::with_capacity(results.len());
            for (task, result) in tasks.iter().zip(results) {
                match result {
                    TaskResult::Done(update, goto) => finished.push((task, update, goto)),
                    TaskResult::Failed(GraphError::Interrupted(_)) => {}
                    TaskResult::Failed(e) => {
                        return Err(match e {
                            GraphError::Cancelled | GraphError::Timeout { .. } => e,
                            other => GraphError::NodeFailed {
                                node: task.node.clone(),
                                source: Box::new(other),
                            },
                        });
                    }
                }
            }
            if let Some(interrupt) = paused {
                // Nothing of this step is applied: every task runs again on
                // resume, the paused one with its resume value.
                return self
                    .pause(
                        saver.as_mut(),
                        state,
                        &tasks,
                        step - 1,
                        interrupt,
                        steps_run,
                    )
                    .await;
            }

            let mut gotos = Vec::with_capacity(finished.len());
            for (task, update, goto) in finished {
                if let Some(tx) = &events {
                    let _ = tx
                        .send(Ok(Event::Update {
                            step,
                            node: task.node.clone(),
                            update: update.clone(),
                        }))
                        .await;
                }
                state.merge(update);
                gotos.push((task.node.as_str(), goto));
            }
            let next = self.successors(&state, gotos.into_iter())?;

            let after = tasks
                .iter()
                .position(|t| self.topo.interrupt_after.contains(&t.node));
            let interrupt = after.map(|t| Interrupt {
                node: tasks[t].node.clone(),
                value: Value::Null,
                step,
                kind: InterruptKind::After,
                task: t,
            });
            tasks = next;
            if let Some(saver) = saver.as_mut() {
                last_id = Some(
                    self.save(
                        saver,
                        &state,
                        &tasks,
                        step,
                        interrupt.clone(),
                        CheckpointSource::Loop,
                    )
                    .await?,
                );
            }
            if let Some(interrupt) = interrupt {
                if saver.is_none() {
                    return Err(GraphError::InvalidInput(
                        "interrupts need a checkpointer and a thread id".into(),
                    ));
                }
                return Ok(Outcome {
                    state,
                    interrupt: Some(interrupt),
                    steps: steps_run,
                    checkpoint_id: last_id,
                });
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn pause(
        &self,
        saver: Option<&mut Saver>,
        state: S,
        tasks: &[Task<S>],
        step: usize,
        interrupt: Interrupt,
        steps_run: usize,
    ) -> Result<Outcome<S>, GraphError> {
        let Some(saver) = saver else {
            return Err(GraphError::InvalidInput(format!(
                "node `{}` interrupted, but pausing needs a checkpointer and a thread id",
                interrupt.node
            )));
        };
        let id = self
            .save(
                saver,
                &state,
                tasks,
                step,
                Some(interrupt.clone()),
                CheckpointSource::Loop,
            )
            .await?;
        Ok(Outcome {
            state,
            interrupt: Some(interrupt),
            steps: steps_run,
            checkpoint_id: Some(id),
        })
    }

    /// Run every task of a superstep, at most `max_concurrency` at once.
    /// Results come back in task order whatever order the tasks finish in.
    async fn run_step(
        &self,
        state: &S,
        tasks: &[Task<S>],
        step: usize,
        events: Option<&EventSender<S>>,
        cancel: &CancelToken,
    ) -> Result<Vec<TaskResult<S>>, GraphError> {
        let shared = Arc::new(state.clone());
        // Boxed up front: a lazily mapped stream of borrowing futures trips
        // rustc's higher-ranked `Send` check when the run is spawned.
        let mut pending: Vec<BoxFuture<'_, TaskResult<S>>> = Vec::with_capacity(tasks.len());
        for (i, task) in tasks.iter().enumerate() {
            let input = task.send.clone().map_or_else(
                || Arc::clone(&shared),
                |update| {
                    let mut own = state.clone();
                    own.merge(update);
                    Arc::new(own)
                },
            );
            pending.push(self.run_task(input, task, i, step, events, cancel).boxed());
        }
        let all = futures::stream::iter(pending)
            .buffered(self.options.max_concurrency)
            .collect::<Vec<_>>();
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(GraphError::Cancelled),
            results = all => Ok(results),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_task(
        &self,
        state: Arc<S>,
        task: &Task<S>,
        index: usize,
        step: usize,
        events: Option<&EventSender<S>>,
        cancel: &CancelToken,
    ) -> TaskResult<S> {
        let Some(&at) = self.topo.index.get(&task.node) else {
            return TaskResult::Failed(GraphError::UnknownNode(task.node.clone()));
        };
        let entry = &self.topo.nodes[at];
        let goto = Arc::new(Mutex::new(Vec::new()));
        let ctx = NodeContext {
            node: Arc::clone(&entry.name),
            step,
            task: index,
            resume: task.resume.clone().into(),
            interrupts: AtomicUsize::new(0),
            goto: Arc::clone(&goto),
            events: events.cloned(),
            cancel: cancel.clone(),
        };
        let fut = AssertUnwindSafe(entry.node.run(state, ctx)).catch_unwind();
        let timeout: Option<Duration> = self
            .options
            .node_timeouts
            .get(&task.node)
            .copied()
            .or(self.options.node_timeout);
        let outcome = match timeout {
            Some(t) => match tokio::time::timeout(t, fut).await {
                Ok(r) => r,
                Err(_) => {
                    return TaskResult::Failed(GraphError::Timeout {
                        node: task.node.clone(),
                        after: t,
                    });
                }
            },
            None => fut.await,
        };
        match outcome {
            Ok(Ok(update)) => {
                let targets =
                    std::mem::take(&mut *goto.lock().unwrap_or_else(PoisonError::into_inner));
                TaskResult::Done(update, targets)
            }
            Ok(Err(e)) => TaskResult::Failed(e),
            Err(_) => TaskResult::Failed(GraphError::other("node panicked")),
        }
    }
}

/// The stream returned by [`CompiledGraph::stream`]. Dropping it aborts the
/// run.
pub struct GraphStream<S: GraphState> {
    rx: mpsc::Receiver<Result<Event<S>, GraphError>>,
    handle: JoinHandle<()>,
}

impl<S: GraphState> fmt::Debug for GraphStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraphStream").finish_non_exhaustive()
    }
}

impl<S: GraphState> Stream for GraphStream<S> {
    type Item = Result<Event<S>, GraphError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl<S: GraphState> Drop for GraphStream<S> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
