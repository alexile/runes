//! Stateful graphs for LLM workflows and agents: typed state with
//! reducers, parallel supersteps, checkpoints, human-in-the-loop and a
//! prebuilt tool-calling agent. A Rust take on `LangGraph`.
//!
//! # Model
//!
//! - **State** is your own type implementing [`GraphState`]. Nodes return a
//!   partial [`GraphState::Update`]; per-field [`Reducer`]s ([`Replace`],
//!   [`Append`], [`AddMessages`], [`Sum`], [`MergeMap`]) fold it in. The
//!   [`state!`] macro writes the update type and the merge for you.
//! - **Nodes** are async closures `|state, ctx| async { Ok(update) }`, or a
//!   [`Node`] such as [`LlmNode`], [`ToolNode`] or [`ChainNode`].
//! - **Edges** are fixed ([`StateGraph::add_edge`]) or picked by a router
//!   ([`StateGraph::add_conditional_edges`]), from [`START`] to [`END`].
//!   Several targets run in parallel; [`SendTo`] maps a node over dynamic
//!   items; [`NodeContext::goto`] jumps from inside a node.
//! - **Execution** is in supersteps: all tasks of a step run concurrently
//!   on the same state snapshot, then their updates merge in task order, so
//!   results never depend on timing.
//!
//! # Quick start
//!
//! ```rust
//! use rune_chain_graph::{Append, GraphError, RunConfig, StateGraph, Sum, END, START, state};
//! use serde::{Deserialize, Serialize};
//!
//! state! {
//!     #[derive(Debug, Clone, Default, Serialize, Deserialize)]
//!     struct Counter => CounterUpdate {
//!         count: i64 = Sum,
//!         log: Vec<String> = Append,
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let mut graph = StateGraph::<Counter>::new();
//! graph
//!     .add_node("inc", |_s, ctx| async move {
//!         Ok(CounterUpdate::default().count(1).log(vec![format!("step {}", ctx.step())]))
//!     })
//!     .add_edge(START, "inc")
//!     .add_conditional_edges("inc", |s: &Counter| if s.count < 3 { "inc" } else { END }, ["inc", END]);
//! let app = graph.compile()?;
//!
//! let out = app.invoke(Counter::default(), &RunConfig::default()).await?;
//! assert_eq!(out.state.count, 3);
//! assert_eq!(out.state.log, ["step 1", "step 2", "step 3"]);
//! # Ok::<(), GraphError>(())
//! # }).unwrap();
//! ```
//!
//! # Checkpoints and human-in-the-loop
//!
//! Compile with a [`Checkpointer`] ([`InMemoryCheckpointer`], or
//! `SqliteCheckpointer` with feature `sqlite`) and pass a thread id in
//! [`RunConfig`]. Every superstep is saved, so a thread can be resumed,
//! inspected ([`CompiledGraph::get_state`], [`CompiledGraph::get_state_history`]),
//! edited ([`CompiledGraph::update_state`]) or replayed from any past
//! checkpoint ([`RunConfig::checkpoint`]).
//!
//! Runs pause before or after chosen nodes
//! ([`CompileOptions::interrupt_before`] / [`CompileOptions::interrupt_after`]) or
//! when a node calls [`NodeContext::interrupt`]. Continue with a
//! [`Command`]: `Command::resume(value)`, `Command::goto(node)`,
//! `Command::update(update)` or `Command::default()`.
//!
//! # Limits
//!
//! Every run is bounded: a recursion limit of 25 supersteps (as in
//! `LangGraph`), at most 256 tasks per superstep, 16 running at once,
//! optional per-node timeouts, a [`CancelToken`], and a 16 MiB cap per
//! checkpoint. A router that names an unknown or undeclared node fails the
//! run with an error, and a panicking node or router becomes an error too.
//! Tool calls made through [`ToolNode`] get `rune-chain-agent`'s validation,
//! limits, approval and output fencing.

mod checkpoint;
mod error;
mod graph;
mod node;
mod nodes;
mod prebuilt;
mod run;
#[cfg(feature = "sqlite")]
mod sqlite;
mod state;

pub use checkpoint::{
    Checkpoint, CheckpointSource, Checkpointer, DEFAULT_MAX_CHECKPOINT_BYTES, InMemoryCheckpointer,
    MAX_THREAD_ID_LEN,
};
pub use error::{GraphError, Interrupt, InterruptKind};
pub use graph::{
    CompileOptions, DEFAULT_MAX_CONCURRENCY, DEFAULT_MAX_FANOUT, DEFAULT_RECURSION_LIMIT,
    MAX_NODE_NAME_LEN, StateGraph,
};
pub use node::{CancelToken, END, Node, NodeContext, Route, START, SendTo, Target};
pub use nodes::{ChainNode, LlmNode, ToolNode};
pub use prebuilt::{create_react_agent, react_agent_graph, tools_condition};
pub use run::{
    Command, CompiledGraph, Event, GraphStream, Input, Outcome, RunConfig, StateSnapshot,
};
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteCheckpointer;
pub use state::{
    AddMessages, Append, GraphState, HasMessages, MergeMap, MessageId, MessagesState,
    MessagesUpdate, Reducer, Replace, Sum,
};

/// Re-exported so you can build tool executors without a direct dependency.
pub use rune_chain_agent::{AgentLimits, Approval, ApprovalRequest, Approver, ToolExecutor};
