use std::time::Duration;

use rune_chain_core::{ChainError, LlmError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Why a run paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InterruptKind {
    /// Before a node listed in `interrupt_before` ran.
    Before,
    /// After a node listed in `interrupt_after` ran.
    After,
    /// A node called [`NodeContext::interrupt`](crate::NodeContext::interrupt).
    Node,
}

/// A paused run. Resume it with [`Command::resume`](crate::Command::resume)
/// (or [`Command::default`](crate::Command) to just continue) on the same
/// thread.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Interrupt {
    /// The node the run stopped at.
    pub node: String,
    /// The value passed to `interrupt(..)`, or `null` for before/after
    /// interrupts.
    pub value: Value,
    /// Superstep the interrupt happened in.
    pub step: usize,
    /// What caused it.
    pub kind: InterruptKind,
    /// Index of the paused task within its superstep.
    #[serde(default)]
    pub task: usize,
}

/// Errors from building or running a graph.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GraphError {
    /// The graph failed validation in `compile`.
    #[error("invalid graph: {0}")]
    InvalidGraph(String),
    /// A router, `goto` or `Command` named a node the graph does not have.
    #[error("unknown node `{0}`")]
    UnknownNode(String),
    /// A router returned a node outside the targets declared for it.
    #[error("router of `{from}` returned `{to}`, which is not one of its declared targets")]
    UndeclaredRoute {
        /// Source node of the conditional edge.
        from: String,
        /// The target it returned.
        to: String,
    },
    /// The run used up its superstep budget before reaching `END`.
    #[error("recursion limit of {0} steps reached before END")]
    RecursionLimit(usize),
    /// A superstep would have run more tasks than allowed.
    #[error("a step would run {got} tasks, above the fan-out limit of {limit}")]
    FanOutLimit {
        /// Tasks requested.
        got: usize,
        /// The limit.
        limit: usize,
    },
    /// A node returned an error or panicked.
    #[error("node `{node}` failed: {source}")]
    NodeFailed {
        /// The failing node.
        node: String,
        /// What went wrong.
        #[source]
        source: Box<Self>,
    },
    /// A node ran longer than its timeout.
    #[error("node `{node}` timed out after {} ms", .after.as_millis())]
    Timeout {
        /// The slow node.
        node: String,
        /// The timeout that fired.
        after: Duration,
    },
    /// The run's cancel token fired.
    #[error("the run was cancelled")]
    Cancelled,
    /// Raised by [`NodeContext::interrupt`](crate::NodeContext::interrupt) to
    /// pause the run. Propagate it with `?`; the runner turns it into a paused
    /// [`Outcome`](crate::Outcome).
    #[error("interrupted in node `{}`", .0.node)]
    Interrupted(Box<Interrupt>),
    /// A chain failed.
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// A model call failed.
    #[error(transparent)]
    Llm(#[from] LlmError),
    /// A checkpoint is larger than the configured cap.
    #[error("checkpoint is {size} bytes, above the {limit}-byte limit")]
    CheckpointTooLarge {
        /// Serialized size.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// The checkpointer failed or holds no usable checkpoint.
    #[error("checkpoint: {0}")]
    Checkpoint(String),
    /// State, updates or resume values did not (de)serialize.
    #[error("serialization: {0}")]
    Serde(String),
    /// The call itself was invalid (for example, a `Command` without a
    /// thread id).
    #[error("{0}")]
    InvalidInput(String),
    /// Anything else, for errors raised by your own nodes.
    #[error("{0}")]
    Other(String),
}

impl GraphError {
    /// An [`Other`](Self::Other) error with `message`.
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }

    /// The interrupt, if this error is one.
    #[must_use]
    pub fn as_interrupt(&self) -> Option<&Interrupt> {
        match self {
            Self::Interrupted(i) => Some(i),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for GraphError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e.to_string())
    }
}
