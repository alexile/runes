//! Observability: events emitted while an agent runs.

use std::fmt;

use crate::{FunctionAgentResult, ToolInvocation};

/// Why an agent run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StopReason {
    /// The model produced a final answer.
    FinalAnswer,
    /// [`AgentLimits::max_iterations`](crate::AgentLimits::max_iterations) was reached.
    MaxIterations,
    /// [`AgentLimits::max_wall_time`](crate::AgentLimits::max_wall_time) elapsed.
    WallTime,
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FinalAnswer => "final answer",
            Self::MaxIterations => "iteration limit reached",
            Self::WallTime => "wall-time limit reached",
        })
    }
}

/// How a single tool call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToolStatus {
    /// The tool ran and returned output.
    Ok,
    /// The call was rejected (unknown tool, invalid arguments) or the tool
    /// failed, timed out or panicked.
    Error,
    /// The approver denied the call.
    Denied,
    /// The call was not run because the per-turn tool-call limit was hit.
    Skipped,
}

impl ToolStatus {
    /// Lower-case label used in fences and messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Denied => "denied",
            Self::Skipped => "skipped",
        }
    }
}

impl fmt::Display for ToolStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One step of an agent run, delivered to an [`AgentObserver`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentEvent {
    /// An LLM call is about to be made. `iteration` counts completed tool rounds.
    StepStarted {
        /// Tool rounds completed so far.
        iteration: usize,
    },
    /// The model asked for a tool call (before validation or approval).
    ToolCalled {
        /// Tool round, from 1.
        iteration: usize,
        /// Tool-call id.
        call_id: String,
        /// Requested tool name, sanitised.
        name: String,
        /// Raw arguments as produced by the model.
        arguments: String,
    },
    /// A tool call finished (in any [`ToolStatus`]).
    ToolResult {
        /// Tool round, from 1.
        iteration: usize,
        /// Tool-call id.
        call_id: String,
        /// Tool name, sanitised.
        name: String,
        /// Outcome.
        status: ToolStatus,
        /// Output or error text as fed back to the model (before fencing).
        output: String,
        /// Whether the output was cut to the size limit.
        truncated: bool,
    },
    /// The model produced its final answer.
    FinalAnswer {
        /// The answer.
        output: String,
    },
    /// The run stopped without a final answer.
    Stopped {
        /// Why.
        reason: StopReason,
    },
}

/// One item of [`FunctionCallingAgent::run_stream`](crate::FunctionCallingAgent::run_stream).
///
/// Text and reasoning arrive as the model streams them, in every round;
/// text from a round that ends in tool calls is the model's preamble to
/// those calls, not the answer. The last item of a run is
/// [`Done`](Self::Done).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AgentStreamEvent {
    /// A fragment of the model's text.
    TextDelta(String),
    /// A fragment of the model's reasoning.
    ReasoningDelta(String),
    /// The model started a tool call (before validation or approval).
    ToolCallStarted {
        /// Tool round, from 1.
        iteration: usize,
        /// Tool-call id.
        call_id: String,
        /// Requested tool name, sanitised.
        name: String,
    },
    /// A tool call finished (in any [`ToolStatus`]).
    ToolResult {
        /// Tool round, from 1.
        iteration: usize,
        /// The call, its status and the output the model sees.
        invocation: ToolInvocation,
    },
    /// The run ended: the final answer, or the reason it stopped early.
    Done(FunctionAgentResult),
}

/// Receives [`AgentEvent`]s. Implemented for any `Fn(&AgentEvent) + Send + Sync`.
///
/// Called inline from the agent loop (possibly from concurrently running tool
/// futures), so keep it cheap: push to a channel or a log.
pub trait AgentObserver: Send + Sync {
    /// Handle one event.
    fn on_event(&self, event: &AgentEvent);
}

impl<F: Fn(&AgentEvent) + Send + Sync> AgentObserver for F {
    fn on_event(&self, event: &AgentEvent) {
        self(event);
    }
}
