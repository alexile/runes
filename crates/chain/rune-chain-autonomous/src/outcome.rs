//! How a run ended.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::BudgetKind;

/// How an autonomous run ended.
///
/// ```rust
/// use rune_chain_autonomous::{BudgetKind, RunOutcome};
///
/// let outcome = RunOutcome::BudgetExceeded(BudgetKind::Tokens);
/// assert!(!outcome.is_completed());
/// assert_eq!(outcome.to_string(), "budget exceeded: token limit");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "detail")]
#[non_exhaustive]
pub enum RunOutcome {
    /// The planner's review judged the goal achieved.
    Completed {
        /// The final answer.
        answer: String,
    },
    /// A spend limit in [`Limits`](crate::Limits) was reached.
    BudgetExceeded(BudgetKind),
    /// The run was going in circles.
    LoopDetected(LoopKind),
    /// The caller stopped the run.
    Stopped(StopCause),
    /// An LLM or tool failure ended the run. The message is truncated and
    /// passed through secret redaction.
    Error {
        /// What went wrong.
        message: String,
    },
}

impl RunOutcome {
    /// Whether the goal was reported done.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    /// The final answer, for completed runs.
    #[must_use]
    pub fn answer(&self) -> Option<&str> {
        match self {
            Self::Completed { answer } => Some(answer),
            _ => None,
        }
    }
}

impl fmt::Display for RunOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed { .. } => f.write_str("completed"),
            Self::BudgetExceeded(kind) => write!(f, "budget exceeded: {kind}"),
            Self::LoopDetected(kind) => write!(f, "loop detected: {kind}"),
            Self::Stopped(cause) => write!(f, "stopped: {cause}"),
            Self::Error { message } => write!(f, "error: {message}"),
        }
    }
}

/// What kind of loop was detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LoopKind {
    /// The planner only proposed tasks that already ran
    /// [`Limits::max_task_repeats`](crate::Limits::max_task_repeats) times.
    RepeatedTask {
        /// One of the repeated tasks.
        task: String,
    },
    /// A tool was called with identical arguments more than
    /// [`Limits::max_identical_tool_calls`](crate::Limits::max_identical_tool_calls) times.
    RepeatedToolCall {
        /// The tool.
        tool: String,
    },
    /// The review asked to continue but proposed no usable task.
    NoProgress,
}

impl fmt::Display for LoopKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepeatedTask { task } => write!(f, "task repeated: {task}"),
            Self::RepeatedToolCall { tool } => write!(f, "identical calls to `{tool}` repeated"),
            Self::NoProgress => f.write_str("no new tasks proposed"),
        }
    }
}

/// Why the caller stopped a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StopCause {
    /// [`StopHandle::stop`](crate::StopHandle::stop) was called.
    Requested,
    /// The predicate set with
    /// [`AutonomousAgent::stop_when`](crate::AutonomousAgent::stop_when) returned `true`.
    Condition,
}

impl fmt::Display for StopCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Requested => "stop requested",
            Self::Condition => "stop condition met",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_round_trips_through_json() {
        let cases = [
            RunOutcome::Completed {
                answer: "ok".into(),
            },
            RunOutcome::BudgetExceeded(BudgetKind::Cost),
            RunOutcome::LoopDetected(LoopKind::RepeatedTask { task: "x".into() }),
            RunOutcome::Stopped(StopCause::Requested),
            RunOutcome::Error {
                message: "boom".into(),
            },
        ];
        for case in cases {
            let json = serde_json::to_string(&case).unwrap();
            assert_eq!(serde_json::from_str::<RunOutcome>(&json).unwrap(), case);
        }
        assert_eq!(
            RunOutcome::Completed { answer: "a".into() }.answer(),
            Some("a")
        );
    }
}
