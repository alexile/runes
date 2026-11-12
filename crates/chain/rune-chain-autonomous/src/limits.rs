//! Hard budgets and size bounds for an autonomous run.

use std::fmt;
use std::time::Duration;

use rune_chain_core::Cost;
use serde::{Deserialize, Serialize};

/// Hard limits for an autonomous run. Every limit is on by default.
///
/// The agent checks these itself, between steps and before every LLM call.
/// Nothing the model writes can raise or skip them: the only way to change a
/// limit is to configure the agent differently.
///
/// Spend limits (tasks, cycles, LLM calls, wall time, tokens, cost) end the
/// run with [`RunOutcome::BudgetExceeded`](crate::RunOutcome::BudgetExceeded).
/// Size limits (queue, task text, history, results, prompt context) bound
/// memory and prompt growth by dropping or truncating, and never end the run
/// by themselves.
///
/// ```rust
/// use std::time::Duration;
/// use rune_chain_autonomous::Limits;
/// use rune_chain_core::Cost;
///
/// let limits = Limits::default()
///     .max_tasks(10)
///     .max_wall_time(Some(Duration::from_secs(120)))
///     .max_total_tokens(Some(50_000))
///     .max_cost(Some(Cost::from_cents(25)));
/// assert_eq!(limits.max_tasks, 10);
/// assert_eq!(limits.max_queue_len, 20);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Tasks executed over the whole run (default 25).
    pub max_tasks: usize,
    /// Planning rounds: the initial plan plus every review that asks for more
    /// work (default 4). A review that declares the goal done is always
    /// allowed.
    pub max_cycles: usize,
    /// LLM calls of any kind: planning, task execution, tool rounds and
    /// review (default 100).
    pub max_llm_calls: usize,
    /// Wall-clock time over the whole run, resumed runs included (default
    /// 10 min). `None` disables it.
    pub max_wall_time: Option<Duration>,
    /// Total tokens reported by the LLM (default 200 000). Only enforceable
    /// for providers that report usage. `None` disables it.
    pub max_total_tokens: Option<u64>,
    /// Total spend (default $1.00). Only enforced when the agent has a
    /// [`Pricing`](rune_chain_core::Pricing). `None` disables it.
    pub max_cost: Option<Cost>,
    /// Tasks the planner may create over the whole run (default 100).
    pub max_generated_tasks: usize,
    /// Pending tasks held in the queue at once (default 20). New tasks that
    /// do not fit are dropped and reported.
    pub max_queue_len: usize,
    /// New tasks accepted from one planner reply (default 10).
    pub max_new_tasks_per_step: usize,
    /// Bytes of one task description; longer ones are cut (default 500).
    pub max_task_bytes: usize,
    /// How often the same task (compared case- and punctuation-insensitively)
    /// may run (default 2). Further copies are dropped, and a planner that
    /// proposes nothing but such repeats ends the run with
    /// [`LoopKind::RepeatedTask`](crate::LoopKind::RepeatedTask).
    pub max_task_repeats: u32,
    /// How often one tool may be called with identical arguments over the
    /// run (default 3). The next identical call is refused and ends the run
    /// with [`LoopKind::RepeatedToolCall`](crate::LoopKind::RepeatedToolCall).
    pub max_identical_tool_calls: u32,
    /// Completed-task records kept in the state (default 20); older ones are
    /// dropped and counted.
    pub max_history: usize,
    /// Bytes of one stored task result; longer ones are truncated with a
    /// marker (default 4 KiB).
    pub max_result_bytes: usize,
    /// Bytes of earlier results quoted into one prompt (default 16 KiB). The
    /// newest results are kept.
    pub max_context_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tasks: 25,
            max_cycles: 4,
            max_llm_calls: 100,
            max_wall_time: Some(Duration::from_secs(600)),
            max_total_tokens: Some(200_000),
            max_cost: Some(Cost::from_cents(100)),
            max_generated_tasks: 100,
            max_queue_len: 20,
            max_new_tasks_per_step: 10,
            max_task_bytes: 500,
            max_task_repeats: 2,
            max_identical_tool_calls: 3,
            max_history: 20,
            max_result_bytes: 4 * 1024,
            max_context_bytes: 16 * 1024,
        }
    }
}

macro_rules! setters {
    ($($(#[$doc:meta])* $name:ident: $ty:ty),* $(,)?) => {
        impl Limits {
            $(
                $(#[$doc])*
                #[must_use]
                pub const fn $name(mut self, value: $ty) -> Self {
                    self.$name = value;
                    self
                }
            )*
        }
    };
}

setters! {
    /// Set [`max_tasks`](Self::max_tasks).
    max_tasks: usize,
    /// Set [`max_cycles`](Self::max_cycles).
    max_cycles: usize,
    /// Set [`max_llm_calls`](Self::max_llm_calls).
    max_llm_calls: usize,
    /// Set [`max_wall_time`](Self::max_wall_time).
    max_wall_time: Option<Duration>,
    /// Set [`max_total_tokens`](Self::max_total_tokens).
    max_total_tokens: Option<u64>,
    /// Set [`max_cost`](Self::max_cost).
    max_cost: Option<Cost>,
    /// Set [`max_generated_tasks`](Self::max_generated_tasks).
    max_generated_tasks: usize,
    /// Set [`max_queue_len`](Self::max_queue_len).
    max_queue_len: usize,
    /// Set [`max_new_tasks_per_step`](Self::max_new_tasks_per_step).
    max_new_tasks_per_step: usize,
    /// Set [`max_task_bytes`](Self::max_task_bytes).
    max_task_bytes: usize,
    /// Set [`max_task_repeats`](Self::max_task_repeats).
    max_task_repeats: u32,
    /// Set [`max_identical_tool_calls`](Self::max_identical_tool_calls).
    max_identical_tool_calls: u32,
    /// Set [`max_history`](Self::max_history).
    max_history: usize,
    /// Set [`max_result_bytes`](Self::max_result_bytes).
    max_result_bytes: usize,
    /// Set [`max_context_bytes`](Self::max_context_bytes).
    max_context_bytes: usize,
}

/// Which spend limit ended a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BudgetKind {
    /// [`Limits::max_tasks`].
    Tasks,
    /// [`Limits::max_cycles`].
    Cycles,
    /// [`Limits::max_llm_calls`].
    LlmCalls,
    /// [`Limits::max_wall_time`].
    WallTime,
    /// [`Limits::max_total_tokens`].
    Tokens,
    /// [`Limits::max_cost`].
    Cost,
    /// [`Limits::max_generated_tasks`].
    GeneratedTasks,
}

impl fmt::Display for BudgetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tasks => "task limit",
            Self::Cycles => "planning-cycle limit",
            Self::LlmCalls => "LLM-call limit",
            Self::WallTime => "wall-time limit",
            Self::Tokens => "token limit",
            Self::Cost => "cost limit",
            Self::GeneratedTasks => "generated-task limit",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_all_on() {
        let l = Limits::default();
        assert_eq!(l.max_tasks, 25);
        assert_eq!(l.max_cycles, 4);
        assert!(l.max_wall_time.is_some());
        assert!(l.max_total_tokens.is_some());
        assert_eq!(l.max_cost, Some(Cost::from_cents(100)));
        assert!(l.max_queue_len > 0 && l.max_queue_len <= l.max_generated_tasks);
    }

    #[test]
    fn budget_kind_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&BudgetKind::LlmCalls).unwrap(),
            "\"llm_calls\""
        );
        assert_eq!(BudgetKind::WallTime.to_string(), "wall-time limit");
    }
}
