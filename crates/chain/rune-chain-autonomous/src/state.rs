//! Serializable agent state, used both as the run result and as a
//! checkpoint to resume from.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use rune_chain_agent::sanitize::truncate_with_marker;
use rune_chain_core::{Cost, TokenUsage};
use serde::{Deserialize, Serialize};

use crate::Limits;
use crate::untrusted::{clean_task, task_key};

/// Version of the [`AgentState`] layout. Resuming from a state with another
/// version is refused.
pub const CHECKPOINT_VERSION: u32 = 1;

/// A unit of work in the queue.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Task {
    /// Id, unique within a run, in creation order from 1.
    pub id: u64,
    /// What to do. Produced by the planner, so untrusted.
    pub description: String,
}

impl Task {
    /// A task with the given id and description.
    #[must_use]
    pub fn new(id: u64, description: impl Into<String>) -> Self {
        Self {
            id,
            description: description.into(),
        }
    }
}

/// A finished task and its result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TaskRecord {
    /// The task.
    pub task: Task,
    /// What the task produced, cut to
    /// [`Limits::max_result_bytes`](crate::Limits::max_result_bytes).
    pub result: String,
    /// Whether `result` was truncated.
    pub truncated: bool,
    /// Tool calls made while doing the task (including refused ones).
    pub tool_calls: usize,
}

/// Everything needed to continue a run: goal, queue, bounded history and the
/// budget already spent.
///
/// It is returned in every [`AutonomousRun`](crate::AutonomousRun) and passed
/// to the checkpoint callback after every task. Serialize it with any serde
/// format and hand it to [`AutonomousAgent::resume`](crate::AutonomousAgent::resume)
/// to continue.
///
/// Spent budget (tasks, LLM calls, tokens, cost, wall time, loop counters)
/// carries over on resume, so stopping and resuming cannot be used to get
/// around a limit. To deliberately grant a fresh budget call
/// [`reset_budget`](Self::reset_budget). Store checkpoints somewhere the model
/// and its tools cannot write: the agent re-applies size bounds on resume but
/// trusts the counters.
///
/// ```rust
/// use rune_chain_autonomous::AgentState;
///
/// let state = AgentState::new("Write the release notes");
/// let json = serde_json::to_string(&state).unwrap();
/// let back: AgentState = serde_json::from_str(&json).unwrap();
/// assert_eq!(back, state);
/// assert!(back.queue.is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AgentState {
    /// [`CHECKPOINT_VERSION`] at the time the state was written.
    pub version: u32,
    /// The goal, as given by the caller.
    pub goal: String,
    /// Pending tasks, next first.
    pub queue: VecDeque<Task>,
    /// The most recent completed tasks, oldest first.
    pub history: VecDeque<TaskRecord>,
    /// Completed tasks dropped from `history` to keep it bounded.
    pub dropped_history: usize,
    /// The final answer once the run completed.
    pub answer: Option<String>,
    /// Planning rounds adopted so far (initial plan plus continuing reviews).
    pub cycle: usize,
    /// Tasks executed.
    pub tasks_executed: usize,
    /// Tasks accepted into the queue.
    pub tasks_generated: usize,
    /// Id of the next task.
    pub next_task_id: u64,
    /// LLM calls made.
    pub llm_calls: usize,
    /// Token usage summed over every LLM call, `None` if the LLM never
    /// reported any.
    pub usage: Option<TokenUsage>,
    /// Spend, when the agent has a [`Pricing`](rune_chain_core::Pricing).
    pub cost: Cost,
    /// Wall time spent in runs of this state.
    pub elapsed: Duration,
    /// Executions per task key (see [`Limits::max_task_repeats`]).
    pub task_counts: BTreeMap<String, u32>,
    /// Calls per tool-and-arguments key (see
    /// [`Limits::max_identical_tool_calls`]).
    pub tool_call_counts: BTreeMap<String, u32>,
}

impl AgentState {
    /// A fresh state for `goal`.
    #[must_use]
    pub fn new(goal: impl Into<String>) -> Self {
        Self {
            version: CHECKPOINT_VERSION,
            goal: goal.into(),
            queue: VecDeque::new(),
            history: VecDeque::new(),
            dropped_history: 0,
            answer: None,
            cycle: 0,
            tasks_executed: 0,
            tasks_generated: 0,
            next_task_id: 1,
            llm_calls: 0,
            usage: None,
            cost: Cost::ZERO,
            elapsed: Duration::ZERO,
            task_counts: BTreeMap::new(),
            tool_call_counts: BTreeMap::new(),
        }
    }

    /// Total tokens reported so far.
    #[must_use]
    pub fn total_tokens(&self) -> u64 {
        self.usage.as_ref().map_or(0, |u| u64::from(u.total_tokens))
    }

    /// The result of the most recent task.
    #[must_use]
    pub fn last_result(&self) -> Option<&str> {
        self.history.back().map(|r| r.result.as_str())
    }

    /// Zero every spend counter and loop counter, granting the next resume a
    /// full budget. Queue, history and answer are kept.
    ///
    /// ```rust
    /// use rune_chain_autonomous::AgentState;
    ///
    /// let mut state = AgentState::new("goal");
    /// state.llm_calls = 40;
    /// state.reset_budget();
    /// assert_eq!(state.llm_calls, 0);
    /// ```
    pub fn reset_budget(&mut self) {
        self.cycle = usize::from(self.cycle > 0);
        self.tasks_executed = 0;
        self.tasks_generated = self.queue.len();
        self.llm_calls = 0;
        self.usage = None;
        self.cost = Cost::ZERO;
        self.elapsed = Duration::ZERO;
        self.task_counts.clear();
        self.tool_call_counts.clear();
    }

    /// Re-apply size bounds to a state that may come from outside.
    pub(crate) fn enforce_bounds(&mut self, limits: &Limits) {
        let mut seen = std::collections::HashSet::new();
        let queue = std::mem::take(&mut self.queue);
        for mut task in queue {
            if self.queue.len() >= limits.max_queue_len {
                break;
            }
            let Some(desc) = clean_task(&task.description, limits.max_task_bytes) else {
                continue;
            };
            if seen.insert(task_key(&desc)) {
                task.description = desc;
                self.next_task_id = self.next_task_id.max(task.id.saturating_add(1));
                self.queue.push_back(task);
            }
        }
        for record in &mut self.history {
            if record.result.len() > limits.max_result_bytes {
                let (cut, _) = truncate_with_marker(&record.result, limits.max_result_bytes);
                record.result = cut;
                record.truncated = true;
            }
        }
        self.trim_history(limits.max_history);
    }

    pub(crate) fn push_record(&mut self, record: TaskRecord, max_history: usize) {
        self.history.push_back(record);
        self.trim_history(max_history);
    }

    fn trim_history(&mut self, max_history: usize) {
        while self.history.len() > max_history {
            self.history.pop_front();
            self.dropped_history += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_are_reapplied_to_untrusted_state() {
        let mut s = AgentState::new("g");
        for i in 0..50 {
            s.queue
                .push_back(Task::new(i, format!("task {i}\n{}", "x".repeat(900))));
        }
        s.queue.push_back(Task::new(99, "task 0"));
        for i in 0..30 {
            s.history.push_back(TaskRecord {
                task: Task::new(i, "t"),
                result: "r".repeat(10_000),
                truncated: false,
                tool_calls: 0,
            });
        }
        let limits = Limits::default();
        s.enforce_bounds(&limits);
        assert_eq!(s.queue.len(), limits.max_queue_len);
        assert!(
            s.queue
                .iter()
                .all(|t| t.description.len() <= limits.max_task_bytes)
        );
        assert!(s.queue.iter().all(|t| !t.description.contains('\n')));
        assert_eq!(s.history.len(), limits.max_history);
        assert_eq!(s.dropped_history, 10);
        assert!(s.history.iter().all(|r| r.truncated));
        assert_eq!(s.next_task_id, 20);
    }

    #[test]
    fn reset_budget_keeps_work() {
        let mut s = AgentState::new("g");
        s.queue.push_back(Task::new(1, "a"));
        s.cycle = 3;
        s.tasks_executed = 9;
        s.task_counts.insert("a".into(), 2);
        s.reset_budget();
        assert_eq!(
            (s.cycle, s.tasks_executed, s.tasks_generated, s.queue.len()),
            (1, 0, 1, 1)
        );
        assert!(s.task_counts.is_empty());
    }
}
