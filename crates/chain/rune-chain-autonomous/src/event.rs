//! Observability: the event stream of a run, and the caller's stop switch.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rune_chain_agent::AgentEvent;
use rune_chain_core::{Cost, TokenUsage};

use crate::{RunOutcome, Task};

/// Why the agent discarded tasks proposed by the planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DropReason {
    /// Blank after cleaning.
    Empty,
    /// Already waiting in the queue.
    Duplicate,
    /// Already ran [`Limits::max_task_repeats`](crate::Limits::max_task_repeats) times.
    Repeated,
    /// Beyond [`Limits::max_new_tasks_per_step`](crate::Limits::max_new_tasks_per_step).
    PerStepLimit,
    /// The queue was at [`Limits::max_queue_len`](crate::Limits::max_queue_len).
    QueueFull,
}

/// One step of an autonomous run, delivered to an [`AutonomousObserver`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AutonomousEvent {
    /// A run started or resumed.
    RunStarted {
        /// The goal.
        goal: String,
        /// Whether the run continues an earlier state.
        resumed: bool,
    },
    /// The planner's tasks were accepted into the queue.
    Planned {
        /// Planning round, from 1.
        cycle: usize,
        /// The newly queued tasks.
        tasks: Vec<Task>,
    },
    /// Proposed tasks were discarded.
    TasksDropped {
        /// How many.
        count: usize,
        /// Why.
        reason: DropReason,
    },
    /// A task is about to run.
    TaskStarted {
        /// The task.
        task: Task,
    },
    /// An event from the tool-calling loop running a task (tool calls,
    /// results, approvals denied, ...).
    Agent {
        /// The task being run.
        task_id: u64,
        /// The event.
        event: AgentEvent,
    },
    /// A task finished.
    TaskFinished {
        /// The task.
        task_id: u64,
        /// Its (size-capped) result.
        result: String,
        /// Whether the result was truncated.
        truncated: bool,
    },
    /// An LLM call finished; running totals so far.
    LlmCall {
        /// LLM calls made.
        calls: usize,
        /// Token usage so far.
        usage: Option<TokenUsage>,
        /// Spend so far (zero without pricing).
        cost: Cost,
    },
    /// The planner reviewed progress.
    Reviewed {
        /// Whether it declared the goal done.
        done: bool,
    },
    /// The run ended.
    Finished {
        /// How.
        outcome: RunOutcome,
    },
}

/// Receives [`AutonomousEvent`]s.
///
/// Implemented for any `Fn(&AutonomousEvent) + Send + Sync` and for a Tokio
/// unbounded sender, which turns the run into an event stream:
///
/// ```rust
/// use rune_chain_autonomous::{AutonomousEvent, AutonomousObserver};
///
/// let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AutonomousEvent>();
/// tx.on_event(&AutonomousEvent::Reviewed { done: true });
/// assert_eq!(rx.try_recv().unwrap(), AutonomousEvent::Reviewed { done: true });
/// ```
///
/// Called inline from the run loop, so keep it cheap.
pub trait AutonomousObserver: Send + Sync {
    /// Handle one event.
    fn on_event(&self, event: &AutonomousEvent);
}

impl<F: Fn(&AutonomousEvent) + Send + Sync> AutonomousObserver for F {
    fn on_event(&self, event: &AutonomousEvent) {
        self(event);
    }
}

impl AutonomousObserver for tokio::sync::mpsc::UnboundedSender<AutonomousEvent> {
    fn on_event(&self, event: &AutonomousEvent) {
        // A dropped receiver just means nobody is listening any more.
        let _ = self.send(event.clone());
    }
}

/// A switch the caller flips to stop a run.
///
/// The agent checks it before every LLM call and between tasks; the run then
/// ends with [`RunOutcome::Stopped`]. An LLM call already in flight is allowed
/// to finish. Clones share the switch.
///
/// ```rust
/// use rune_chain_autonomous::StopHandle;
///
/// let handle = StopHandle::new();
/// let remote = handle.clone();
/// remote.stop();
/// assert!(handle.is_stopped());
/// handle.reset();
/// assert!(!remote.is_stopped());
/// ```
#[derive(Debug, Clone, Default)]
pub struct StopHandle(Arc<AtomicBool>);

impl StopHandle {
    /// A handle that is not stopped.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask every run using this handle to stop.
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether [`stop`](Self::stop) was called (and not reset since).
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Clear the switch so new runs can proceed.
    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
