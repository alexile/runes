use std::collections::HashMap;
use std::time::Duration;

use rune_chain_core::{ChainError, GenerateResult, TokenUsage};
use serde_json::Value;

/// What happened to a step, reported to the
/// [`on_event`](crate::SequentialChainBuilder::on_event) callback as the
/// pipeline runs.
///
/// Events arrive in order: `Started`, any number of `Retrying`, then
/// `Finished` or `Failed`, and `Exited` after the step whose
/// [`exit_if`](crate::Step::exit_if) fired. A step streamed by
/// [`Chain::stream`](rune_chain_core::Chain::stream) reports only `Started`
/// (and `Failed` if the stream cannot be opened).
#[derive(Debug)]
#[non_exhaustive]
pub enum StepEvent<'a> {
    /// The step is about to run.
    Started {
        /// Position of the step, from 0.
        index: usize,
        /// The step's name.
        name: &'a str,
    },
    /// An attempt failed and the step will run again after `delay`.
    Retrying {
        /// Position of the step, from 0.
        index: usize,
        /// The step's name.
        name: &'a str,
        /// The attempt that failed, from 1.
        attempt: u32,
        /// Why it failed.
        error: &'a ChainError,
        /// How long the pipeline waits before the next attempt.
        delay: Duration,
    },
    /// The step succeeded.
    Finished {
        /// Position of the step, from 0.
        index: usize,
        /// The step's name.
        name: &'a str,
        /// The step's result, with its own token usage.
        result: &'a GenerateResult,
        /// Attempts it took, from 1.
        attempts: u32,
        /// Wall time across all attempts and retry delays.
        elapsed: Duration,
    },
    /// The step failed for good; the pipeline stops with `error`.
    Failed {
        /// Position of the step, from 0.
        index: usize,
        /// The step's name.
        name: &'a str,
        /// The error the pipeline returns.
        error: &'a ChainError,
        /// Attempts made, from 1.
        attempts: u32,
        /// Wall time across all attempts and retry delays.
        elapsed: Duration,
    },
    /// The step's exit condition fired; later steps are skipped.
    Exited {
        /// Position of the step, from 0.
        index: usize,
        /// The step's name.
        name: &'a str,
    },
}

/// How one step went, as recorded in a [`SequentialRun`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StepReport {
    /// The step's name.
    pub name: String,
    /// The key its answer was stored under.
    pub output_key: String,
    /// Its result, with its own token usage and finish reason.
    pub result: GenerateResult,
    /// Attempts it took, from 1.
    pub attempts: u32,
    /// Wall time across all attempts and retry delays.
    pub elapsed: Duration,
}

/// Everything a [`SequentialChain::run`](crate::SequentialChain::run)
/// produced.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SequentialRun {
    /// The final answer: the last step that ran, with token usage summed
    /// across every step.
    pub result: GenerateResult,
    /// Every step output by key, as [`Chain::execute`](rune_chain_core::Chain::execute)
    /// returns them (without `"generate_result"`). After an early exit the
    /// skipped steps' keys hold `null`, except the last step's key, which
    /// holds the final answer.
    pub outputs: HashMap<String, Value>,
    /// One report per step that ran, in order.
    pub steps: Vec<StepReport>,
    /// The name of the step whose exit condition stopped the pipeline.
    pub exited_after: Option<String>,
}

impl SequentialRun {
    /// Token usage summed across every step, if any step reported it.
    #[must_use]
    pub const fn usage(&self) -> Option<&TokenUsage> {
        self.result.tokens.as_ref()
    }
}
