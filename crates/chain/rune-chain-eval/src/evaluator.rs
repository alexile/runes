//! The [`Evaluator`] trait and the [`Score`] it returns.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{EvalError, Example, TargetOutput};

/// One metric's result for one example.
///
/// `value` is the metric (usually in `0.0..=1.0`); `passed` is the
/// evaluator's verdict against its threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Score {
    /// The metric value.
    pub value: f64,
    /// Whether the example passes this metric.
    pub passed: bool,
    /// Why, when the evaluator explains itself (judges do).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    /// Extra structured detail (per-claim verdicts, violations, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl Score {
    /// A score with an explicit pass/fail.
    #[must_use]
    pub const fn new(value: f64, passed: bool) -> Self {
        Self {
            value,
            passed,
            reasoning: None,
            details: None,
        }
    }

    /// `1.0` and passed, or `0.0` and failed.
    #[must_use]
    pub const fn binary(passed: bool) -> Self {
        Self::new(if passed { 1.0 } else { 0.0 }, passed)
    }

    /// A score that passes when `value >= threshold`.
    #[must_use]
    pub fn at_least(value: f64, threshold: f64) -> Self {
        Self::new(value, value >= threshold)
    }

    /// Attach reasoning (builder style).
    #[must_use]
    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Self {
        self.reasoning = Some(reasoning.into());
        self
    }

    /// Attach details (builder style).
    #[must_use]
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// What happened when a metric was computed for one example.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MetricOutcome {
    /// The evaluator produced a score.
    Scored(Score),
    /// The evaluator (or the target) failed. Never counts as a pass.
    Error {
        /// What went wrong.
        message: String,
    },
}

impl MetricOutcome {
    /// The score, if there is one.
    #[must_use]
    pub const fn score(&self) -> Option<&Score> {
        match self {
            Self::Scored(s) => Some(s),
            Self::Error { .. } => None,
        }
    }

    /// Whether this is a passing score.
    #[must_use]
    pub const fn passed(&self) -> bool {
        matches!(self, Self::Scored(s) if s.passed)
    }

    /// The metric value, if scored.
    #[must_use]
    pub fn value(&self) -> Option<f64> {
        self.score().map(|s| s.value)
    }
}

/// Scores a target's output for one example.
///
/// ```rust
/// use async_trait::async_trait;
/// use rune_chain_eval::{EvalError, Evaluator, Example, Score, TargetOutput};
///
/// /// Passes when the answer is short.
/// struct Concise;
///
/// #[async_trait]
/// impl Evaluator for Concise {
///     fn name(&self) -> &str { "concise" }
///     async fn evaluate(&self, _: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
///         Ok(Score::binary(out.output.split_whitespace().count() <= 20))
///     }
/// }
/// ```
#[async_trait]
pub trait Evaluator: Send + Sync {
    /// The metric name; unique within a run.
    fn name(&self) -> &str;

    /// Score `output` for `example`.
    async fn evaluate(&self, example: &Example, output: &TargetOutput) -> Result<Score, EvalError>;
}

#[async_trait]
impl<E: Evaluator + ?Sized> Evaluator for std::sync::Arc<E> {
    fn name(&self) -> &str {
        (**self).name()
    }
    async fn evaluate(&self, example: &Example, output: &TargetOutput) -> Result<Score, EvalError> {
        (**self).evaluate(example, output).await
    }
}

#[async_trait]
impl<E: Evaluator + ?Sized> Evaluator for Box<E> {
    fn name(&self) -> &str {
        (**self).name()
    }
    async fn evaluate(&self, example: &Example, output: &TargetOutput) -> Result<Score, EvalError> {
        (**self).evaluate(example, output).await
    }
}

/// The example's reference, or [`EvalError::Missing`].
pub fn reference(example: &Example) -> Result<&str, EvalError> {
    example
        .reference
        .as_deref()
        .ok_or_else(|| EvalError::Missing("reference output".into()))
}
