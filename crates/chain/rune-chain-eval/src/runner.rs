//! Running a target over a dataset and scoring it.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{StreamExt, future::join_all, stream};
use rune_chain_core::{ChainError, DEFAULT_BATCH_CONCURRENCY, LlmError, Pricing};
use rune_chain_usage::{Usage, UsageMeter};

use crate::stats::BootstrapConfig;
use crate::{
    Dataset, EvalError, Evaluator, Example, ExampleResult, MetricOutcome, RunResult, Target,
    TargetOutput,
};

/// Default cap on stored target output, in bytes.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024;
/// Most characters of an error message kept in a result.
const MAX_ERROR_CHARS: usize = 500;
/// Longest single retry backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Records each example's usage in a [`UsageMeter`] under a provider and
/// model, at a price.
#[derive(Debug, Clone)]
struct Metering {
    meter: UsageMeter,
    provider: String,
    model: String,
}

/// An evaluation: evaluators plus how to run the target.
///
/// ```rust
/// use rune_chain_eval::{Dataset, Evaluation, Example, ExactMatch, TargetOutput, target_fn};
///
/// # tokio_test::block_on(async {
/// let ds = Dataset::new(vec![
///     Example::from_question("1", "2+2?").with_reference("4"),
///     Example::from_question("2", "3+3?").with_reference("6"),
/// ]).unwrap();
/// let target = target_fn(|ex| async move {
///     let answer = if ex.question() == Some("2+2?") { "4" } else { "7" };
///     Ok::<_, rune_chain_core::ChainError>(TargetOutput::text(answer))
/// });
/// let run = Evaluation::new("calc-v1")
///     .evaluator(ExactMatch::new())
///     .run(&ds, &target)
///     .await
///     .unwrap();
/// assert_eq!(run.metric("exact_match").unwrap().pass_rate, 0.5);
/// # });
/// ```
#[derive(Clone)]
pub struct Evaluation {
    name: String,
    evaluators: Vec<Arc<dyn Evaluator>>,
    concurrency: usize,
    timeout: Option<Duration>,
    evaluator_timeout: Option<Duration>,
    retries: u32,
    backoff: Duration,
    max_output_bytes: usize,
    pricing: Option<Pricing>,
    metering: Option<Metering>,
    bootstrap: BootstrapConfig,
}

impl std::fmt::Debug for Evaluation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Evaluation")
            .field("name", &self.name)
            .field(
                "evaluators",
                &self
                    .evaluators
                    .iter()
                    .map(|e| e.name().to_owned())
                    .collect::<Vec<_>>(),
            )
            .field("concurrency", &self.concurrency)
            .field("timeout", &self.timeout)
            .field("retries", &self.retries)
            .finish_non_exhaustive()
    }
}

impl Evaluation {
    /// A run named `name`: [`DEFAULT_BATCH_CONCURRENCY`] examples at once,
    /// no timeout, no retries, outputs capped at
    /// [`DEFAULT_MAX_OUTPUT_BYTES`], 1000 bootstrap resamples with seed 0.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            evaluators: Vec::new(),
            concurrency: DEFAULT_BATCH_CONCURRENCY,
            timeout: None,
            evaluator_timeout: None,
            retries: 0,
            backoff: Duration::from_millis(500),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            pricing: None,
            metering: None,
            bootstrap: BootstrapConfig::default(),
        }
    }

    /// Add an evaluator (builder style).
    #[must_use]
    pub fn evaluator(mut self, evaluator: impl Evaluator + 'static) -> Self {
        self.evaluators.push(Arc::new(evaluator));
        self
    }

    /// Add a shared evaluator (builder style).
    #[must_use]
    pub fn evaluator_arc(mut self, evaluator: Arc<dyn Evaluator>) -> Self {
        self.evaluators.push(evaluator);
        self
    }

    /// Examples in flight at once; `0` means 1 (builder style).
    #[must_use]
    pub fn concurrency(mut self, n: usize) -> Self {
        self.concurrency = n.max(1);
        self
    }

    /// Time limit per target attempt (builder style). Also the evaluator
    /// limit unless [`evaluator_timeout`](Self::evaluator_timeout) is set.
    #[must_use]
    pub const fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = Some(limit);
        self
    }

    /// Time limit per evaluator call (builder style).
    #[must_use]
    pub const fn evaluator_timeout(mut self, limit: Duration) -> Self {
        self.evaluator_timeout = Some(limit);
        self
    }

    /// Retries after a timeout or a retryable model error (rate limit,
    /// overload, network, 5xx), with exponential backoff (builder style).
    #[must_use]
    pub const fn retries(mut self, n: u32) -> Self {
        self.retries = n;
        self
    }

    /// First retry delay, doubled each retry, capped at 30 s (builder
    /// style).
    #[must_use]
    pub const fn retry_backoff(mut self, delay: Duration) -> Self {
        self.backoff = delay;
        self
    }

    /// Cap on the stored and scored output, in bytes (builder style).
    #[must_use]
    pub const fn max_output_bytes(mut self, n: usize) -> Self {
        self.max_output_bytes = n;
        self
    }

    /// Price the target's token usage (builder style).
    #[must_use]
    pub const fn pricing(mut self, pricing: Pricing) -> Self {
        self.pricing = Some(pricing);
        self
    }

    /// Also record each example's usage in `meter` under `provider` /
    /// `model`, tagged with the run name (builder style). Needs
    /// [`pricing`](Self::pricing) for costs.
    #[must_use]
    pub fn meter(
        mut self,
        meter: UsageMeter,
        provider: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        self.metering = Some(Metering {
            meter,
            provider: provider.into(),
            model: model.into(),
        });
        self
    }

    /// Bootstrap settings for the confidence intervals (builder style).
    #[must_use]
    pub const fn bootstrap(mut self, config: BootstrapConfig) -> Self {
        self.bootstrap = config;
        self
    }

    /// Run `target` on every example and score each output with every
    /// evaluator.
    ///
    /// Examples run at most [`concurrency`](Self::concurrency) at a time,
    /// in the same ordered, bounded way as
    /// [`Chain::batch`](rune_chain_core::Chain::batch); results keep
    /// dataset order. A failed target or evaluator becomes an error
    /// outcome for that example and never stops the run.
    ///
    /// # Errors
    ///
    /// [`EvalError::Config`] when two evaluators share a name.
    pub async fn run<T: Target + ?Sized>(
        &self,
        dataset: &Dataset,
        target: &T,
    ) -> Result<RunResult, EvalError> {
        let mut names = HashSet::new();
        for e in &self.evaluators {
            if !names.insert(e.name()) {
                return Err(EvalError::Config(format!(
                    "two evaluators are named `{}`; rename one with `with_name`",
                    e.name()
                )));
            }
        }
        let results: Vec<ExampleResult> =
            stream::iter(dataset.iter().map(|ex| self.one(ex, target)))
                .buffered(self.concurrency)
                .collect()
                .await;
        Ok(RunResult::new(self.name.clone(), results, &self.bootstrap))
    }

    /// Score outputs that were produced elsewhere (pairs of example and
    /// output), e.g. to re-score a stored run with new metrics.
    ///
    /// # Errors
    ///
    /// [`EvalError::Config`] when two evaluators share a name.
    pub async fn score_outputs(
        &self,
        pairs: &[(Example, TargetOutput)],
    ) -> Result<RunResult, EvalError> {
        let target = crate::target_fn(|ex: Example| {
            let found = pairs
                .iter()
                .find(|(e, _)| e.id == ex.id)
                .map(|(_, o)| o.clone());
            async move { found.ok_or_else(|| ChainError::Other("no stored output".into())) }
        });
        let dataset = Dataset::new(pairs.iter().map(|(e, _)| e.clone()).collect())?;
        self.run(&dataset, &target).await
    }

    async fn call_target<T: Target + ?Sized>(
        &self,
        ex: &Example,
        target: &T,
    ) -> (Result<TargetOutput, String>, Duration, u32) {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let start = Instant::now();
            let res = match self.timeout {
                Some(limit) => tokio::time::timeout(limit, target.run(ex))
                    .await
                    .unwrap_or_else(|_| Err(LlmError::timeout("target timed out").into())),
                None => target.run(ex).await,
            };
            let elapsed = start.elapsed();
            match res {
                Ok(out) => return (Ok(out), elapsed, attempt),
                Err(e) => {
                    if attempt > self.retries || !retryable(&e) {
                        return (Err(clip(&e.to_string(), MAX_ERROR_CHARS)), elapsed, attempt);
                    }
                    let factor = 1u32 << (attempt - 1).min(16);
                    tokio::time::sleep(self.backoff.saturating_mul(factor).min(MAX_BACKOFF)).await;
                }
            }
        }
    }

    async fn one<T: Target + ?Sized>(&self, ex: &Example, target: &T) -> ExampleResult {
        let (res, elapsed, attempts) = self.call_target(ex, target).await;
        let mut result = ExampleResult {
            id: ex.id.clone(),
            inputs: ex.inputs.clone(),
            reference: ex.reference.clone(),
            output: None,
            output_truncated: false,
            error: None,
            latency_ms: elapsed.as_secs_f64() * 1000.0,
            attempts,
            usage: None,
            cost: None,
            tool_calls: Vec::new(),
            scores: BTreeMap::new(),
        };
        let mut out = match res {
            Ok(out) => out,
            Err(msg) => {
                for e in &self.evaluators {
                    result.scores.insert(
                        e.name().to_owned(),
                        MetricOutcome::Error {
                            message: "target failed".into(),
                        },
                    );
                }
                result.error = Some(msg);
                return result;
            }
        };
        result.output_truncated = truncate_bytes(&mut out.output, self.max_output_bytes);
        if let Some(u) = &out.usage {
            let usage = Usage::from_token_usage(u);
            if let Some(p) = &self.pricing {
                result.cost = Some(usage.cost(p));
                if let Some(m) = &self.metering {
                    // The run keeps going when a budget is exhausted; the
                    // meter has still recorded the call.
                    let _ =
                        m.meter
                            .record_tagged(&m.provider, &m.model, Some(&self.name), p, usage);
                }
            }
        }
        result.usage = out.usage.clone();
        result.tool_calls = out.tool_calls.iter().map(|c| c.name.clone()).collect();
        let limit = self.evaluator_timeout.or(self.timeout);
        let outcomes = join_all(self.evaluators.iter().map(|e| {
            let out = &out;
            async move {
                let fut = e.evaluate(ex, out);
                let res = match limit {
                    Some(l) => tokio::time::timeout(l, fut)
                        .await
                        .unwrap_or(Err(EvalError::Timeout)),
                    None => fut.await,
                };
                let outcome = match res {
                    Ok(s) if s.value.is_finite() => MetricOutcome::Scored(s),
                    Ok(_) => MetricOutcome::Error {
                        message: "score is not a finite number".into(),
                    },
                    Err(err) => MetricOutcome::Error {
                        message: clip(&err.to_string(), MAX_ERROR_CHARS),
                    },
                };
                (e.name().to_owned(), outcome)
            }
        }))
        .await;
        result.scores.extend(outcomes);
        result.output = Some(out.output);
        result
    }
}

const fn retryable(e: &ChainError) -> bool {
    matches!(e, ChainError::LlmError(e) if e.is_retryable())
}

/// Cut `text` to at most `max` bytes on a char boundary.
fn truncate_bytes(text: &mut String, max: usize) -> bool {
    if text.len() <= max {
        return false;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    true
}

fn clip(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &text[..i]),
        None => text.to_owned(),
    }
}
