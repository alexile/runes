//! `ParallelChain` — run several chains on the same input concurrently and
//! merge their outputs.
//!
//! Branches run concurrently on the calling task (nothing is spawned). Each
//! branch's answer is stored under its output key; [`Chain::call`] returns
//! the last declared branch's result with token usage summed across all
//! branches.
//!
//! # Features
//!
//! - Bounded concurrency: [`ParallelChain::max_concurrency`], or a
//!   [`Semaphore`] shared between chains with
//!   [`ParallelChain::with_semaphore`] to cap load on a provider globally.
//! - Per-branch timeouts ([`Branch::timeout`], or a default with
//!   [`ParallelChain::branch_timeout`]).
//! - [`ErrorMode::FailFast`] (default): the first failure cancels the
//!   branches still running and is returned as is.
//!   [`ErrorMode::CollectAll`]: every branch runs to the end and
//!   [`ParallelChain::run`] reports each outcome.
//! - Deterministic output: results are ordered as the branches were
//!   declared, whatever order they finish in.
//! - Token usage summed across branches (cache and reasoning tokens
//!   included).
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_parallel::ParallelChain;
//! use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, prompt_args};
//! use async_trait::async_trait;
//!
//! struct UpperCase;
//! #[async_trait]
//! impl Chain for UpperCase {
//!     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
//!         let text = input["input"].as_str().unwrap_or_default().to_uppercase();
//!         Ok(GenerateResult::from_text(text))
//!     }
//! }
//!
//! struct LowerCase;
//! #[async_trait]
//! impl Chain for LowerCase {
//!     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
//!         let text = input["input"].as_str().unwrap_or_default().to_lowercase();
//!         Ok(GenerateResult::from_text(text))
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let par = ParallelChain::new()
//!     .branch(UpperCase, "upper")
//!     .branch(LowerCase, "lower")
//!     .max_concurrency(2);
//!
//! let out = par.execute(prompt_args! { "input" => "Hello" }).await.unwrap();
//! assert_eq!(out["upper"], "HELLO");
//! assert_eq!(out["lower"], "hello");
//! # });
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use rune_chain_core::{Chain, ChainError, GenerateResult, LlmError, PromptArgs, TokenUsage};
use serde_json::Value;
pub use tokio::sync::Semaphore;
use tokio::sync::SemaphorePermit;
use tokio::time::Instant;

const RESULT_KEY: &str = "generate_result";

/// What a [`ParallelChain`] does when a branch fails.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorMode {
    /// Return the first failure as soon as it happens and cancel (drop) the
    /// branches still running. The default.
    #[default]
    FailFast,
    /// Let every branch finish. [`ParallelChain::run`] returns every
    /// outcome; the [`Chain`] methods fail if any branch failed.
    CollectAll,
}

/// One branch of a [`ParallelChain`]: a chain, the key its answer is
/// stored under, and an optional timeout.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use rune_chain_parallel::Branch;
/// # use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs};
/// # struct Noop;
/// # #[async_trait::async_trait]
/// # impl Chain for Noop {
/// #     async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
/// #         Ok(GenerateResult::from_text(""))
/// #     }
/// # }
///
/// let b = Branch::new(Noop, "summary").timeout(Duration::from_secs(20));
/// assert_eq!(b.output_key(), "summary");
/// ```
pub struct Branch {
    chain: Arc<dyn Chain>,
    output_key: String,
    timeout: Option<Duration>,
}

impl Branch {
    /// Run `chain` and store its answer under `output_key`.
    #[must_use]
    pub fn new(chain: impl Chain + 'static, output_key: impl Into<String>) -> Self {
        Self::from_arc(Arc::new(chain), output_key)
    }

    /// Like [`new`](Self::new), for a chain that is shared elsewhere.
    #[must_use]
    pub fn from_arc(chain: Arc<dyn Chain>, output_key: impl Into<String>) -> Self {
        Self {
            chain,
            output_key: output_key.into(),
            timeout: None,
        }
    }

    /// Fail the branch with a [timeout error](LlmError::timeout) when it
    /// runs longer than `limit`. Time spent waiting for a concurrency slot
    /// does not count.
    #[must_use]
    pub const fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = Some(limit);
        self
    }

    /// The key the branch's answer is stored under.
    #[must_use]
    pub fn output_key(&self) -> &str {
        &self.output_key
    }
}

impl fmt::Debug for Branch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Branch")
            .field("output_key", &self.output_key)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// How one branch ended, as reported by [`ParallelChain::run`].
#[derive(Debug)]
#[non_exhaustive]
pub struct BranchOutcome {
    /// The branch's output key.
    pub output_key: String,
    /// Its result or error.
    pub result: Result<GenerateResult, ChainError>,
    /// How long it ran, not counting time spent waiting for a slot.
    pub elapsed: Duration,
}

/// Every branch outcome of one [`ParallelChain::run`], in declaration order.
#[derive(Debug)]
#[non_exhaustive]
pub struct ParallelRun {
    /// One outcome per branch, in the order the branches were declared.
    pub branches: Vec<BranchOutcome>,
}

impl ParallelRun {
    /// `true` if every branch succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.branches.iter().all(|b| b.result.is_ok())
    }

    /// The failed branches' keys and errors, in declaration order.
    pub fn errors(&self) -> impl Iterator<Item = (&str, &ChainError)> {
        self.branches
            .iter()
            .filter_map(|b| b.result.as_ref().err().map(|e| (b.output_key.as_str(), e)))
    }

    /// The successful branches' answers by output key.
    #[must_use]
    pub fn outputs(&self) -> HashMap<String, Value> {
        self.branches
            .iter()
            .filter_map(|b| {
                let r = b.result.as_ref().ok()?;
                Some((b.output_key.clone(), Value::String(r.generation.clone())))
            })
            .collect()
    }

    /// Token usage summed across the successful branches, if any reported
    /// it.
    #[must_use]
    pub fn usage(&self) -> Option<TokenUsage> {
        let mut total = None;
        for b in &self.branches {
            if let Ok(r) = &b.result {
                TokenUsage::accumulate(&mut total, r.tokens.as_ref());
            }
        }
        total
    }

    /// The combined result: the last branch's result with usage summed over
    /// all branches, plus every answer by key.
    ///
    /// # Errors
    ///
    /// When exactly one branch failed, its error. When several failed, a
    /// [`ChainError::Other`] naming each failed branch and its error.
    pub fn into_result(self) -> Result<(GenerateResult, HashMap<String, Value>), ChainError> {
        let usage = self.usage();
        let failures = self.branches.iter().filter(|b| b.result.is_err()).count();
        if failures > 1 {
            let detail: Vec<String> = self
                .errors()
                .map(|(key, e)| format!("`{key}`: {e}"))
                .collect();
            return Err(ChainError::Other(format!(
                "{failures} of {} branches failed: {}",
                self.branches.len(),
                detail.join("; ")
            )));
        }
        let mut outputs = HashMap::with_capacity(self.branches.len());
        let mut last = None;
        for b in self.branches {
            let r = b.result?;
            outputs.insert(b.output_key, Value::String(r.generation.clone()));
            last = Some(r);
        }
        let mut result = last.unwrap_or_default();
        result.tokens = usage;
        Ok((result, outputs))
    }
}

/// A fan-out chain that runs several chains on the same input concurrently
/// and merges their answers.
///
/// See the [crate documentation](crate) for the behaviour in detail.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, prompt_args};
/// use rune_chain_parallel::{Branch, ErrorMode, ParallelChain};
/// # struct Fixed(&'static str);
/// # #[async_trait::async_trait]
/// # impl Chain for Fixed {
/// #     async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
/// #         if self.0.is_empty() { return Err(ChainError::Other("no answer".into())) }
/// #         Ok(GenerateResult::from_text(self.0))
/// #     }
/// # }
///
/// # tokio_test::block_on(async {
/// let par = ParallelChain::new()
///     .branch(Fixed("pro"), "pros")
///     .with_branch(Branch::new(Fixed(""), "cons").timeout(Duration::from_secs(5)))
///     .error_mode(ErrorMode::CollectAll);
///
/// let run = par.run(prompt_args! {}).await.unwrap();
/// assert!(!run.is_success());
/// assert_eq!(run.outputs()["pros"], "pro");
/// let failed: Vec<&str> = run.errors().map(|(key, _)| key).collect();
/// assert_eq!(failed, ["cons"]);
/// # });
/// ```
#[derive(Default)]
pub struct ParallelChain {
    branches: Vec<Branch>,
    max_concurrency: Option<usize>,
    semaphore: Option<Arc<Semaphore>>,
    branch_timeout: Option<Duration>,
    error_mode: ErrorMode,
}

impl fmt::Debug for ParallelChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParallelChain")
            .field("branches", &self.branches)
            .field("max_concurrency", &self.max_concurrency)
            .field("shared_semaphore", &self.semaphore.is_some())
            .field("branch_timeout", &self.branch_timeout)
            .field("error_mode", &self.error_mode)
            .finish()
    }
}

impl ParallelChain {
    /// An empty fan-out: unbounded concurrency, no timeouts, fail-fast.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a branch that runs `chain` and stores its answer under
    /// `output_key`; shorthand for `.with_branch(Branch::new(chain, output_key))`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_parallel::ParallelChain;
    /// use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs};
    /// use async_trait::async_trait;
    ///
    /// struct Noop;
    /// #[async_trait]
    /// impl Chain for Noop {
    ///     async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
    ///         Ok(GenerateResult::from_text(""))
    ///     }
    /// }
    ///
    /// let par = ParallelChain::new().branch(Noop, "a").branch(Noop, "b");
    /// assert_eq!(par.output_keys(), vec!["a", "b", "generate_result"]);
    /// ```
    #[must_use]
    pub fn branch(self, chain: impl Chain + 'static, output_key: impl Into<String>) -> Self {
        self.with_branch(Branch::new(chain, output_key))
    }

    /// Add a configured [`Branch`].
    #[must_use]
    pub fn with_branch(mut self, branch: Branch) -> Self {
        self.branches.push(branch);
        self
    }

    /// Run at most `limit` branches at once (values below 1 count as 1).
    #[must_use]
    pub const fn max_concurrency(mut self, limit: usize) -> Self {
        self.max_concurrency = Some(if limit == 0 { 1 } else { limit });
        self
    }

    /// Take a permit from `semaphore` for each running branch, so several
    /// chains can share one limit. Combines with
    /// [`max_concurrency`](Self::max_concurrency).
    #[must_use]
    pub fn with_semaphore(mut self, semaphore: Arc<Semaphore>) -> Self {
        self.semaphore = Some(semaphore);
        self
    }

    /// Default timeout for branches that do not set their own.
    #[must_use]
    pub const fn branch_timeout(mut self, limit: Duration) -> Self {
        self.branch_timeout = Some(limit);
        self
    }

    /// Choose between fail-fast (default) and collect-all error handling.
    #[must_use]
    pub const fn error_mode(mut self, mode: ErrorMode) -> Self {
        self.error_mode = mode;
        self
    }

    /// Check that every output key is non-empty, unique and not
    /// `"generate_result"`.
    ///
    /// # Errors
    ///
    /// [`ChainError::Other`] naming the offending key. Every run calls this
    /// first.
    pub fn validate(&self) -> Result<(), ChainError> {
        let mut seen = HashSet::with_capacity(self.branches.len());
        for b in &self.branches {
            let key = b.output_key.as_str();
            if key.is_empty() || key == RESULT_KEY {
                return Err(ChainError::Other(format!(
                    "parallel branch output key `{key}` is empty or reserved"
                )));
            }
            if !seen.insert(key) {
                return Err(ChainError::Other(format!(
                    "parallel branch output key `{key}` is used twice"
                )));
            }
        }
        Ok(())
    }

    /// Run every branch and report each outcome in declaration order.
    ///
    /// # Errors
    ///
    /// A [`validate`](Self::validate) error. In [`ErrorMode::FailFast`],
    /// also the first branch error (the other branches are cancelled); in
    /// [`ErrorMode::CollectAll`] branch errors are reported in the
    /// [`ParallelRun`] instead.
    pub async fn run(&self, input: PromptArgs) -> Result<ParallelRun, ChainError> {
        self.validate()?;
        let local = self.max_concurrency.map(Semaphore::new);
        let local = local.as_ref();
        let shared = self.semaphore.as_deref();

        let mut pending: FuturesUnordered<_> = self
            .branches
            .iter()
            .enumerate()
            .map(|(index, branch)| {
                let input = input.clone();
                async move {
                    let (result, elapsed) = match (acquire(local).await, acquire(shared).await) {
                        (Ok(_local), Ok(_shared)) => self.run_branch(branch, input).await,
                        (Err(e), _) | (_, Err(e)) => (Err(e), Duration::ZERO),
                    };
                    (index, result, elapsed)
                }
            })
            .collect();

        let mut done = Vec::with_capacity(self.branches.len());
        while let Some((index, result, elapsed)) = pending.next().await {
            let result = match (self.error_mode, result) {
                (ErrorMode::FailFast, Err(e)) => return Err(e),
                (_, result) => result,
            };
            done.push((index, result, elapsed));
        }
        done.sort_by_key(|(index, ..)| *index);
        let branches = done
            .into_iter()
            .map(|(index, result, elapsed)| BranchOutcome {
                output_key: self.branches[index].output_key.clone(),
                result,
                elapsed,
            })
            .collect();
        Ok(ParallelRun { branches })
    }

    async fn run_branch(
        &self,
        branch: &Branch,
        input: PromptArgs,
    ) -> (Result<GenerateResult, ChainError>, Duration) {
        let started = Instant::now();
        let call = branch.chain.call(input);
        let result = match branch.timeout.or(self.branch_timeout) {
            None => call.await,
            Some(limit) => tokio::time::timeout(limit, call).await.unwrap_or_else(|_| {
                Err(LlmError::timeout(format!(
                    "parallel branch `{}` took longer than {limit:?}",
                    branch.output_key
                ))
                .into())
            }),
        };
        (result, started.elapsed())
    }
}

async fn acquire(semaphore: Option<&Semaphore>) -> Result<Option<SemaphorePermit<'_>>, ChainError> {
    match semaphore {
        None => Ok(None),
        Some(s) => s
            .acquire()
            .await
            .map(Some)
            .map_err(|_| ChainError::Other("parallel concurrency semaphore was closed".into())),
    }
}

#[async_trait]
impl Chain for ParallelChain {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        Ok(self.run(input).await?.into_result()?.0)
    }

    async fn execute(&self, input: PromptArgs) -> Result<HashMap<String, Value>, ChainError> {
        let (result, mut map) = self.run(input).await?.into_result()?;
        // An empty fan-out still stores its (empty) answer under the
        // primary key, per the `Chain::execute` contract.
        map.entry(self.primary_output_key())
            .or_insert_with(|| Value::String(result.generation.clone()));
        map.insert(
            RESULT_KEY.to_string(),
            serde_json::to_value(&result)
                .map_err(|e| ChainError::Other(format!("result serialisation failed: {e}")))?,
        );
        Ok(map)
    }

    /// Every input key any branch reads, in branch order, without
    /// duplicates.
    fn input_keys(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.branches
            .iter()
            .flat_map(|b| b.chain.input_keys())
            .filter(|k| seen.insert(k.clone()))
            .collect()
    }

    fn output_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.branches.iter().map(|b| b.output_key.clone()).collect();
        keys.push(RESULT_KEY.to_string());
        keys
    }
}
