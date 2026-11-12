//! Resilience and routing for any [`Llm`]: retries with backoff, and a
//! multi-provider [`Router`] with circuit breakers.
//!
//! - [`RetryLlm`] retries one model on transient failures: exponential
//!   backoff with full jitter, a total time budget, a per-attempt timeout,
//!   provider retry-after hints, and error [classification](classify) so
//!   that rate limits, overload, 5xx and timeouts are retried while auth
//!   failures and invalid requests are not.
//! - [`Router`] puts N providers behind one [`Llm`] — a small, composable
//!   take on litellm's router. Strategies: ordered fallback, weighted
//!   random, round-robin, lowest latency (EWMA) and cheapest first (by
//!   [`Pricing`](rune_chain_core::Pricing)). Each provider has a circuit
//!   breaker (closed / open / half-open), a cooldown after rate limits, and
//!   optional context-window filtering.
//! - Streams are retried or re-routed only **before the first chunk**; the
//!   output of two providers is never spliced together.
//! - [`Event`]s report attempts, retries, fallbacks, skips and breaker
//!   changes to any observer registered with `on_event`.
//!
//! For a plain "try these models in order" without health tracking,
//! `rune_chain_core::LlmExt::with_fallbacks` is enough; the two compose
//! (`Arc<T>` implements [`Llm`], so one model can sit in several routers).
//!
//! # Quick Start
//!
//! ```rust
//! use std::time::Duration;
//! use rune_chain_retry::{Provider, RetryLlm, RetryPolicy, Router, Strategy};
//! use rune_chain_core::{Llm, Message};
//!
//! # async fn run() -> Result<(), rune_chain_core::LlmError> {
//! # struct MyLlm;
//! # use async_trait::async_trait;
//! # use rune_chain_core::{GenerateResult, LlmError};
//! # #[async_trait] impl Llm for MyLlm {
//! #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
//! #         Ok(GenerateResult::from_text("ok"))
//! #     }
//! # }
//! // Wrap any Llm with up to 3 retries, starting at 500ms backoff.
//! let llm = RetryLlm::new(MyLlm)
//!     .max_retries(3)
//!     .initial_delay_ms(500)
//!     .attempt_timeout(Duration::from_secs(60));
//! let result = llm.generate(&[Message::human("hello")]).await?;
//! # assert_eq!(result.generation, "ok");
//!
//! // Or route across providers, retrying each once before falling back.
//! let router = Router::new(Strategy::LowestLatency)
//!     .provider(Provider::new("a", MyLlm))
//!     .provider(Provider::new("b", MyLlm))
//!     .retry_policy(RetryPolicy::default().with_max_retries(1));
//! let result = router.generate(&[Message::human("hello")]).await?;
//! # assert_eq!(result.generation, "ok");
//! # Ok(())
//! # }
//! # tokio::runtime::Runtime::new().unwrap().block_on(run()).unwrap();
//! ```

#![warn(missing_docs)]

mod classify;
mod estimate;
mod event;
mod exec;
mod policy;
mod router;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rune_chain_core::{
    FunctionDefinition, GenerateResult, Llm, LlmError, Message, ResponseFormat, ToolChoice,
};

pub use classify::{ErrorClass, MAX_RETRY_AFTER_HINT, classify, retry_after};
pub use estimate::{IMAGE_TOKEN_ESTIMATE, estimate_tokens};
pub use event::{BreakerState, Event, Observer, SkipReason};
pub use exec::LlmStream;
pub use policy::{Jitter, RetryPolicy};
pub use router::{BreakerConfig, Provider, Router, Strategy};

use event::Observers;
use exec::{Classifier, Ctx, Output, Request};
use policy::Rng;

/// An [`Llm`] wrapper that retries transient failures with exponential
/// backoff.
///
/// Whether an error is retried is decided by [`classify`]
/// ([`ErrorClass::is_retryable`]): rate limits, overload, 5xx, timeouts,
/// network failures and unrecognised provider errors are; authentication,
/// invalid requests, context-length errors,
/// [`LlmError::invalid_response`], [`LlmError::unsupported`] and
/// [`LlmError::other`] are returned immediately.
///
/// Backoff follows [`RetryPolicy`] (by default 3 retries starting at 200 ms,
/// doubling, capped at 30 s, with full jitter). A retry-after hint in the
/// provider's message raises the wait to at least that hint.
///
/// [`stream`](Llm::stream) is retried until the first chunk arrives (the
/// stream is opened and its first item awaited before it is returned);
/// errors after that are passed through untouched.
pub struct RetryLlm<L> {
    inner: L,
    policy: RetryPolicy,
    name: Option<Arc<str>>,
    classifier: Classifier,
    observers: Observers,
    rng: Rng,
}

impl<L> fmt::Debug for RetryLlm<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryLlm")
            .field("policy", &self.policy)
            .field("name", &self.name)
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}

impl<L> RetryLlm<L> {
    /// Wrap `inner` with [`RetryPolicy::DEFAULT`]: 3 retries, 200 ms initial
    /// delay, 2× multiplier, 30 s cap, full jitter.
    pub const fn new(inner: L) -> Self {
        Self {
            inner,
            policy: RetryPolicy::DEFAULT,
            name: None,
            classifier: classify,
            observers: Observers::new(),
            rng: Rng::new(),
        }
    }

    /// The wrapped model.
    pub const fn inner(&self) -> &L {
        &self.inner
    }

    /// The current retry policy.
    pub const fn policy(&self) -> &RetryPolicy {
        &self.policy
    }

    /// Replace the whole retry policy.
    #[must_use]
    pub const fn with_policy(mut self, policy: RetryPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Maximum number of retry attempts (not counting the initial try).
    #[must_use]
    pub const fn max_retries(mut self, max_retries: u32) -> Self {
        self.policy.max_retries = max_retries;
        self
    }

    /// Initial backoff delay in milliseconds before the first retry.
    #[must_use]
    pub const fn initial_delay_ms(mut self, ms: u64) -> Self {
        self.policy.initial_delay = Duration::from_millis(ms);
        self
    }

    /// Backoff multiplier applied after each retry (default: 2.0).
    #[must_use]
    pub const fn multiplier(mut self, multiplier: f64) -> Self {
        self.policy.multiplier = multiplier;
        self
    }

    /// Upper bound on one backoff delay (default 30 s).
    #[must_use]
    pub const fn max_delay(mut self, d: Duration) -> Self {
        self.policy.max_delay = d;
        self
    }

    /// Delay randomisation (default [`Jitter::Full`]).
    #[must_use]
    pub const fn jitter(mut self, jitter: Jitter) -> Self {
        self.policy.jitter = jitter;
        self
    }

    /// Stop retrying once the next wait would end more than `d` after the
    /// first attempt started.
    #[must_use]
    pub const fn max_elapsed(mut self, d: Duration) -> Self {
        self.policy.max_elapsed = Some(d);
        self
    }

    /// Time limit for each attempt (for streams: until the first chunk).
    /// An attempt that runs over fails as an [`ErrorClass::Timeout`] and is
    /// retried.
    #[must_use]
    pub const fn attempt_timeout(mut self, d: Duration) -> Self {
        self.policy.attempt_timeout = Some(d);
        self
    }

    /// Name used for this model in [`Event`]s (default `"llm"`).
    #[must_use]
    pub fn name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Replace the error classifier (default: [`classify`]).
    #[must_use]
    pub const fn classifier(mut self, classifier: fn(&LlmError) -> ErrorClass) -> Self {
        self.classifier = classifier;
        self
    }

    /// Register an observer for [`Event`]s. Can be called more than once.
    #[must_use]
    pub fn on_event(mut self, observer: impl Fn(&Event) + Send + Sync + 'static) -> Self {
        let observer: Observer = Arc::new(observer);
        self.observers.push(observer);
        self
    }

    /// Seed the jitter source, for reproducible tests. Unseeded wrappers
    /// draw a random seed.
    #[must_use]
    pub fn seed(mut self, seed: u64) -> Self {
        self.rng = Rng::seeded(seed);
        self
    }
}

impl<L: Llm> RetryLlm<L> {
    async fn run(&self, req: Request<'_>) -> Result<Output, LlmError> {
        let name = self.name.clone().unwrap_or_else(|| Arc::from("llm"));
        let ctx = Ctx {
            name: &name,
            policy: &self.policy,
            rng: &self.rng,
            observers: &self.observers,
            classifier: self.classifier,
        };
        exec::run(&ctx, &self.inner, req)
            .await
            .map(|s| s.output)
            .map_err(|f| f.error)
    }
}

#[async_trait]
impl<L: Llm + Send + Sync> Llm for RetryLlm<L> {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.run(Request::Generate(messages)).await?.into_result()
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        self.run(Request::Tools(messages, tools, &tool_choice))
            .await?
            .into_result()
    }

    async fn stream(&self, messages: &[Message]) -> Result<LlmStream, LlmError> {
        self.run(Request::Stream(messages)).await?.into_stream()
    }

    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        self.run(Request::Structured(messages, format))
            .await?
            .into_result()
    }
}

#[cfg(test)]
mod tests {
    use rune_chain_core::LlmErrorKind;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use rune_chain_core::{GenerateResult, LlmError, Message};

    use super::*;

    struct FlakeyLlm {
        fail_count: Arc<Mutex<u32>>,
        fail_with: LlmError,
    }

    #[async_trait]
    impl rune_chain_core::Llm for FlakeyLlm {
        #[allow(
            clippy::significant_drop_tightening,
            reason = "the guard must outlive the values borrowed from it"
        )]
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            let mut count = self.fail_count.lock().unwrap();
            if *count > 0 {
                *count -= 1;
                return Err(self.fail_with.clone());
            }
            Ok(GenerateResult::from_text("ok"))
        }
    }

    #[tokio::test]
    async fn retries_request_failed_and_succeeds() {
        let fail_count = Arc::new(Mutex::new(2u32));
        let llm = RetryLlm::new(FlakeyLlm {
            fail_count: Arc::clone(&fail_count),
            fail_with: LlmError::request_failed("timeout"),
        })
        .max_retries(3)
        .initial_delay_ms(0);

        let result = llm.generate(&[]).await.unwrap();
        assert_eq!(result.generation, "ok");
        assert_eq!(*fail_count.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn does_not_retry_invalid_response() {
        let fail_count = Arc::new(Mutex::new(1u32));
        let llm = RetryLlm::new(FlakeyLlm {
            fail_count: Arc::clone(&fail_count),
            fail_with: LlmError::invalid_response("bad json"),
        })
        .max_retries(3)
        .initial_delay_ms(0);

        let err = llm.generate(&[]).await.unwrap_err();
        assert!(matches!(err, e if e.kind() == LlmErrorKind::InvalidResponse));
        assert_eq!(*fail_count.lock().unwrap(), 0);
    }
}
