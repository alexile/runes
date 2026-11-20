//! Timeouts and simple retries (feature `tokio`).
//!
//! These are deliberately small. For jitter, time budgets, error
//! classification of untyped provider errors, routing and circuit breakers,
//! use a dedicated retry layer such as `rune-chain-retry`.

use std::{collections::HashMap, fmt, time::Duration};

use async_trait::async_trait;
use serde_json::Value;

use crate::{
    Chain, ChainError, EventStream, FunctionDefinition, GenerateResult, Llm, LlmError, Message,
    PromptArgs, ResponseFormat, ToolChoice,
    ext::{ChainStream, LlmStream},
};

/// A model or chain whose calls fail with a timeout error after a fixed
/// time; built by `.with_timeout(…)` on [`LlmExt`](crate::LlmExt) or
/// [`ChainExt`](crate::ChainExt).
///
/// The error is [`LlmError::timeout`] (wrapped in [`ChainError::LlmError`]
/// for chains), so retry layers treat it as transient. For streams the limit
/// covers opening the stream, not reading it.
pub struct WithTimeout<T> {
    inner: T,
    limit: Duration,
}

impl<T> WithTimeout<T> {
    pub(crate) const fn new(inner: T, limit: Duration) -> Self {
        Self { inner, limit }
    }

    fn error(&self) -> LlmError {
        LlmError::timeout(format!("no response within {:?}", self.limit))
    }

    async fn run<R, E: From<LlmError>>(
        &self,
        fut: impl Future<Output = Result<R, E>> + Send,
    ) -> Result<R, E>
    where
        T: Sync,
    {
        tokio::time::timeout(self.limit, fut)
            .await
            .unwrap_or_else(|_| Err(self.error().into()))
    }
}

impl<T> fmt::Debug for WithTimeout<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WithTimeout")
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<L: Llm> Llm for WithTimeout<L> {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.run(self.inner.generate(messages)).await
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        self.run(self.inner.generate_with_tools(messages, tools, tool_choice))
            .await
    }

    async fn stream(&self, messages: &[Message]) -> Result<LlmStream, LlmError> {
        self.run(self.inner.stream(messages)).await
    }

    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        self.run(self.inner.stream_events(messages, tools, tool_choice))
            .await
    }

    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        self.run(self.inner.generate_structured(messages, format))
            .await
    }
}

#[async_trait]
impl<C: Chain> Chain for WithTimeout<C> {
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        self.run(self.inner.call(input_variables)).await
    }

    async fn execute(
        &self,
        input_variables: PromptArgs,
    ) -> Result<HashMap<String, Value>, ChainError> {
        self.run(self.inner.execute(input_variables)).await
    }

    async fn stream(&self, input_variables: PromptArgs) -> Result<ChainStream, ChainError> {
        self.run(self.inner.stream(input_variables)).await
    }

    fn input_keys(&self) -> Vec<String> {
        self.inner.input_keys()
    }

    fn output_keys(&self) -> Vec<String> {
        self.inner.output_keys()
    }

    fn primary_output_key(&self) -> String {
        self.inner.primary_output_key()
    }
}

/// Longest provider retry-after hint [`WithRetry`] will wait for. A longer
/// hint returns the error instead of sleeping.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// A model or chain that retries transient failures with exponential
/// backoff; built by `.with_retry(n)` on [`LlmExt`](crate::LlmExt) or
/// [`ChainExt`](crate::ChainExt).
///
/// Only errors with [`LlmError::is_retryable`] are retried (rate limits,
/// overload, timeouts, network and 5xx errors); for chains that means
/// [`ChainError::LlmError`] with such an error. The wait before retry `k`
/// (from 0) is `initial_delay × 2^k`, capped at `max_delay`, and never less
/// than the provider's [`retry_after`](LlmError::retry_after) hint. A hint
/// above [`MAX_RETRY_AFTER`] ends the retries. Streams are retried only
/// while opening.
pub struct WithRetry<T> {
    inner: T,
    max_retries: u32,
    initial_delay: Duration,
    max_delay: Duration,
}

impl<T> WithRetry<T> {
    pub(crate) const fn new(inner: T, max_retries: u32) -> Self {
        Self {
            inner,
            max_retries,
            initial_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(10),
        }
    }

    /// The wait before the first retry (default 200 ms).
    #[must_use]
    pub const fn initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// The longest backoff between attempts (default 10 s).
    #[must_use]
    pub const fn max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// How long to wait before retry number `retry` (from 0) after `error`,
    /// or `None` to give up.
    fn delay(&self, retry: u32, error: &LlmError) -> Option<Duration> {
        if retry >= self.max_retries || !error.is_retryable() {
            return None;
        }
        let factor = 1u32.checked_shl(retry.min(30)).unwrap_or(u32::MAX);
        let backoff = self
            .initial_delay
            .saturating_mul(factor)
            .min(self.max_delay);
        match error.retry_after() {
            Some(hint) if hint > MAX_RETRY_AFTER => None,
            Some(hint) => Some(backoff.max(hint)),
            None => Some(backoff),
        }
    }

    async fn run<R, E, F, Fut>(
        &self,
        mut attempt: F,
        as_llm: fn(&E) -> Option<&LlmError>,
    ) -> Result<R, E>
    where
        F: FnMut() -> Fut + Send,
        Fut: Future<Output = Result<R, E>> + Send,
        R: Send,
        E: Send,
        T: Sync,
    {
        let mut retry = 0;
        loop {
            let err = match attempt().await {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            match as_llm(&err).and_then(|e| self.delay(retry, e)) {
                Some(wait) => tokio::time::sleep(wait).await,
                None => return Err(err),
            }
            retry += 1;
        }
    }
}

impl<T> fmt::Debug for WithRetry<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WithRetry")
            .field("max_retries", &self.max_retries)
            .field("initial_delay", &self.initial_delay)
            .field("max_delay", &self.max_delay)
            .finish_non_exhaustive()
    }
}

#[allow(clippy::unnecessary_wraps)] // must match `chain_llm_error`
const fn llm_error(e: &LlmError) -> Option<&LlmError> {
    Some(e)
}

const fn chain_llm_error(e: &ChainError) -> Option<&LlmError> {
    match e {
        ChainError::LlmError(e) => Some(e),
        _ => None,
    }
}

#[async_trait]
impl<L: Llm> Llm for WithRetry<L> {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.run(|| self.inner.generate(messages), llm_error).await
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        self.run(
            || {
                self.inner
                    .generate_with_tools(messages, tools, tool_choice.clone())
            },
            llm_error,
        )
        .await
    }

    async fn stream(&self, messages: &[Message]) -> Result<LlmStream, LlmError> {
        self.run(|| self.inner.stream(messages), llm_error).await
    }

    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        self.run(
            || {
                self.inner
                    .stream_events(messages, tools, tool_choice.clone())
            },
            llm_error,
        )
        .await
    }

    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        self.run(
            || self.inner.generate_structured(messages, format),
            llm_error,
        )
        .await
    }
}

#[async_trait]
impl<C: Chain> Chain for WithRetry<C> {
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        self.run(|| self.inner.call(input_variables.clone()), chain_llm_error)
            .await
    }

    async fn execute(
        &self,
        input_variables: PromptArgs,
    ) -> Result<HashMap<String, Value>, ChainError> {
        self.run(
            || self.inner.execute(input_variables.clone()),
            chain_llm_error,
        )
        .await
    }

    async fn stream(&self, input_variables: PromptArgs) -> Result<ChainStream, ChainError> {
        self.run(
            || self.inner.stream(input_variables.clone()),
            chain_llm_error,
        )
        .await
    }

    fn input_keys(&self) -> Vec<String> {
        self.inner.input_keys()
    }

    fn output_keys(&self) -> Vec<String> {
        self.inner.output_keys()
    }

    fn primary_output_key(&self) -> String {
        self.inner.primary_output_key()
    }
}
