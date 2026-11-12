//! [`TracedLlm`]: an [`Llm`] wrapper that emits a `GenAI` span per call.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use async_trait::async_trait;
use futures::Stream;
use rune_chain_core::{
    FunctionDefinition, GenerateResult, Llm, LlmError, Message, StreamData, ToolChoice,
};
use rune_chain_usage::estimate::{estimate_messages, estimate_tools};
use serde_json::json;
use tracing::{Instrument, Span};

use crate::span::{
    GenAiConfig, assistant_json, llm_error_type, model_span, record_input, record_llm_error,
    record_result, record_usage, report_metrics, result_usage, token_usage,
};

/// Characters of streamed text buffered past the cap, so a secret cut at
/// the cap is still seen whole by the redactor.
const REDACT_SLACK: usize = 256;

type BoxStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;

/// Wraps an [`Llm`] so every call runs inside a client span following the
/// OpenTelemetry `GenAI` semantic conventions.
///
/// Each `generate`, `generate_with_tools` and `stream` call opens a span
/// named `{operation} {model}` (for example `chat claude-sonnet-4-6`) with
/// `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`
/// and the request settings from [`GenAiConfig`], then records:
///
/// - `gen_ai.usage.input_tokens` / `gen_ai.usage.output_tokens`: the
///   provider-reported usage, or a local estimate (flagged with
///   `rune.gen_ai.usage.estimated = true`) when the provider sent none,
///   which is always the case for streams;
/// - `rune.gen_ai.usage.cost_usd`, when [`GenAiConfig::pricing`] is set;
/// - `rune.gen_ai.response.tool_calls` and one `gen_ai.tool.call` event per
///   tool call the model asks for;
/// - `gen_ai.response.finish_reasons`, when the provider reported one;
/// - on failure, `error.type` (from [`LlmError::kind`]),
///   `http.response.status_code` (from [`LlmError::status`]) and an
///   `ERROR` span status;
/// - with content capture on ([`GenAiConfig::content`]), the input and
///   output messages, redacted and size-capped;
/// - with [`GenAiConfig::metrics`] set, the call's duration and token usage.
///
/// The spans are ordinary `tracing` spans (target
/// [`TARGET`](crate::TARGET)). Install `rune-telemetry` with its `otlp`
/// feature, or any `tracing-opentelemetry` layer, to export them; the
/// `otel.*` fields set the OpenTelemetry span name, kind and status.
///
/// # Examples
///
/// ```
/// use async_trait::async_trait;
/// use rune_chain_core::{GenerateResult, Llm, LlmError, Message, Pricing, TokenUsage};
/// use rune_otel_genai::{GenAiConfig, TracedLlm};
///
/// struct Echo;
/// #[async_trait]
/// impl Llm for Echo {
///     async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
///         let mut r = GenerateResult::from_text(messages[0].content.text_content());
///         r.tokens = Some(TokenUsage::new(3, 2).with_total_tokens(5));
///         Ok(r)
///     }
/// }
///
/// let llm = TracedLlm::new(
///     Echo,
///     GenAiConfig::new("acme", "echo-1").with_pricing(Pricing::per_mtok(1_000_000, 2_000_000)),
/// );
/// let reply = tokio_test::block_on(llm.generate(&[Message::human("hi")]))?;
/// assert_eq!(reply.generation, "hi");
/// # Ok::<(), LlmError>(())
/// ```
#[derive(Debug, Clone)]
pub struct TracedLlm<L> {
    inner: L,
    config: Arc<GenAiConfig>,
}

impl<L: Llm> TracedLlm<L> {
    /// Traces `inner`'s calls as described by `config`.
    pub fn new(inner: L, config: GenAiConfig) -> Self {
        Self {
            inner,
            config: Arc::new(config),
        }
    }

    /// The span configuration.
    #[must_use]
    pub fn config(&self) -> &GenAiConfig {
        &self.config
    }

    /// The wrapped LLM.
    #[must_use]
    pub const fn inner(&self) -> &L {
        &self.inner
    }

    /// Unwraps, returning the inner LLM.
    pub fn into_inner(self) -> L {
        self.inner
    }

    fn open(&self, messages: &[Message]) -> (Span, Instant) {
        let span = model_span(&self.config);
        record_input(&span, &self.config, messages);
        (span, Instant::now())
    }

    fn settle(
        &self,
        span: &Span,
        start: Instant,
        input_estimate: u64,
        result: Result<GenerateResult, LlmError>,
    ) -> Result<GenerateResult, LlmError> {
        match &result {
            Ok(r) => {
                record_result(span, &self.config, r, input_estimate);
                let (usage, estimated) = result_usage(r, input_estimate);
                report_metrics(&self.config, start, Some((&usage, estimated)), None);
            }
            Err(e) => {
                record_llm_error(span, e);
                report_metrics(&self.config, start, None, Some(llm_error_type(e)));
            }
        }
        result
    }
}

#[async_trait]
impl<L: Llm> Llm for TracedLlm<L> {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        let (span, start) = self.open(messages);
        let result = self.inner.generate(messages).instrument(span.clone()).await;
        self.settle(&span, start, estimate_messages(messages), result)
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        let (span, start) = self.open(messages);
        let result = self
            .inner
            .generate_with_tools(messages, tools, tool_choice)
            .instrument(span.clone())
            .await;
        let input = estimate_messages(messages).saturating_add(estimate_tools(tools));
        self.settle(&span, start, input, result)
    }

    async fn stream(&self, messages: &[Message]) -> Result<BoxStream, LlmError> {
        let (span, start) = self.open(messages);
        match self.inner.stream(messages).instrument(span.clone()).await {
            Ok(inner) => Ok(Box::pin(TracedStream {
                inner,
                span,
                start,
                config: Arc::clone(&self.config),
                input_estimate: estimate_messages(messages),
                output_chars: 0,
                captured: String::new(),
                captured_chars: 0,
                cut: false,
                error_type: None,
                finished: false,
            })),
            Err(e) => {
                record_llm_error(&span, &e);
                report_metrics(&self.config, start, None, Some(llm_error_type(&e)));
                Err(e)
            }
        }
    }
}

/// A stream that keeps its model span open until the stream ends or is
/// dropped, then records estimated usage.
///
/// Memory stays bounded: only a character count is kept, plus, with content
/// capture on, at most the policy's cap (and a little slack for redaction)
/// of the text.
struct TracedStream {
    inner: BoxStream,
    span: Span,
    start: Instant,
    config: Arc<GenAiConfig>,
    input_estimate: u64,
    output_chars: u64,
    captured: String,
    captured_chars: usize,
    cut: bool,
    error_type: Option<&'static str>,
    finished: bool,
}

impl TracedStream {
    fn take(&mut self, chunk: &str) {
        self.output_chars = self
            .output_chars
            .saturating_add(chunk.chars().count() as u64);
        let policy = &self.config.content;
        if !policy.is_enabled() || self.cut {
            return;
        }
        let room = policy
            .max_chars()
            .saturating_add(REDACT_SLACK)
            .saturating_sub(self.captured_chars);
        let mut taken = 0;
        for c in chunk.chars() {
            if taken == room {
                self.cut = true;
                break;
            }
            self.captured.push(c);
            taken += 1;
        }
        self.captured_chars += taken;
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let usage = token_usage(self.input_estimate, self.output_chars.div_ceil(4));
        record_usage(&self.span, &usage, self.config.pricing.as_ref(), true);
        self.span.record("rune.gen_ai.response.tool_calls", 0_u64);
        let policy = &self.config.content;
        if policy.is_enabled() {
            let text = policy.apply_cut(&self.captured, self.cut);
            self.span.record(
                "gen_ai.output.messages",
                json!([assistant_json(&text, &[], None, policy)]).to_string(),
            );
        }
        let usage = self.error_type.is_none().then_some((&usage, true));
        report_metrics(&self.config, self.start, usage, self.error_type);
    }
}

impl Stream for TracedStream {
    type Item = Result<StreamData, LlmError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let polled = {
            let _entered = this.span.enter();
            this.inner.as_mut().poll_next(cx)
        };
        match &polled {
            Poll::Ready(Some(Ok(chunk))) => {
                this.take(&chunk.content);
                if chunk.is_finished {
                    this.finish();
                }
            }
            Poll::Ready(Some(Err(e))) => {
                record_llm_error(&this.span, e);
                this.error_type = Some(llm_error_type(e));
            }
            Poll::Ready(None) => this.finish(),
            Poll::Pending => {}
        }
        polled
    }
}

impl Drop for TracedStream {
    fn drop(&mut self) {
        // A stream dropped early still reports what it consumed.
        self.finish();
    }
}
