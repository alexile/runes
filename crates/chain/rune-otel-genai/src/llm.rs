//! [`TracedLlm`]: an [`Llm`] wrapper that emits a `GenAI` span per call.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use async_trait::async_trait;
use futures::Stream;
use rune_chain_core::{
    EventStream, FinishReason, FunctionDefinition, GenerateResult, Llm, LlmError, Message,
    StreamData, StreamEvent, TokenUsage, ToolCall, ToolChoice,
};
use rune_chain_usage::estimate::{estimate_messages, estimate_tools};
use serde_json::json;
use tracing::{Instrument, Span};

use crate::content::ContentPolicy;
use crate::span::{
    GenAiConfig, assistant_json, llm_error_type, model_span, record_finish_reason, record_input,
    record_llm_error_with, record_result, record_tool_calls, record_usage, report_metrics,
    result_usage, token_usage,
};

/// Characters of streamed text buffered past the cap, so a secret cut at
/// the cap is still seen whole by the redactor.
const REDACT_SLACK: usize = 256;

/// Most tool calls traced per streamed reply, as in `StreamAccumulator`.
const MAX_TRACED_TOOL_CALLS: usize = 256;

/// Longest tool-call id or name kept, in characters. Real ones are short;
/// this only stops a hostile stream from growing the span.
const MAX_CALL_LABEL_CHARS: usize = 256;

type BoxStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;

/// Wraps an [`Llm`] so every call runs inside a client span following the
/// OpenTelemetry `GenAI` semantic conventions.
///
/// Each `generate`, `generate_with_tools`, `stream` and `stream_events`
/// call opens a span
/// named `{operation} {model}` (for example `chat claude-sonnet-4-6`) with
/// `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`
/// and the request settings from [`GenAiConfig`], then records:
///
/// - `gen_ai.usage.input_tokens` / `gen_ai.usage.output_tokens`: the
///   provider-reported usage, or a local estimate (flagged with
///   `rune.gen_ai.usage.estimated = true`) when the provider sent none,
///   which is always the case for `stream` (`stream_events` uses the
///   provider's [`StreamEvent::Usage`] when there is one);
/// - `rune.gen_ai.usage.cost_usd`, when [`GenAiConfig::pricing`] is set;
/// - `rune.gen_ai.response.tool_calls` and one `gen_ai.tool.call` event per
///   tool call the model asks for;
/// - `gen_ai.response.finish_reasons`, when the provider reported one;
/// - on failure, `error.type` (from [`LlmError::kind`]),
///   `http.response.status_code` (from [`LlmError::status`]) and an
///   `ERROR` span status;
/// - with content capture on ([`GenAiConfig::content`]), the input and
///   output messages, redacted and size-capped; tool-call arguments and
///   streamed text are only kept when it is on;
/// - with [`GenAiConfig::metrics`] set, the call's duration and token usage.
///
/// Spans of streams stay open until the stream ends, fails or is dropped.
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
                record_llm_error_with(span, e, &self.config.content);
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
                captured: Capture::default(),
                error_type: None,
                finished: false,
            })),
            Err(e) => Err(self.fail(&span, start, e)),
        }
    }

    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        let (span, start) = self.open(messages);
        let opened = self
            .inner
            .stream_events(messages, tools, tool_choice)
            .instrument(span.clone())
            .await;
        match opened {
            Ok(inner) => Ok(Box::pin(TracedEvents {
                inner,
                span,
                start,
                config: Arc::clone(&self.config),
                input_estimate: estimate_messages(messages)
                    .saturating_add(tools.map_or(0, estimate_tools)),
                output_chars: 0,
                text: Capture::default(),
                calls: Vec::new(),
                usage: None,
                finish: None,
                error_type: None,
                finished: false,
            })),
            Err(e) => Err(self.fail(&span, start, e)),
        }
    }
}

impl<L> TracedLlm<L> {
    /// Records a stream that failed to open.
    fn fail(&self, span: &Span, start: Instant, e: LlmError) -> LlmError {
        record_llm_error_with(span, &e, &self.config.content);
        report_metrics(&self.config, start, None, Some(llm_error_type(&e)));
        e
    }
}

/// A capped prefix of streamed text, kept only with content capture on.
#[derive(Default)]
struct Capture {
    text: String,
    chars: usize,
    cut: bool,
}

impl Capture {
    /// Keeps as much of `chunk` as fits under the policy's cap plus
    /// [`REDACT_SLACK`]; does nothing with capture off.
    fn push(&mut self, chunk: &str, policy: &ContentPolicy) {
        if !policy.is_enabled() || self.cut {
            return;
        }
        let room = policy
            .max_chars()
            .saturating_add(REDACT_SLACK)
            .saturating_sub(self.chars);
        let mut taken = 0;
        for c in chunk.chars() {
            if taken == room {
                self.cut = true;
                break;
            }
            self.text.push(c);
            taken += 1;
        }
        self.chars += taken;
    }
}

fn count_chars(total: &mut u64, text: &str) {
    *total = total.saturating_add(text.chars().count() as u64);
}

fn short_label(label: &str) -> String {
    label.chars().take(MAX_CALL_LABEL_CHARS).collect()
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
    captured: Capture,
    error_type: Option<&'static str>,
    finished: bool,
}

impl TracedStream {
    fn take(&mut self, chunk: &str) {
        count_chars(&mut self.output_chars, chunk);
        self.captured.push(chunk, &self.config.content);
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
            let text = policy.apply_cut(&self.captured.text, self.captured.cut);
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
                record_llm_error_with(&this.span, e, &this.config.content);
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

/// One streamed tool call: id and name always; arguments only with content
/// capture on.
struct TracedCall {
    index: usize,
    id: String,
    name: String,
    arguments: Capture,
}

/// Like [`TracedStream`] for [`StreamEvent`]s. On close the span gets the
/// provider's usage (or an estimate), the finish reason and the tool calls
/// by name; text and arguments are kept, capped, only with content capture
/// on.
struct TracedEvents {
    inner: EventStream,
    span: Span,
    start: Instant,
    config: Arc<GenAiConfig>,
    input_estimate: u64,
    output_chars: u64,
    text: Capture,
    calls: Vec<TracedCall>,
    usage: Option<TokenUsage>,
    finish: Option<FinishReason>,
    error_type: Option<&'static str>,
    finished: bool,
}

/// The call at `index`, added if new; `None` past [`MAX_TRACED_TOOL_CALLS`].
fn call_at(calls: &mut Vec<TracedCall>, index: usize) -> Option<&mut TracedCall> {
    // Calls usually arrive in order, so look from the back.
    if let Some(pos) = calls.iter().rposition(|c| c.index == index) {
        return Some(&mut calls[pos]);
    }
    if calls.len() >= MAX_TRACED_TOOL_CALLS {
        return None;
    }
    calls.push(TracedCall {
        index,
        id: String::new(),
        name: String::new(),
        arguments: Capture::default(),
    });
    calls.last_mut()
}

impl TracedEvents {
    fn take(&mut self, event: &StreamEvent) {
        match event {
            StreamEvent::TextDelta(text) => {
                count_chars(&mut self.output_chars, text);
                self.text.push(text, &self.config.content);
            }
            StreamEvent::ToolCallStart { index, id, name } => {
                count_chars(&mut self.output_chars, name);
                if let Some(call) = call_at(&mut self.calls, *index) {
                    if call.id.is_empty() {
                        call.id = short_label(id);
                    }
                    if call.name.is_empty() {
                        call.name = short_label(name);
                    }
                }
            }
            StreamEvent::ToolCallDelta {
                index,
                arguments_fragment,
            } => {
                count_chars(&mut self.output_chars, arguments_fragment);
                if let Some(call) = call_at(&mut self.calls, *index) {
                    call.arguments
                        .push(arguments_fragment, &self.config.content);
                }
            }
            StreamEvent::Usage(usage) => self.usage = Some(usage.clone()),
            StreamEvent::Finish(reason) => self.finish = Some(reason.clone()),
            _ => {}
        }
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let (usage, estimated) = self.usage.take().map_or_else(
            || {
                let output = self.output_chars.div_ceil(4);
                (token_usage(self.input_estimate, output), true)
            },
            |u| (u, false),
        );
        record_usage(&self.span, &usage, self.config.pricing.as_ref(), estimated);
        if let Some(reason) = &self.finish {
            record_finish_reason(&self.span, reason);
        }
        let policy = &self.config.content;
        let calls: Vec<ToolCall> = std::mem::take(&mut self.calls)
            .into_iter()
            .map(|c| ToolCall::new(c.id, c.name, c.arguments.text))
            .collect();
        record_tool_calls(&self.span, &calls);
        if policy.is_enabled() {
            let text = policy.apply_cut(&self.text.text, self.text.cut);
            self.span.record(
                "gen_ai.output.messages",
                json!([assistant_json(&text, &calls, self.finish.as_ref(), policy)]).to_string(),
            );
        }
        let usage = self.error_type.is_none().then_some((&usage, estimated));
        report_metrics(&self.config, self.start, usage, self.error_type);
    }
}

impl Stream for TracedEvents {
    type Item = Result<StreamEvent, LlmError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let polled = {
            let _entered = this.span.enter();
            this.inner.as_mut().poll_next(cx)
        };
        match &polled {
            Poll::Ready(Some(Ok(event))) => this.take(event),
            Poll::Ready(Some(Err(e))) => {
                record_llm_error_with(&this.span, e, &this.config.content);
                this.error_type = Some(llm_error_type(e));
            }
            Poll::Ready(None) => this.finish(),
            Poll::Pending => {}
        }
        polled
    }
}

impl Drop for TracedEvents {
    fn drop(&mut self) {
        self.finish();
    }
}
