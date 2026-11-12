//! Span constructors and recorders for `GenAI` operations.

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use rune_chain_core::{
    ContentPart, FinishReason, GenerateResult, LlmError, LlmErrorKind, Message, MessageContent,
    Pricing, Role, TokenUsage, ToolCall, ToolError,
};
use serde_json::{Value, json};
use tracing::Span;
use tracing::field::Empty;

use crate::attr::operation;
use crate::metrics::OperationMetrics;
use crate::{ContentPolicy, GenAiMetrics};

/// The `tracing` target every span and event of this crate uses, for
/// filtering (`RUST_LOG=rune_otel_genai=info`).
pub const TARGET: &str = "rune_otel_genai";

/// Describes the model calls a [`TracedLlm`](crate::TracedLlm) makes: who
/// serves them, which model, the request settings worth recording, and how
/// to price them.
///
/// # Examples
///
/// ```
/// use rune_chain_core::Pricing;
/// use rune_otel_genai::GenAiConfig;
///
/// let config = GenAiConfig::new("anthropic", "claude-sonnet-4-6")
///     .with_pricing(Pricing::per_mtok(3_000_000, 15_000_000))
///     .with_max_tokens(1024)
///     .with_temperature(0.2)
///     .with_server("api.anthropic.com", 443);
/// assert_eq!(config.model, "claude-sonnet-4-6");
/// assert!(!config.content.is_enabled()); // no prompts on spans unless asked
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct GenAiConfig {
    /// `gen_ai.provider.name`, such as `openai`, `anthropic` or `ollama`.
    pub provider: String,
    /// `gen_ai.request.model`.
    pub model: String,
    /// `gen_ai.operation.name`. Defaults to `chat`.
    pub operation: String,
    /// List prices, for `rune.gen_ai.usage.cost_usd`. No cost is recorded
    /// without them.
    pub pricing: Option<Pricing>,
    /// `gen_ai.request.max_tokens`.
    pub max_tokens: Option<u64>,
    /// `gen_ai.request.temperature`.
    pub temperature: Option<f64>,
    /// `gen_ai.request.top_p`.
    pub top_p: Option<f64>,
    /// `gen_ai.conversation.id`.
    pub conversation_id: Option<String>,
    /// `server.address`.
    pub server_address: Option<String>,
    /// `server.port`.
    pub server_port: Option<u16>,
    /// Whether prompts and completions (`gen_ai.input.messages`,
    /// `gen_ai.output.messages`) are recorded, redacted and capped. Off by
    /// default: they may hold personal or secret data.
    pub content: ContentPolicy,
    /// Where per-call duration and token metrics go, if anywhere.
    pub metrics: Option<Arc<dyn GenAiMetrics>>,
    /// Also emit the deprecated `gen_ai.system` attribute.
    pub legacy_system: bool,
}

impl fmt::Debug for GenAiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenAiConfig")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("operation", &self.operation)
            .field("pricing", &self.pricing)
            .field("max_tokens", &self.max_tokens)
            .field("temperature", &self.temperature)
            .field("top_p", &self.top_p)
            .field("conversation_id", &self.conversation_id)
            .field("server_address", &self.server_address)
            .field("server_port", &self.server_port)
            .field("content", &self.content)
            .field("metrics", &self.metrics.as_ref().map(|_| "GenAiMetrics"))
            .field("legacy_system", &self.legacy_system)
            .finish()
    }
}

impl GenAiConfig {
    /// A `chat` configuration for `model` served by `provider`.
    #[must_use]
    pub fn new(provider: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            operation: operation::CHAT.to_owned(),
            pricing: None,
            max_tokens: None,
            temperature: None,
            top_p: None,
            conversation_id: None,
            server_address: None,
            server_port: None,
            content: ContentPolicy::off(),
            metrics: None,
            legacy_system: false,
        }
    }

    /// Sets the operation name (default `chat`).
    #[must_use]
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = operation.into();
        self
    }

    /// Sets the prices used to compute each call's cost.
    #[must_use]
    pub const fn with_pricing(mut self, pricing: Pricing) -> Self {
        self.pricing = Some(pricing);
        self
    }

    /// Records the request's output token limit.
    #[must_use]
    pub const fn with_max_tokens(mut self, max_tokens: u64) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Records the request's sampling temperature.
    #[must_use]
    pub const fn with_temperature(mut self, temperature: f64) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Records the request's `top_p`.
    #[must_use]
    pub const fn with_top_p(mut self, top_p: f64) -> Self {
        self.top_p = Some(top_p);
        self
    }

    /// Records the conversation the calls belong to.
    #[must_use]
    pub fn with_conversation_id(mut self, id: impl Into<String>) -> Self {
        self.conversation_id = Some(id.into());
        self
    }

    /// Records the server the calls go to.
    #[must_use]
    pub fn with_server(mut self, address: impl Into<String>, port: u16) -> Self {
        self.server_address = Some(address.into());
        self.server_port = Some(port);
        self
    }

    /// Turns content capture on or off, with the current policy's caps and
    /// redaction (by default: 4096 characters per value, last 32 messages,
    /// no redaction).
    #[must_use]
    pub fn with_capture_content(mut self, capture: bool) -> Self {
        self.content = self.content.with_enabled(capture);
        self
    }

    /// Sets the full content policy: capture, size caps and redaction.
    #[must_use]
    pub fn with_content_policy(mut self, policy: ContentPolicy) -> Self {
        self.content = policy;
        self
    }

    /// Reports each call's duration and token usage to `metrics`, for
    /// example `OtelMetrics` (feature `opentelemetry`) or a closure.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<dyn GenAiMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Also emits the deprecated `gen_ai.system` attribute (same value as
    /// `gen_ai.provider.name`) for backends built on older conventions.
    #[must_use]
    pub const fn with_legacy_system(mut self, emit: bool) -> Self {
        self.legacy_system = emit;
        self
    }
}

/// Opens a client span for one model call, named `{operation} {model}`,
/// with every request attribute of `config` set.
///
/// Usage, cost and errors are recorded later with [`record_result`],
/// [`record_usage`] and [`record_error`]. [`TracedLlm`](crate::TracedLlm)
/// does all of this for you.
#[must_use]
pub fn model_span(config: &GenAiConfig) -> Span {
    let span = tracing::info_span!(
        target: TARGET,
        "gen_ai.client",
        otel.name = %format_args!("{} {}", config.operation, config.model),
        otel.kind = "client",
        otel.status_code = Empty,
        otel.status_description = Empty,
        gen_ai.operation.name = %config.operation,
        gen_ai.provider.name = %config.provider,
        gen_ai.system = Empty,
        gen_ai.request.model = %config.model,
        gen_ai.request.max_tokens = Empty,
        gen_ai.request.temperature = Empty,
        gen_ai.request.top_p = Empty,
        gen_ai.conversation.id = Empty,
        gen_ai.usage.input_tokens = Empty,
        gen_ai.usage.output_tokens = Empty,
        gen_ai.usage.cache_read.input_tokens = Empty,
        gen_ai.usage.cache_creation.input_tokens = Empty,
        gen_ai.usage.reasoning.output_tokens = Empty,
        gen_ai.response.finish_reasons = Empty,
        gen_ai.input.messages = Empty,
        gen_ai.output.messages = Empty,
        rune.gen_ai.usage.cost_usd = Empty,
        rune.gen_ai.usage.estimated = Empty,
        rune.gen_ai.response.tool_calls = Empty,
        error.type = Empty,
        http.response.status_code = Empty,
        server.address = Empty,
        server.port = Empty,
    );
    if config.legacy_system {
        span.record("gen_ai.system", config.provider.as_str());
    }
    if let Some(v) = config.max_tokens {
        span.record("gen_ai.request.max_tokens", v);
    }
    if let Some(v) = config.temperature {
        span.record("gen_ai.request.temperature", v);
    }
    if let Some(v) = config.top_p {
        span.record("gen_ai.request.top_p", v);
    }
    if let Some(v) = &config.conversation_id {
        span.record("gen_ai.conversation.id", v.as_str());
    }
    if let Some(v) = &config.server_address {
        span.record("server.address", v.as_str());
    }
    if let Some(v) = config.server_port {
        span.record("server.port", u64::from(v));
    }
    span
}

/// Records token counts and, with `pricing`, the cost on a model span.
/// `estimated` marks counts that are local estimates rather than
/// provider-reported.
///
/// Cache reads and writes (`gen_ai.usage.cache_read.input_tokens`,
/// `gen_ai.usage.cache_creation.input_tokens`) and reasoning tokens
/// (`gen_ai.usage.reasoning.output_tokens`) are recorded when non-zero; the
/// cost prices cache traffic at the cache rates.
pub fn record_usage(span: &Span, usage: &TokenUsage, pricing: Option<&Pricing>, estimated: bool) {
    span.record("gen_ai.usage.input_tokens", u64::from(usage.prompt_tokens));
    span.record(
        "gen_ai.usage.output_tokens",
        u64::from(usage.completion_tokens),
    );
    if usage.cache_read_tokens > 0 {
        span.record(
            "gen_ai.usage.cache_read.input_tokens",
            u64::from(usage.cache_read_tokens),
        );
    }
    if usage.cache_creation_tokens > 0 {
        span.record(
            "gen_ai.usage.cache_creation.input_tokens",
            u64::from(usage.cache_creation_tokens),
        );
    }
    if usage.reasoning_tokens > 0 {
        span.record(
            "gen_ai.usage.reasoning.output_tokens",
            u64::from(usage.reasoning_tokens),
        );
    }
    if let Some(pricing) = pricing {
        span.record("rune.gen_ai.usage.cost_usd", pricing.cost(usage).as_usd());
    }
    span.record("rune.gen_ai.usage.estimated", estimated);
}

/// Records the prompt on a model span, when content capture is on: the
/// last [`ContentPolicy::max_messages`] messages, each text redacted and
/// capped by the policy.
pub fn record_input(span: &Span, config: &GenAiConfig, messages: &[Message]) {
    let policy = &config.content;
    if policy.is_enabled() {
        let skip = messages.len().saturating_sub(policy.max_messages());
        let recorded = messages
            .iter()
            .skip(skip)
            .map(|m| message_json(m, policy))
            .collect();
        span.record("gen_ai.input.messages", Value::Array(recorded).to_string());
    }
}

/// Records a successful response on a model span.
///
/// That is: usage (provider-reported, or estimated from `input_estimate`
/// and the reply when the provider sent none), cost, the finish reason
/// (`gen_ai.response.finish_reasons`, when the provider reported one),
/// requested tool calls (as a count and one `gen_ai.tool.call` event each)
/// and, with content capture, the output message.
pub fn record_result(
    span: &Span,
    config: &GenAiConfig,
    result: &GenerateResult,
    input_estimate: u64,
) {
    let (usage, estimated) = result_usage(result, input_estimate);
    record_usage(span, &usage, config.pricing.as_ref(), estimated);
    if let Some(reason) = &result.finish_reason {
        span.record(
            "gen_ai.response.finish_reasons",
            semconv_finish_reason(reason),
        );
    }
    span.record(
        "rune.gen_ai.response.tool_calls",
        result.tool_calls.len() as u64,
    );
    span.in_scope(|| {
        for call in &result.tool_calls {
            // The message becomes the OpenTelemetry event name.
            tracing::event!(
                target: TARGET,
                tracing::Level::INFO,
                { gen_ai.tool.name = %call.name, gen_ai.tool.call.id = %call.id },
                "gen_ai.tool.call"
            );
        }
    });
    if config.content.is_enabled() {
        span.record(
            "gen_ai.output.messages",
            json!([assistant_json(
                &config.content.apply(&result.generation),
                &result.tool_calls,
                result.finish_reason.as_ref(),
                &config.content,
            )])
            .to_string(),
        );
    }
}

/// The usage a result reports, or an estimate (flagged `true`) when it
/// reports none.
pub fn result_usage(result: &GenerateResult, input_estimate: u64) -> (TokenUsage, bool) {
    result.tokens.as_ref().map_or_else(
        || {
            let output =
                rune_chain_usage::estimate::estimate_reply(&result.generation, &result.tool_calls);
            (token_usage(input_estimate, output), true)
        },
        |u| (u.clone(), false),
    )
}

/// Hands one finished call to the configured metrics sink, if any.
pub fn report_metrics(
    config: &GenAiConfig,
    start: Instant,
    usage: Option<(&TokenUsage, bool)>,
    error_type: Option<&str>,
) {
    if let Some(sink) = &config.metrics {
        sink.record(&OperationMetrics {
            operation: &config.operation,
            provider: &config.provider,
            request_model: &config.model,
            server_address: config.server_address.as_deref(),
            server_port: config.server_port,
            duration: start.elapsed(),
            input_tokens: usage.map(|(u, _)| u64::from(u.prompt_tokens)),
            output_tokens: usage.map(|(u, _)| u64::from(u.completion_tokens)),
            usage_estimated: usage.is_some_and(|(_, estimated)| estimated),
            error_type,
        });
    }
}

/// Builds a [`TokenUsage`] from 64-bit counts, saturating at `u32::MAX`.
pub fn token_usage(input: u64, output: u64) -> TokenUsage {
    let input = u32::try_from(input).unwrap_or(u32::MAX);
    let output = u32::try_from(output).unwrap_or(u32::MAX);
    TokenUsage::new(input, output).with_total_tokens(input.saturating_add(output))
}

/// Marks a span as failed: `error.type` (a low-cardinality class), the
/// OpenTelemetry status `ERROR` and its description.
pub fn record_error(span: &Span, error_type: &str, description: &str) {
    span.record("error.type", error_type);
    span.record("otel.status_code", "ERROR");
    span.record("otel.status_description", description);
}

/// Marks a model span as failed with an [`LlmError`]: `error.type` from
/// its [`kind`](LlmError::kind), `http.response.status_code` when the
/// provider answered with an HTTP error, and the `ERROR` status.
pub fn record_llm_error(span: &Span, error: &LlmError) {
    if let Some(status) = error.status() {
        span.record("http.response.status_code", u64::from(status));
    }
    record_error(span, llm_error_type(error), &error.to_string());
}

/// The `error.type` value for an [`LlmError`]: its [`LlmErrorKind`] in
/// snake case (`rate_limit`, `overloaded`, `context_length_exceeded`, …),
/// or `_OTHER` for a kind this crate does not know yet.
#[must_use]
pub const fn llm_error_type(error: &LlmError) -> &'static str {
    match error.kind() {
        LlmErrorKind::RateLimit => "rate_limit",
        LlmErrorKind::Overloaded => "overloaded",
        LlmErrorKind::Auth => "auth",
        LlmErrorKind::InvalidRequest => "invalid_request",
        LlmErrorKind::ContextLengthExceeded => "context_length_exceeded",
        LlmErrorKind::Timeout => "timeout",
        LlmErrorKind::Network => "network",
        LlmErrorKind::Server => "server",
        LlmErrorKind::InvalidResponse => "invalid_response",
        LlmErrorKind::Unsupported => "unsupported",
        LlmErrorKind::Provider => "provider_error",
        LlmErrorKind::Other => "other",
        _ => "_OTHER",
    }
}

/// The `GenAI` conventions' name for a [`FinishReason`]: `stop`, `length`,
/// `content_filter`, `tool_call`; anything else verbatim.
fn semconv_finish_reason(reason: &FinishReason) -> &str {
    match reason {
        FinishReason::ToolCalls => "tool_call",
        other => other.as_str(),
    }
}

/// The `error.type` value for a [`ToolError`].
#[must_use]
pub const fn tool_error_type(error: &ToolError) -> &'static str {
    match error {
        ToolError::InvalidInput(_) => "invalid_input",
        ToolError::ExecutionFailed(_) => "execution_failed",
        ToolError::Other(_) => "other",
    }
}

/// Opens an internal `execute_tool {name}` span for one tool execution.
///
/// `call_id` is the model-issued call identifier, when known.
#[must_use]
pub fn tool_span(name: &str, description: &str, call_id: Option<&str>) -> Span {
    let span = tracing::info_span!(
        target: TARGET,
        "gen_ai.execute_tool",
        otel.name = %format_args!("{} {name}", operation::EXECUTE_TOOL),
        otel.kind = "internal",
        otel.status_code = Empty,
        otel.status_description = Empty,
        gen_ai.operation.name = operation::EXECUTE_TOOL,
        gen_ai.tool.name = name,
        gen_ai.tool.description = description,
        gen_ai.tool.type = "function",
        gen_ai.tool.call.id = Empty,
        gen_ai.tool.call.arguments = Empty,
        gen_ai.tool.call.result = Empty,
        error.type = Empty,
    );
    if let Some(id) = call_id {
        span.record("gen_ai.tool.call.id", id);
    }
    span
}

/// Opens an internal `invoke_agent {name}` span around an agent run, for
/// agent loops (such as `rune-chain-agent`) to parent their model and
/// tool spans.
///
/// # Examples
///
/// ```
/// let span = rune_otel_genai::agent_span("researcher", Some("agent-7"), None);
/// let _entered = span.enter();
/// // ... run the agent loop: TracedLlm and TracedTool spans nest here ...
/// ```
#[must_use]
pub fn agent_span(name: &str, id: Option<&str>, description: Option<&str>) -> Span {
    let span = tracing::info_span!(
        target: TARGET,
        "gen_ai.invoke_agent",
        otel.name = %format_args!("{} {name}", operation::INVOKE_AGENT),
        otel.kind = "internal",
        otel.status_code = Empty,
        otel.status_description = Empty,
        gen_ai.operation.name = operation::INVOKE_AGENT,
        gen_ai.agent.name = name,
        gen_ai.agent.id = Empty,
        gen_ai.agent.description = Empty,
        error.type = Empty,
    );
    if let Some(id) = id {
        span.record("gen_ai.agent.id", id);
    }
    if let Some(d) = description {
        span.record("gen_ai.agent.description", d);
    }
    span
}

/// Semantic-convention role for a message.
const fn role_name(role: &Role) -> &'static str {
    match role {
        Role::System => "system",
        Role::Human => "user",
        Role::Ai => "assistant",
        Role::Tool => "tool",
    }
}

fn content_parts(content: &MessageContent, policy: &ContentPolicy) -> Vec<Value> {
    match content {
        MessageContent::Text(t) => vec![json!({"type": "text", "content": policy.apply(t)})],
        MessageContent::Parts(parts) => parts
            .iter()
            .map(|p| match p {
                ContentPart::Text { text } => {
                    json!({"type": "text", "content": policy.apply(text)})
                }
                // Image payloads can be large and are not useful in a span.
                ContentPart::Image { .. } => json!({"type": "image"}),
            })
            .collect(),
    }
}

fn tool_call_part(call: &ToolCall, policy: &ContentPolicy) -> Value {
    let recorded = policy.apply(&call.arguments);
    let arguments = serde_json::from_str::<Value>(&recorded).unwrap_or(Value::String(recorded));
    json!({"type": "tool_call", "id": call.id, "name": call.name, "arguments": arguments})
}

/// A chat message in the semantic-convention message shape.
fn message_json(message: &Message, policy: &ContentPolicy) -> Value {
    let mut parts = if message.role == Role::Tool {
        vec![json!({
            "type": "tool_call_response",
            "id": message.tool_call_id,
            "response": policy.apply(&message.content.text_content()),
        })]
    } else {
        content_parts(&message.content, policy)
    };
    parts.extend(message.tool_calls.iter().map(|c| tool_call_part(c, policy)));
    json!({"role": role_name(&message.role), "parts": parts})
}

/// The assistant reply in the semantic-convention shape. `text` must
/// already have been through the policy.
pub fn assistant_json(
    text: &str,
    tool_calls: &[ToolCall],
    reason: Option<&FinishReason>,
    policy: &ContentPolicy,
) -> Value {
    let mut parts = Vec::new();
    if !text.is_empty() {
        parts.push(json!({"type": "text", "content": text}));
    }
    parts.extend(tool_calls.iter().map(|c| tool_call_part(c, policy)));
    let finish = match reason {
        Some(reason) => semconv_finish_reason(reason),
        None if tool_calls.is_empty() => "stop",
        None => "tool_call",
    };
    json!({"role": "assistant", "parts": parts, "finish_reason": finish})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_follow_the_semconv_shape() {
        let call = ToolCall::new("c1", "add", r#"{"a":1}"#);
        let messages = [
            Message::system("be brief"),
            Message::human("hi"),
            Message::ai_with_tool_calls("", vec![call.clone()]),
            Message::tool_result("c1", "2"),
        ];
        let policy = ContentPolicy::capture();
        let v: Vec<Value> = messages.iter().map(|m| message_json(m, &policy)).collect();
        assert_eq!(v[0]["role"], "system");
        assert_eq!(
            v[1],
            json!({"role": "user", "parts": [{"type": "text", "content": "hi"}]})
        );
        assert_eq!(v[2]["parts"][1]["arguments"], json!({"a": 1}));
        assert_eq!(
            v[3]["parts"][0],
            json!({"type": "tool_call_response", "id": "c1", "response": "2"})
        );
        let out = assistant_json("", &[call], None, &policy);
        assert_eq!(out["finish_reason"], "tool_call");
        assert_eq!(out["parts"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            assistant_json("ok", &[], None, &policy)["finish_reason"],
            "stop"
        );
        assert_eq!(
            assistant_json("ok", &[], Some(&FinishReason::Length), &policy)["finish_reason"],
            "length"
        );
    }

    #[test]
    fn error_types_are_low_cardinality() {
        assert_eq!(llm_error_type(&LlmError::request_failed("x")), "network");
        assert_eq!(
            llm_error_type(&LlmError::from_status(429, "x")),
            "rate_limit"
        );
        assert_eq!(
            llm_error_type(&LlmError::from_status(529, "x")),
            "overloaded"
        );
        assert_eq!(llm_error_type(&LlmError::other("x")), "other");
        assert_eq!(
            tool_error_type(&ToolError::InvalidInput("x".into())),
            "invalid_input"
        );
    }

    #[test]
    fn token_usage_saturates() {
        let u = token_usage(u64::MAX, 5);
        assert_eq!(u.prompt_tokens, u32::MAX);
        assert_eq!(u.total_tokens, u32::MAX);
        assert_eq!(token_usage(2, 3).total_tokens, 5);
    }
}
