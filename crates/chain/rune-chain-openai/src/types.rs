//! Wire types for `/chat/completions`. Request types are strict; response
//! types are lenient so OpenAI-compatible servers that omit optional fields
//! still decode.

use rune_chain_core::{FinishReason, LlmErrorKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── request ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ApiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// The modern field; rejected by some compatible servers, which take
    /// `max_tokens` instead (see [`MaxTokensField`](crate::MaxTokensField)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_options: Option<StreamOptions>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<OpenAiToolDef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<OpenAiToolChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ApiResponseFormat>,
}

#[derive(Debug, Serialize)]
pub struct StreamOptions {
    pub include_usage: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApiResponseFormat {
    JsonObject,
    JsonSchema { json_schema: JsonSchemaSpec },
}

#[derive(Debug, Serialize)]
pub struct JsonSchemaSpec {
    pub name: String,
    pub schema: Value,
    pub strict: bool,
}

#[derive(Debug, Serialize)]
pub struct ApiMessage {
    pub role: &'static str,
    pub content: Option<ApiMessageContent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ApiToolCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// Content of an `OpenAI` API message.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ApiMessageContent {
    Text(String),
    Parts(Vec<ApiContentPart>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApiContentPart {
    Text {
        text: String,
    },
    ImageUrl {
        image_url: ImageUrlContent,
    },
    /// Any other part type a server might return (audio, refusal, …).
    #[serde(other)]
    Other,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageUrlContent {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

// ── function calling ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct OpenAiToolDef {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub function: OpenAiFunctionDef,
}

#[derive(Debug, Serialize)]
pub struct OpenAiFunctionDef {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum OpenAiToolChoice {
    String(&'static str),
    Named(OpenAiNamedTool),
}

#[derive(Debug, Serialize)]
pub struct OpenAiNamedTool {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub function: OpenAiNamedFunction,
}

#[derive(Debug, Serialize)]
pub struct OpenAiNamedFunction {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct ApiToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub function: ApiFunctionCall,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiFunctionCall {
    pub name: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub arguments: String,
}

// ── non-streaming response ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ChatResponse {
    pub choices: Vec<Choice>,
    pub usage: Option<UsageReport>,
}

#[derive(Debug, Deserialize)]
pub struct Choice {
    pub message: ResponseMessage,
    #[serde(default)]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResponseMessage {
    #[allow(dead_code, reason = "required so a non-message object is rejected")]
    pub role: String,
    pub content: Option<ApiMessageContent>,
    pub refusal: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub tool_calls: Vec<ResponseToolCall>,
    /// Reasoning text from compatible servers: `reasoning_content`
    /// (`DeepSeek`, vLLM) or `reasoning` (`OpenRouter`, Ollama).
    #[serde(default, alias = "reasoning")]
    pub reasoning_content: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResponseToolCall {
    #[serde(default, deserialize_with = "null_as_default")]
    pub id: String,
    pub function: ApiFunctionCall,
}

/// Token usage; `total_tokens` is derived when a server omits it.
#[derive(Debug, Deserialize)]
pub struct UsageReport {
    #[serde(default, deserialize_with = "lenient_count")]
    pub prompt_tokens: u32,
    #[serde(default, deserialize_with = "lenient_count")]
    pub completion_tokens: u32,
    #[serde(default, deserialize_with = "lenient_count")]
    pub total_tokens: u32,
    #[serde(default)]
    pub prompt_tokens_details: Option<PromptTokensDetails>,
    #[serde(default)]
    pub completion_tokens_details: Option<CompletionTokensDetails>,
}

/// `usage.prompt_tokens_details`: the cached part of `prompt_tokens`.
#[derive(Debug, Default, Deserialize)]
pub struct PromptTokensDetails {
    #[serde(default, deserialize_with = "lenient_opt_count")]
    pub cached_tokens: Option<u32>,
}

/// `usage.completion_tokens_details`: the reasoning part of
/// `completion_tokens`.
#[derive(Debug, Default, Deserialize)]
pub struct CompletionTokensDetails {
    #[serde(default, deserialize_with = "lenient_opt_count")]
    pub reasoning_tokens: Option<u32>,
}

impl UsageReport {
    pub fn into_usage(self) -> rune_chain_core::TokenUsage {
        let total = if self.total_tokens == 0 {
            self.prompt_tokens.saturating_add(self.completion_tokens)
        } else {
            self.total_tokens
        };
        let cached = self
            .prompt_tokens_details
            .and_then(|d| d.cached_tokens)
            .unwrap_or(0);
        let reasoning = self
            .completion_tokens_details
            .and_then(|d| d.reasoning_tokens)
            .unwrap_or(0);
        rune_chain_core::TokenUsage::new(self.prompt_tokens, self.completion_tokens)
            .with_total_tokens(total)
            .with_cache_read_tokens(cached)
            .with_reasoning_tokens(reasoning)
    }
}

/// Map an `OpenAI` `finish_reason` onto the portable [`FinishReason`].
pub fn finish_reason(reason: &str) -> FinishReason {
    match reason {
        "function_call" => FinishReason::ToolCalls,
        other => FinishReason::from(other),
    }
}

// ── streaming response ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ChatChunk {
    #[serde(default, deserialize_with = "null_as_default")]
    pub choices: Vec<ChunkChoice>,
    pub usage: Option<UsageReport>,
    /// Groq reports streaming usage here instead of `usage`.
    pub x_groq: Option<XGroq>,
    /// Some servers send an error object as an event.
    pub error: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct XGroq {
    pub usage: Option<UsageReport>,
}

#[derive(Debug, Deserialize)]
pub struct ChunkChoice {
    #[serde(default, deserialize_with = "null_as_default")]
    pub index: u32,
    #[serde(default, deserialize_with = "null_as_default")]
    pub delta: Delta,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Delta {
    pub content: Option<String>,
    /// Reasoning text from compatible servers, as on [`ResponseMessage`].
    #[serde(default, alias = "reasoning")]
    pub reasoning_content: Option<String>,
    pub refusal: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub tool_calls: Vec<ToolCallDelta>,
}

#[derive(Debug, Deserialize)]
pub struct ToolCallDelta {
    pub index: Option<usize>,
    pub id: Option<String>,
    pub function: Option<FunctionDelta>,
}

#[derive(Debug, Deserialize)]
pub struct FunctionDelta {
    pub name: Option<String>,
    pub arguments: Option<String>,
}

fn null_as_default<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(de)?.unwrap_or_default())
}

/// A token count that tolerates what some servers send: `null` or a
/// non-number becomes `None`, negatives clamp to 0, huge values to
/// `u32::MAX`, and floats are truncated.
fn lenient_opt_count<'de, D>(de: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(de)?;
    let Value::Number(n) = value else {
        return Ok(None);
    };
    // Every count up to `u32::MAX` is exact as an f64.
    let f = n.as_f64().unwrap_or(0.0);
    let count = if f.is_nan() || f <= 0.0 {
        0
    } else if f >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "range checked above"
        )]
        let c = f as u32;
        c
    };
    Ok(Some(count))
}

/// Like [`lenient_opt_count`], with a missing value read as 0.
fn lenient_count<'de, D>(de: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(lenient_opt_count(de)?.unwrap_or(0))
}

// ── error response ────────────────────────────────────────────────────────────

/// Classify an error body by its `error.code` / `error.type` (and, for
/// context-window errors, the wording), when it says more than the status.
pub fn error_kind(value: &Value) -> Option<LlmErrorKind> {
    let err = value.get("error").unwrap_or(value);
    let field = |k: &str| err.get(k).and_then(Value::as_str).unwrap_or_default();
    let (code, kind) = (field("code"), field("type"));
    let message = error_message(value)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if code == "context_length_exceeded"
        || code == "string_above_max_length"
        || message.contains("maximum context length")
        || message.contains("context window")
    {
        return Some(LlmErrorKind::ContextLengthExceeded);
    }
    match (code, kind) {
        ("insufficient_quota" | "invalid_api_key", _)
        | (_, "insufficient_quota" | "authentication_error" | "permission_error") => {
            Some(LlmErrorKind::Auth)
        }
        ("rate_limit_exceeded", _) | (_, "rate_limit_error" | "tokens" | "requests") => {
            Some(LlmErrorKind::RateLimit)
        }
        (_, "server_error") => Some(LlmErrorKind::Server),
        (_, "overloaded_error") => Some(LlmErrorKind::Overloaded),
        _ => None,
    }
}

/// Extract a human-readable message from an error body. Understands
/// `{"error": {"message": …}}` (`OpenAI`, Azure), `{"error": "…"}` (LM
/// Studio, some proxies), `{"message": …}` (Mistral) and `{"detail": "…"}`
/// (FastAPI-based servers).
pub fn error_message(value: &Value) -> Option<String> {
    let text = |v: &Value| v.as_str().map(str::to_owned);
    let err = value.get("error");
    err.and_then(|e| e.get("message"))
        .and_then(text)
        .or_else(|| err.and_then(text))
        .or_else(|| value.get("message").and_then(text))
        .or_else(|| value.get("detail").and_then(text))
}
