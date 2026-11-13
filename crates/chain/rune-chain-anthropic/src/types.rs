//! Wire types of the Messages API. Crate-private; the public view of a
//! response is [`crate::MessageResponse`].

use rune_chain_core::{LlmError, LlmErrorKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{CacheControl, Effort, Fallbacks, Thinking};

// ── request ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct MessagesRequest {
    pub model: String,
    pub messages: Vec<ApiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemPrompt>,
    pub max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<AnthropicToolDef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<AnthropicToolChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<Thinking>,
    #[serde(skip_serializing_if = "OutputConfig::is_empty")]
    pub output_config: OutputConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallbacks: Option<Fallbacks>,
}

/// Body of `/v1/messages/count_tokens`: the request minus generation
/// settings.
#[derive(Debug, Serialize)]
pub struct CountTokensRequest<'a> {
    pub model: &'a str,
    pub messages: &'a [ApiMessage],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<&'a SystemPrompt>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub tools: &'a [AnthropicToolDef],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<&'a AnthropicToolChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<&'a Thinking>,
    #[serde(skip_serializing_if = "OutputConfig::is_empty")]
    pub output_config: &'a OutputConfig,
}

impl<'a> From<&'a MessagesRequest> for CountTokensRequest<'a> {
    fn from(r: &'a MessagesRequest) -> Self {
        Self {
            model: &r.model,
            messages: &r.messages,
            system: r.system.as_ref(),
            tools: &r.tools,
            tool_choice: r.tool_choice.as_ref(),
            thinking: r.thinking.as_ref(),
            output_config: &r.output_config,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CountTokensResponse {
    pub input_tokens: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct OutputConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effort: Option<Effort>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<OutputFormat>,
}

impl OutputConfig {
    pub const fn is_empty(&self) -> bool {
        self.effort.is_none() && self.format.is_none()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutputFormat {
    JsonSchema { schema: Value },
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum SystemPrompt {
    Text(String),
    Blocks(Vec<SystemBlock>),
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemBlock {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiMessage {
    pub role: &'static str,
    pub content: ApiMessageContent,
}

/// Content of an Anthropic API message — either a plain string or an array of
/// content blocks.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ApiMessageContent {
    Text(String),
    Blocks(Vec<ApiContentBlock>),
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApiContentBlock {
    /// An earlier turn's thinking, sent back verbatim with its signature.
    Thinking { thinking: String, signature: String },
    /// An earlier turn's redacted thinking, sent back verbatim.
    RedactedThinking { data: String },
    Text {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    Image {
        source: AnthropicImageSource,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
}

impl ApiContentBlock {
    pub const fn text(text: String) -> Self {
        Self::Text {
            text,
            cache_control: None,
        }
    }

    /// Set the block's breakpoint. Returns `false` for an empty text block,
    /// which the API does not accept as a breakpoint.
    pub const fn set_cache_control(&mut self, cc: CacheControl) -> bool {
        let slot = match self {
            // Thinking blocks cannot carry a breakpoint.
            Self::Thinking { .. } | Self::RedactedThinking { .. } => return false,
            Self::Text { text, .. } if text.is_empty() => return false,
            Self::Text { cache_control, .. }
            | Self::Image { cache_control, .. }
            | Self::ToolUse { cache_control, .. }
            | Self::ToolResult { cache_control, .. } => cache_control,
        };
        *slot = Some(cc);
        true
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AnthropicImageSource {
    Url { url: String },
    Base64 { media_type: String, data: String },
}

// ── function calling ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct AnthropicToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AnthropicToolChoice {
    Auto,
    Any,
    None,
    Tool { name: String },
}

// ── non-streaming response ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct MessagesResponse {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub model: String,
    pub content: Vec<ResponseContentBlock>,
    #[serde(default)]
    pub stop_reason: Option<String>,
    #[serde(default, deserialize_with = "lenient")]
    pub stop_details: Option<StopDetailsReport>,
    pub usage: UsageReport,
}

/// `stop_details` (set on a refusal). Every field is optional and unknown
/// ones are ignored.
#[derive(Debug, Default, Deserialize)]
pub struct StopDetailsReport {
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub explanation: Option<String>,
    #[serde(default)]
    pub recommended_model: Option<String>,
}

/// `{"model": …}` as used by the `from`/`to` fields of a fallback block.
#[derive(Debug, Default, Deserialize)]
pub struct ModelRef {
    #[serde(default)]
    pub model: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseContentBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        #[serde(default)]
        input: Value,
    },
    Thinking {
        #[serde(default)]
        thinking: String,
        #[serde(default)]
        signature: String,
    },
    RedactedThinking {
        #[serde(default)]
        data: String,
    },
    /// A server-side fallback switched models at this point.
    Fallback {
        #[serde(default, deserialize_with = "lenient_or_default")]
        from: ModelRef,
        #[serde(default, deserialize_with = "lenient_or_default")]
        to: ModelRef,
    },
    #[serde(other)]
    Unknown,
}

/// `usage` object. Every field is optional because `message_delta` events
/// carry only some of them; absent and `null` both read as "not reported".
#[derive(Debug, Default, Deserialize)]
pub struct UsageReport {
    #[serde(default)]
    pub input_tokens: Option<u32>,
    #[serde(default)]
    pub output_tokens: Option<u32>,
    #[serde(default)]
    pub cache_creation_input_tokens: Option<u32>,
    #[serde(default)]
    pub cache_read_input_tokens: Option<u32>,
    /// Per-attempt usage (`usage.iterations`), e.g. one entry per model
    /// tried when a fallback ran.
    #[serde(default, deserialize_with = "lenient_list")]
    pub iterations: Option<Vec<IterationReport>>,
}

/// One entry of `usage.iterations`. Unknown fields are ignored.
#[derive(Debug, Default, Deserialize)]
pub struct IterationReport {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub input_tokens: Option<u32>,
    #[serde(default)]
    pub output_tokens: Option<u32>,
    #[serde(default)]
    pub cache_creation_input_tokens: Option<u32>,
    #[serde(default)]
    pub cache_read_input_tokens: Option<u32>,
}

// ── streaming SSE events ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SseEvent {
    MessageStart {
        message: StreamMessageStart,
    },
    ContentBlockStart {
        index: usize,
        content_block: ResponseContentBlock,
    },
    ContentBlockDelta {
        index: usize,
        delta: Delta,
    },
    ContentBlockStop {
        index: usize,
    },
    MessageDelta {
        #[serde(default, deserialize_with = "null_as_default")]
        delta: MessageDeltaBody,
        #[serde(default, deserialize_with = "null_as_default")]
        usage: UsageReport,
    },
    MessageStop,
    Error {
        error: ApiError,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
pub struct StreamMessageStart {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub model: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub usage: UsageReport,
}

/// Read `null` as the type's default; some gateways send `null` for objects
/// the API itself would leave out.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Read an optional object, treating `null` or a value of the wrong shape
/// as absent, so a field this crate only reports never fails a response.
fn lenient<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).ok())
}

/// [`lenient`], falling back to the type's default.
fn lenient_or_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned + Default,
{
    Ok(lenient(deserializer)?.unwrap_or_default())
}

/// A list whose malformed entries are skipped; anything but an array reads
/// as absent.
fn lenient_list<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::Array(items) => Some(
            items
                .into_iter()
                .filter_map(|v| serde_json::from_value(v).ok())
                .collect(),
        ),
        _ => None,
    })
}

#[derive(Debug, Default, Deserialize)]
pub struct MessageDeltaBody {
    #[serde(default)]
    pub stop_reason: Option<String>,
    #[serde(default, deserialize_with = "lenient")]
    pub stop_details: Option<StopDetailsReport>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Delta {
    #[serde(rename = "text_delta")]
    Text { text: String },
    #[serde(rename = "input_json_delta")]
    InputJson { partial_json: String },
    #[serde(rename = "thinking_delta")]
    Thinking { thinking: String },
    #[serde(rename = "signature_delta")]
    Signature { signature: String },
    #[serde(other)]
    Other,
}

// ── error response ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub error: ApiError,
}

#[derive(Debug, Deserialize)]
pub struct ApiError {
    /// `error.type`: `rate_limit_error`, `overloaded_error`, …
    #[serde(rename = "type", default)]
    pub kind: String,
    pub message: String,
}

impl ApiError {
    /// Classify by `error.type` (and, for an over-long prompt, the
    /// wording); `None` when the type says nothing beyond the status.
    pub fn error_kind(&self) -> Option<LlmErrorKind> {
        let message = self.message.to_ascii_lowercase();
        if message.contains("prompt is too long")
            || message.contains("context window")
            || message.contains("context length")
        {
            return Some(LlmErrorKind::ContextLengthExceeded);
        }
        Some(match self.kind.as_str() {
            "rate_limit_error" => LlmErrorKind::RateLimit,
            "overloaded_error" => LlmErrorKind::Overloaded,
            "authentication_error" | "permission_error" | "billing_error" => LlmErrorKind::Auth,
            "invalid_request_error" | "not_found_error" | "request_too_large" => {
                LlmErrorKind::InvalidRequest
            }
            "timeout_error" => LlmErrorKind::Timeout,
            "api_error" => LlmErrorKind::Server,
            _ => return None,
        })
    }

    /// The portable error for an error object (no HTTP status).
    pub fn into_llm_error(self) -> LlmError {
        let kind = self.error_kind();
        let err = LlmError::provider(self.message);
        match kind {
            Some(kind) => err.with_kind(kind),
            None => err,
        }
    }
}
