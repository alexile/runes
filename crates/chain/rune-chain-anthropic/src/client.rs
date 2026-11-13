use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use reqwest::header::{CONTENT_TYPE, HeaderValue};
use rune_chain_core::{
    ContentPart, FunctionDefinition, GenerateResult, ImageData, LlmError, Message, MessageContent,
    ResponseFormat, Role, StreamData, ToolChoice,
};
use serde::Serialize;
use serde_json::Value;

use crate::config::{CachePolicy, CacheTtl, Effort, StructuredOutput, Thinking};
use crate::http::{self, ApiKey};
use crate::models::{self, ModelInfo};
use crate::response::{ContentBlock, MessageResponse};
use crate::stream::{DEFAULT_MAX_STREAM_BYTES, MessageAccumulator, StreamEvent};
use crate::types::{
    AnthropicImageSource, AnthropicToolChoice, AnthropicToolDef, ApiContentBlock, ApiMessage,
    ApiMessageContent, CountTokensRequest, CountTokensResponse, MessagesRequest, MessagesResponse,
    OutputConfig, OutputFormat, SystemBlock, SystemPrompt,
};

#[cfg(test)]
mod tests;

/// Default API origin; see [`Anthropic::base_url`].
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const MESSAGES_PATH: &str = "/v1/messages";
const COUNT_TOKENS_PATH: &str = "/v1/messages/count_tokens";
const ANTHROPIC_VERSION: &str = "2023-06-01";
/// Default `max_tokens` for blocking requests (`generate*`), sized so that a
/// response finishes well inside HTTP timeouts while leaving thinking models
/// room to reason before they answer.
pub const DEFAULT_MAX_TOKENS: u32 = 16_000;
/// Default `max_tokens` for streaming requests, where timeouts are not a
/// concern.
pub const DEFAULT_STREAM_MAX_TOKENS: u32 = 64_000;
/// Default number of retries after a retryable failure (HTTP 408, 409, 429,
/// 5xx including 529 overloaded, or a connection error).
pub const DEFAULT_MAX_RETRIES: u32 = 2;
/// Default total timeout of a blocking request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
/// Default connect timeout of the built-in HTTP client.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default cap on a blocking response body.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 << 20;

/// Name of the tool used by [`StructuredOutput::ForcedTool`] for a
/// [`ResponseFormat::JsonObject`].
const JSON_OBJECT_TOOL: &str = "json_response";

/// Boxed stream returned by [`Anthropic::stream_message`].
pub type MessageStream = Pin<Box<dyn Stream<Item = Result<StreamEvent, LlmError>> + Send>>;

/// Anthropic Claude client implementing [`Llm`](rune_chain_core::Llm).
///
/// Talks to any Claude model via the `/v1/messages` endpoint with blocking
/// generation, streaming, native function/tool calling and native
/// structured output. The model is a free-form id (default
/// [`models::DEFAULT_MODEL`], `claude-sonnet-5-5`); see [`models`] for
/// constants and per-model capability notes.
///
/// # Quick start
///
/// ```rust,no_run
/// use rune_chain_anthropic::Anthropic;
/// use rune_chain_core::{Llm, Message};
///
/// # tokio_test::block_on(async {
/// let llm = Anthropic::from_env().unwrap();
///
/// let result = llm.generate(&[
///     Message::system("You are a helpful assistant."),
///     Message::human("What is the capital of France?"),
/// ]).await.unwrap();
/// println!("{}", result.generation);
/// # });
/// ```
///
/// # Output budget
///
/// Unless [`max_tokens`](Self::max_tokens) is set, requests ask for
/// [`DEFAULT_MAX_TOKENS`] (blocking) or [`DEFAULT_STREAM_MAX_TOKENS`]
/// (streaming), capped at the model's documented output limit when the model
/// is known. Thinking tokens count against this budget, and many current
/// models always think, so a small budget can end a response before any text
/// is produced.
///
/// # Transport
///
/// - The API key is sent only as a sensitive `x-api-key` header, never
///   printed by `Debug`, and scrubbed from error messages.
/// - The base URL must be `https://`, except for `localhost` / loopback.
/// - Retryable failures (408, 409, 429, 5xx, 529, connection errors) are
///   retried [`DEFAULT_MAX_RETRIES`] times, honouring `retry-after-ms` /
///   `retry-after` up to 60 s, otherwise with jittered exponential backoff.
///   Streams are retried only before the first byte.
/// - Blocking bodies are capped at [`DEFAULT_MAX_RESPONSE_BYTES`], streamed
///   content at [`DEFAULT_MAX_STREAM_BYTES`]; error bodies are truncated.
/// - The built-in HTTP client has a [`DEFAULT_CONNECT_TIMEOUT`] and a read
///   timeout; blocking requests have a [`DEFAULT_TIMEOUT`] total timeout.
#[derive(Clone)]
pub struct Anthropic {
    api_key: ApiKey,
    model: String,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
    base_url: String,
    client: reqwest::Client,
    cache: CachePolicy,
    thinking: Option<Thinking>,
    effort: Option<Effort>,
    structured_output: StructuredOutput,
    max_retries: u32,
    timeout: Duration,
    max_response_bytes: usize,
}

impl fmt::Debug for Anthropic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Anthropic")
            .field("api_key", &self.api_key)
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("temperature", &self.temperature)
            .field("max_tokens", &self.max_tokens)
            .field("cache", &self.cache)
            .field("thinking", &self.thinking)
            .field("effort", &self.effort)
            .field("structured_output", &self.structured_output)
            .field("max_retries", &self.max_retries)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .read_timeout(DEFAULT_TIMEOUT)
        // Never follow redirects: reqwest keeps `x-api-key` on a cross-origin
        // redirect, and a redirect could also downgrade to plain HTTP.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

impl Anthropic {
    /// Create a client with the given API key and default settings.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: ApiKey::new(api_key.into()),
            model: models::DEFAULT_MODEL.to_string(),
            temperature: None,
            max_tokens: None,
            base_url: DEFAULT_BASE_URL.to_string(),
            client: default_http_client(),
            cache: CachePolicy::none(),
            thinking: None,
            effort: None,
            structured_output: StructuredOutput::Auto,
            max_retries: DEFAULT_MAX_RETRIES,
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// Create a client from the `ANTHROPIC_API_KEY` environment variable.
    pub fn from_env() -> Result<Self, LlmError> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| LlmError::other("ANTHROPIC_API_KEY environment variable not set"))?;
        Ok(Self::new(api_key))
    }

    /// Set the model id. Any id the Messages API accepts works, e.g. one of
    /// the [`models`] constants or a newer release this crate does not know.
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// The model id this client sends.
    #[must_use]
    pub fn model_id(&self) -> &str {
        &self.model
    }

    /// Capability note for this client's model, if it is a known one.
    #[must_use]
    pub fn model_info(&self) -> Option<&'static ModelInfo> {
        models::lookup(&self.model)
    }

    /// Set the sampling temperature.
    ///
    /// Most current models reject sampling parameters; for a known model
    /// whose [`ModelInfo::sampling_params`] is `false`, requests fail locally.
    #[must_use]
    pub const fn temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Set the maximum number of tokens to generate (thinking included),
    /// overriding the defaults described under "Output budget" above.
    #[must_use]
    pub const fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Set the API origin (default [`DEFAULT_BASE_URL`]), e.g. a gateway, a
    /// proxy, or a local mock server in tests. `/v1/messages` is appended; a
    /// trailing slash is ignored. It must be `https://` unless the host is
    /// `localhost` or a loopback address; otherwise every request fails
    /// locally before the key is sent.
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into().trim_end_matches('/').to_string();
        self
    }

    /// Use a preconfigured HTTP client (timeouts, proxies, TLS settings).
    /// Its own timeouts replace the built-in connect/read timeouts; the
    /// per-request [`timeout`](Self::timeout) still applies. Its redirect
    /// policy applies too: the default client follows none, and since a
    /// followed redirect keeps the `x-api-key` header, set
    /// `.redirect(reqwest::redirect::Policy::none())` on yours as well.
    #[must_use]
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Set where `cache_control` breakpoints go (default: none). See
    /// [`CachePolicy`].
    ///
    /// ```rust
    /// use rune_chain_anthropic::{Anthropic, CachePolicy, CacheTtl};
    ///
    /// let llm = Anthropic::new("sk-ant-example")
    ///     .cache(CachePolicy::none().with_system(CacheTtl::OneHour).with_messages(CacheTtl::FiveMinutes));
    /// ```
    #[must_use]
    pub const fn cache(mut self, policy: CachePolicy) -> Self {
        self.cache = policy;
        self
    }

    /// Shorthand for a system-prompt breakpoint with `ttl`.
    #[must_use]
    pub const fn cache_system(mut self, ttl: CacheTtl) -> Self {
        self.cache = self.cache.with_system(ttl);
        self
    }

    /// Set the extended-thinking mode (default: unset, the model's own
    /// default). See [`Thinking`].
    #[must_use]
    pub const fn thinking(mut self, thinking: Thinking) -> Self {
        self.thinking = Some(thinking);
        self
    }

    /// Set the effort level (`output_config.effort`).
    #[must_use]
    pub const fn effort(mut self, effort: Effort) -> Self {
        self.effort = Some(effort);
        self
    }

    /// Choose how [`generate_structured`](rune_chain_core::Llm::generate_structured)
    /// constrains output (default [`StructuredOutput::Auto`]).
    #[must_use]
    pub const fn structured_output(mut self, mode: StructuredOutput) -> Self {
        self.structured_output = mode;
        self
    }

    /// Set how many times a retryable failure is retried (default
    /// [`DEFAULT_MAX_RETRIES`]; `0` disables retries).
    #[must_use]
    pub const fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Set the total timeout of blocking requests (default
    /// [`DEFAULT_TIMEOUT`]). Streams are bounded by the HTTP client's read
    /// timeout instead, since they may legitimately run longer.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Cap blocking response bodies and streamed content at `bytes`
    /// (defaults [`DEFAULT_MAX_RESPONSE_BYTES`] and
    /// [`DEFAULT_MAX_STREAM_BYTES`]).
    #[must_use]
    pub const fn max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }

    /// The `max_tokens` a blocking (`streaming == false`) or streaming request
    /// sends: the explicit setting, or the default capped at the known
    /// model's output limit.
    fn effective_max_tokens(&self, streaming: bool) -> u32 {
        self.max_tokens.unwrap_or_else(|| {
            let default = if streaming {
                DEFAULT_STREAM_MAX_TOKENS
            } else {
                DEFAULT_MAX_TOKENS
            };
            self.model_info()
                .map_or(default, |info| default.min(info.max_output_tokens))
        })
    }

    const fn stream_limit(&self) -> usize {
        if self.max_response_bytes == DEFAULT_MAX_RESPONSE_BYTES {
            DEFAULT_MAX_STREAM_BYTES
        } else {
            self.max_response_bytes
        }
    }
}

fn image_to_api(image: &ImageData) -> AnthropicImageSource {
    match image {
        ImageData::Url { url } => AnthropicImageSource::Url { url: url.clone() },
        ImageData::Base64 { mime_type, data } => AnthropicImageSource::Base64 {
            media_type: mime_type.clone(),
            data: data.clone(),
        },
    }
}

fn content_to_api(content: &MessageContent) -> ApiMessageContent {
    match content {
        MessageContent::Text(s) => ApiMessageContent::Text(s.clone()),
        MessageContent::Parts(parts) => ApiMessageContent::Blocks(
            parts
                .iter()
                .map(|p| match p {
                    ContentPart::Text { text } => ApiContentBlock::text(text.clone()),
                    ContentPart::Image { image } => ApiContentBlock::Image {
                        source: image_to_api(image),
                        cache_control: None,
                    },
                })
                .collect(),
        ),
    }
}

/// Tool-call arguments as the JSON object the API expects. Empty arguments
/// mean "no arguments"; anything unparseable is sent as `null` so the API,
/// not this crate, decides.
fn tool_input(arguments: &str) -> Value {
    if arguments.trim().is_empty() {
        return Value::Object(serde_json::Map::new());
    }
    serde_json::from_str(arguments).unwrap_or(Value::Null)
}

/// An assistant turn's reasoning as thinking blocks to send back. Only
/// blocks the API can verify are kept: thinking with a signature, and
/// redacted thinking. Unsigned reasoning (from another provider) is dropped.
fn thinking_blocks(msg: &Message) -> Vec<ApiContentBlock> {
    msg.reasoning
        .iter()
        .filter_map(|r| match (&r.redacted, &r.signature) {
            (Some(data), _) => Some(ApiContentBlock::RedactedThinking { data: data.clone() }),
            (None, Some(signature)) => Some(ApiContentBlock::Thinking {
                thinking: r.text.clone(),
                signature: signature.clone(),
            }),
            (None, None) => None,
        })
        .collect()
}

fn partition_messages(messages: &[Message]) -> (Option<String>, Vec<ApiMessage>) {
    let mut system_parts: Vec<&str> = Vec::new();
    let mut api_messages: Vec<ApiMessage> = Vec::new();

    for msg in messages {
        match msg.role {
            Role::System => {
                system_parts.push(msg.content.as_text());
            }
            Role::Human => {
                api_messages.push(ApiMessage {
                    role: "user",
                    content: content_to_api(&msg.content),
                });
            }
            Role::Ai => {
                let thinking = thinking_blocks(msg);
                if msg.tool_calls.is_empty() && thinking.is_empty() {
                    api_messages.push(ApiMessage {
                        role: "assistant",
                        content: content_to_api(&msg.content),
                    });
                } else {
                    // Thinking must come first, before text and tool use.
                    let mut blocks: Vec<ApiContentBlock> = thinking;
                    let text = msg.content.text_content();
                    if !text.is_empty() {
                        blocks.push(ApiContentBlock::text(text));
                    }
                    for tc in &msg.tool_calls {
                        blocks.push(ApiContentBlock::ToolUse {
                            id: tc.id.clone(),
                            name: tc.name.clone(),
                            input: tool_input(&tc.arguments),
                            cache_control: None,
                        });
                    }
                    api_messages.push(ApiMessage {
                        role: "assistant",
                        content: ApiMessageContent::Blocks(blocks),
                    });
                }
            }
            Role::Tool => {
                let block = ApiContentBlock::ToolResult {
                    tool_use_id: msg
                        .tool_call_id
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    content: msg.content.text_content(),
                    cache_control: None,
                };
                // Results of parallel tool calls belong in one user message.
                if let Some(ApiMessage {
                    role: "user",
                    content: ApiMessageContent::Blocks(blocks),
                }) = api_messages.last_mut()
                    && blocks
                        .iter()
                        .all(|b| matches!(b, ApiContentBlock::ToolResult { .. }))
                {
                    blocks.push(block);
                    continue;
                }
                api_messages.push(ApiMessage {
                    role: "user",
                    content: ApiMessageContent::Blocks(vec![block]),
                });
            }
        }
    }

    let system = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n"))
    };

    (system, api_messages)
}

/// Put a breakpoint on the last content block of the last message.
fn mark_last_message(messages: &mut [ApiMessage], ttl: CacheTtl) {
    let Some(last) = messages.last_mut() else {
        return;
    };
    if let ApiMessageContent::Text(text) = &mut last.content {
        last.content = ApiMessageContent::Blocks(vec![ApiContentBlock::text(std::mem::take(text))]);
    }
    if let ApiMessageContent::Blocks(blocks) = &mut last.content
        && let Some(block) = blocks.last_mut()
    {
        block.set_cache_control(ttl.to_wire());
    }
}

/// A structured-output request plan.
enum Plan {
    Native(Value),
    ForcedTool {
        name: String,
        schema: Value,
        wrapped: bool,
    },
    Prompt,
}

/// A tool name from a schema name: `[A-Za-z0-9_-]`, 1–64 chars.
fn tool_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(64)
        .collect();
    if cleaned.is_empty() {
        JSON_OBJECT_TOOL.to_string()
    } else {
        cleaned
    }
}

/// A tool input schema must be an object; wrap anything else in
/// `{"value": …}`, hoisting `$defs`/`definitions` so `$ref`s still resolve.
fn object_schema(schema: &Value) -> (Value, bool) {
    if schema.get("type").and_then(Value::as_str) == Some("object") {
        return (schema.clone(), false);
    }
    let mut inner = schema.clone();
    let mut wrapper = serde_json::json!({
        "type": "object",
        "properties": {},
        "required": ["value"],
        "additionalProperties": false,
    });
    if let (Some(inner_obj), Some(outer)) = (inner.as_object_mut(), wrapper.as_object_mut()) {
        for key in ["$defs", "definitions"] {
            if let Some(defs) = inner_obj.remove(key) {
                outer.insert(key.to_string(), defs);
            }
        }
    }
    wrapper["properties"]["value"] = inner;
    (wrapper, true)
}

impl Anthropic {
    /// Reject, before any network I/O, requests that cannot succeed: an
    /// insecure base URL, malformed images, and settings a known model is
    /// documented to refuse. Unknown model ids skip the model checks.
    fn preflight(
        &self,
        messages: &[Message],
        tool_choice: Option<&ToolChoice>,
        streaming: bool,
    ) -> Result<(), LlmError> {
        http::check_base_url(&self.base_url)?;
        self.cache.check_order().map_err(LlmError::other)?;
        for msg in messages {
            if let MessageContent::Parts(parts) = &msg.content {
                for part in parts {
                    if let ContentPart::Image { image } = part {
                        image
                            .validate_default()
                            .map_err(|e| LlmError::other(format!("invalid image: {e}")))?;
                    }
                }
            }
        }
        let forced = matches!(
            tool_choice,
            Some(ToolChoice::Required | ToolChoice::Tool(_))
        );
        if let Some(thinking) = &self.thinking {
            if forced && thinking.is_enabled() {
                return Err(LlmError::other(
                    "a forced tool choice cannot be combined with extended thinking",
                ));
            }
            if let Thinking::Budget { budget_tokens, .. } = thinking {
                if *budget_tokens < Thinking::MIN_BUDGET_TOKENS {
                    return Err(LlmError::other(format!(
                        "thinking budget must be at least {}",
                        Thinking::MIN_BUDGET_TOKENS
                    )));
                }
                if *budget_tokens >= self.effective_max_tokens(streaming) {
                    return Err(LlmError::other("thinking budget must be below max_tokens"));
                }
            }
        }
        let Some(info) = self.model_info() else {
            return Ok(());
        };
        if self.temperature.is_some() && !info.sampling_params {
            return Err(LlmError::other(format!(
                "model `{}` does not accept a sampling temperature; remove `.temperature(..)`",
                info.id
            )));
        }
        if forced && !info.forced_tool_choice {
            return Err(LlmError::other(format!(
                "model `{}` accepts only an automatic tool choice; use `ToolChoice::Auto`",
                info.id
            )));
        }
        match self.thinking {
            Some(Thinking::Adaptive { .. }) if !info.adaptive_thinking => {
                Err(LlmError::other(format!(
                    "model `{}` does not support adaptive thinking; use `Thinking::budget(..)`",
                    info.id
                )))
            }
            Some(Thinking::Budget { .. }) if !info.thinking_budget => {
                Err(LlmError::other(format!(
                    "model `{}` rejects a fixed thinking budget; use `Thinking::adaptive()` \
                     and steer depth with `.effort(..)`",
                    info.id
                )))
            }
            Some(Thinking::Disabled) if !info.thinking_can_disable => {
                Err(LlmError::other(format!(
                    "model `{}` cannot turn thinking off; lower `.effort(..)` instead",
                    info.id
                )))
            }
            _ => Ok(()),
        }
    }

    /// Translate rune-chain messages, tools and tool choice into a
    /// `/v1/messages` body using this client's settings.
    fn request_body(
        &self,
        messages: &[Message],
        tool_defs: &[FunctionDefinition],
        tool_choice: Option<&ToolChoice>,
        stream: Option<bool>,
    ) -> MessagesRequest {
        let mut tools: Vec<AnthropicToolDef> = tool_defs
            .iter()
            .map(|d| AnthropicToolDef {
                name: d.name.clone(),
                description: d.description.clone(),
                input_schema: d.parameters.clone(),
                cache_control: None,
            })
            .collect();
        if let (Some(ttl), Some(last)) = (self.cache.tools, tools.last_mut()) {
            last.cache_control = Some(ttl.to_wire());
        }

        let (system, mut api_messages) = partition_messages(messages);
        let system = system.map(|text| match self.cache.system {
            Some(ttl) if !text.is_empty() => SystemPrompt::Blocks(vec![SystemBlock {
                kind: "text",
                text,
                cache_control: Some(ttl.to_wire()),
            }]),
            _ => SystemPrompt::Text(text),
        });
        if let Some(ttl) = self.cache.messages {
            mark_last_message(&mut api_messages, ttl);
        }

        let tool_choice = tool_choice.map(|tc| match tc {
            ToolChoice::Auto => AnthropicToolChoice::Auto,
            ToolChoice::None => AnthropicToolChoice::None,
            ToolChoice::Required => AnthropicToolChoice::Any,
            ToolChoice::Tool(name) => AnthropicToolChoice::Tool { name: name.clone() },
        });

        MessagesRequest {
            model: self.model.clone(),
            messages: api_messages,
            system,
            max_tokens: self.effective_max_tokens(stream == Some(true)),
            temperature: self.temperature,
            stream,
            tools,
            tool_choice,
            thinking: self.thinking,
            output_config: OutputConfig {
                effort: self.effort,
                format: None,
            },
        }
    }

    /// POST `body` to `path`, retrying retryable failures. Returns the
    /// successful response (body unread).
    async fn send<B: Serialize + Sync>(
        &self,
        path: &str,
        body: &B,
        streaming: bool,
    ) -> Result<reqwest::Response, LlmError> {
        http::check_base_url(&self.base_url)?;
        let payload = serde_json::to_vec(body)
            .map_err(|e| LlmError::other(format!("failed to encode request: {e}")))?;
        let key = self.api_key.header_value()?;
        let url = format!("{}{path}", self.base_url);
        let mut attempt = 0;
        loop {
            let mut request = self
                .client
                .post(&url)
                .header("x-api-key", key.clone())
                .header("anthropic-version", ANTHROPIC_VERSION)
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(payload.clone());
            if !streaming {
                request = request.timeout(self.timeout);
            }
            let (retry_wait, error) = match request.send().await {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response) => {
                    let status = response.status().as_u16();
                    let wait = if http::is_retryable(status) && attempt < self.max_retries {
                        http::retry_delay(attempt, response.headers())
                    } else {
                        None
                    };
                    (
                        wait,
                        http::error_from_response(response, &self.api_key).await,
                    )
                }
                Err(e) => {
                    let wait = if e.is_connect() && attempt < self.max_retries {
                        http::retry_delay(attempt, &reqwest::header::HeaderMap::new())
                    } else {
                        None
                    };
                    (wait, http::transport_error(&e, &self.api_key))
                }
            };
            let Some(wait) = retry_wait else {
                return Err(error);
            };
            tokio::time::sleep(wait).await;
            attempt += 1;
        }
    }

    async fn complete(&self, body: &MessagesRequest) -> Result<MessageResponse, LlmError> {
        let response = self.send(MESSAGES_PATH, body, false).await?;
        let bytes = http::read_capped(response, self.max_response_bytes).await?;
        decode_response(&bytes)
    }

    async fn open_stream(&self, body: &MessagesRequest) -> Result<MessageStream, LlmError> {
        let response = self.send(MESSAGES_PATH, body, true).await?;
        Ok(Box::pin(assemble_events(
            Box::pin(response.bytes_stream()),
            self.stream_limit(),
        )))
    }

    /// Generate a full [`MessageResponse`] — thinking blocks, stop reason
    /// and cache-token [`Usage`](crate::Usage) included — with optional
    /// tools.
    ///
    /// # Errors
    ///
    /// As [`Llm::generate_with_tools`](rune_chain_core::Llm::generate_with_tools).
    pub async fn generate_message(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<MessageResponse, LlmError> {
        self.preflight(messages, tool_choice.as_ref(), false)?;
        self.complete(&self.request_body(messages, tools, tool_choice.as_ref(), None))
            .await
    }

    /// Stream a response as typed [`StreamEvent`]s: text and thinking
    /// fragments, complete tool calls (their streamed JSON assembled), and
    /// finally the whole [`MessageResponse`].
    ///
    /// # Errors
    ///
    /// Opening the stream fails like [`generate_message`](Self::generate_message);
    /// the stream itself yields at most one error and then ends.
    pub async fn stream_message(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<MessageStream, LlmError> {
        self.preflight(messages, tool_choice.as_ref(), true)?;
        self.open_stream(&self.request_body(messages, tools, tool_choice.as_ref(), Some(true)))
            .await
    }

    /// Count the input tokens `messages` (and `tools`) would use with this
    /// client's model and settings, via `/v1/messages/count_tokens`. Token
    /// counts are model-specific; nothing is generated or billed as output.
    ///
    /// # Errors
    ///
    /// The same transport and provider errors as a generation request.
    pub async fn count_tokens(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
    ) -> Result<u32, LlmError> {
        self.preflight(messages, None, false)?;
        let request = self.request_body(messages, tools, None, None);
        let response = self
            .send(
                COUNT_TOKENS_PATH,
                &CountTokensRequest::from(&request),
                false,
            )
            .await?;
        let bytes = http::read_capped(response, 64 << 10).await?;
        serde_json::from_slice::<CountTokensResponse>(&bytes)
            .map(|r| r.input_tokens)
            .map_err(|e| LlmError::invalid_response(e.to_string()))
    }

    /// Decide how to satisfy a JSON response format.
    fn plan_structured(&self, format: &ResponseFormat) -> Result<Plan, LlmError> {
        let info = self.model_info();
        let thinking_on = self.thinking.map_or_else(
            || info.is_some_and(|i| i.thinking_always_on),
            |t| t.is_enabled(),
        );
        let forced_ok = info.is_some_and(|i| i.forced_tool_choice) && !thinking_on;
        let native_ok = info.is_none_or(|i| i.native_structured_output);
        let forced = |name: &str, schema: &Value| {
            let (schema, wrapped) = object_schema(schema);
            Plan::ForcedTool {
                name: tool_name(name),
                schema,
                wrapped,
            }
        };
        let object = serde_json::json!({ "type": "object" });
        Ok(match (self.structured_output, format) {
            (_, ResponseFormat::Text) | (StructuredOutput::Prompt, _) => Plan::Prompt,
            (StructuredOutput::Native, ResponseFormat::JsonSchema { schema, .. }) => {
                Plan::Native(schema.clone())
            }
            (StructuredOutput::Native, _) => {
                return Err(LlmError::other(
                    "native structured output needs a JSON schema; use ResponseFormat::JsonSchema",
                ));
            }
            (StructuredOutput::ForcedTool, ResponseFormat::JsonSchema { name, schema, .. }) => {
                forced(name, schema)
            }
            (StructuredOutput::ForcedTool, _) => forced(JSON_OBJECT_TOOL, &object),
            (_, ResponseFormat::JsonSchema { schema, .. }) if native_ok => {
                Plan::Native(schema.clone())
            }
            (_, ResponseFormat::JsonSchema { name, schema, .. }) if forced_ok => {
                forced(name, schema)
            }
            (_, ResponseFormat::JsonObject) if forced_ok => forced(JSON_OBJECT_TOOL, &object),
            _ => Plan::Prompt,
        })
    }
}

/// Decode a successful `/v1/messages` body.
fn decode_response(body: &[u8]) -> Result<MessageResponse, LlmError> {
    serde_json::from_slice::<MessagesResponse>(body)
        .map(MessageResponse::from)
        .map_err(|e| LlmError::invalid_response(e.to_string()))
}

/// Reject responses that cannot hold a complete structured answer.
fn check_structured(message: &MessageResponse) -> Result<(), LlmError> {
    if message.is_refusal() {
        return Err(LlmError::provider(
            "the model declined the request (stop_reason: refusal)",
        ));
    }
    if message.is_truncated() {
        return Err(LlmError::invalid_response(
            "structured output was cut off at max_tokens; raise `.max_tokens(..)`",
        ));
    }
    Ok(())
}

/// Turn a byte stream of SSE (an HTTP response body) into typed events.
///
/// The stream ends after [`StreamEvent::Done`] or the first error. A body
/// that ends before `message_stop` yields a final
/// [`LlmError::invalid_response`], so a truncated response is never mistaken
/// for a complete one.
fn assemble_events<S, B, E>(
    body: S,
    max_bytes: usize,
) -> impl Stream<Item = Result<StreamEvent, LlmError>> + Send
where
    S: Stream<Item = Result<B, E>> + Send + Unpin,
    B: AsRef<[u8]>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let options = rune_sse::Options::default()
        .with_max_event_len(max_bytes.min(16 << 20))
        .with_max_line_len(max_bytes.min(16 << 20));
    let mut events = rune_sse::SseStream::with_options(body, options);
    let mut acc = MessageAccumulator::with_limit(max_bytes);
    async_stream::stream! {
        while let Some(item) = events.next().await {
            let event = match item {
                Ok(item) => match item.into_event() {
                    Some(event) => event,
                    None => continue,
                },
                Err(e) => {
                    yield Err(sse_error(&e));
                    return;
                }
            };
            match acc.push(&event.data) {
                Ok(None) => {}
                Ok(Some(ev)) => {
                    let done = matches!(ev, StreamEvent::Done(_));
                    yield Ok(ev);
                    if done {
                        return;
                    }
                }
                Err(e) => {
                    yield Err(e);
                    return;
                }
            }
        }
        yield Err(LlmError::invalid_response(
            "event stream ended before `message_stop`",
        ));
    }
}

/// Text-only view of [`assemble_events`] for [`Llm::stream`](rune_chain_core::Llm::stream).
fn text_chunks<S>(events: S) -> impl Stream<Item = Result<StreamData, LlmError>> + Send
where
    S: Stream<Item = Result<StreamEvent, LlmError>> + Send,
{
    events.filter_map(|ev| {
        futures::future::ready(match ev {
            Ok(StreamEvent::Text(text)) => Some(Ok(StreamData::chunk(text))),
            Ok(StreamEvent::Done(_)) => Some(Ok(StreamData::done())),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
    })
}

/// Describe an event-stream failure, including its underlying cause.
fn sse_error(e: &rune_sse::Error) -> LlmError {
    use std::error::Error as _;
    let message = e
        .source()
        .map_or_else(|| e.to_string(), |source| format!("{e}: {source}"));
    match e {
        rune_sse::Error::Transport(_) | rune_sse::Error::Io(_) => LlmError::request_failed(message),
        _ => LlmError::invalid_response(message),
    }
}

#[async_trait]
impl rune_chain_core::Llm for Anthropic {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.generate_message(messages, &[], None)
            .await
            .map(|m| m.to_generate_result())
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        self.generate_message(messages, tools, tool_choice)
            .await
            .map(|m| m.to_generate_result())
    }

    async fn stream(
        &self,
        messages: &[Message],
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>, LlmError> {
        let events = self.stream_message(messages, &[], None).await?;
        Ok(Box::pin(text_chunks(events)))
    }

    /// Structured output per [`StructuredOutput`]: native
    /// `output_config.format`, a forced tool call whose input is returned as
    /// the generation, or prompt instructions. The generation is the JSON
    /// text either way; parse it with [`ResponseFormat::parse_json`].
    /// Refusals and responses cut off at `max_tokens` are errors.
    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        match self.plan_structured(format)? {
            Plan::Prompt if !format.is_json() => self.generate(messages).await,
            Plan::Prompt => {
                let message = self
                    .generate_message(&format.apply_to(messages), &[], None)
                    .await?;
                check_structured(&message)?;
                Ok(message.to_generate_result())
            }
            Plan::Native(schema) => {
                self.preflight(messages, None, false)?;
                let mut body = self.request_body(messages, &[], None, None);
                body.output_config.format = Some(OutputFormat::JsonSchema { schema });
                let message = self.complete(&body).await?;
                check_structured(&message)?;
                Ok(message.to_generate_result())
            }
            Plan::ForcedTool {
                name,
                schema,
                wrapped,
            } => {
                let choice = ToolChoice::Tool(name.clone());
                self.preflight(messages, Some(&choice), false)?;
                let tool = FunctionDefinition::new(
                    name.clone(),
                    "Return the final answer. Call this tool exactly once with the complete \
                     answer as its input.",
                    schema,
                );
                let message = self
                    .complete(&self.request_body(
                        messages,
                        std::slice::from_ref(&tool),
                        Some(&choice),
                        None,
                    ))
                    .await?;
                check_structured(&message)?;
                let input = message
                    .content
                    .iter()
                    .find_map(|b| match b {
                        ContentBlock::ToolUse { name: n, input, .. } if *n == name => Some(input),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        LlmError::invalid_response(format!(
                            "the model did not call the `{name}` response tool"
                        ))
                    })?;
                let value = if wrapped {
                    input.get("value").cloned().unwrap_or(Value::Null)
                } else {
                    input.clone()
                };
                Ok(GenerateResult::from_text(value.to_string())
                    .with_tokens(message.usage.to_token_usage()))
            }
        }
    }
}
