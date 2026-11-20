use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use futures::Stream;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use rune_chain_core::{
    ContentPart, FinishReason, FunctionDefinition, GenerateResult, ImageData, LlmError, Message,
    MessageContent, ReasoningBlock, ResponseFormat, Role, StreamData, ToolChoice,
};
use serde_json::{Map, Number, Value};

use crate::http::{self, HttpPolicy, Secret};
use crate::ndjson::Limits;
use crate::options::{KeepAlive, Think};
use crate::stream::{self, EventStream};
use crate::types::{
    ApiFunctionDef, ApiFunctionOut, ApiMessage, ApiToolCallOut, ApiToolDef, ChatRequest,
    ChatResponse,
};

#[cfg(test)]
mod tests;

/// Default server URL; see [`Ollama::base_url`].
pub const DEFAULT_BASE_URL: &str = "http://localhost:11434";
/// Default model; see [`Ollama::model`].
pub const DEFAULT_MODEL: &str = "llama3.2";
/// Default whole-request timeout (10 minutes: loading a large model and
/// evaluating a long prompt on CPU can take minutes); see [`Ollama::timeout`].
/// Covers reading the whole body, including streams.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
/// TCP/TLS connect timeout of the default HTTP client.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default cap on a response body, streamed or not (32 MiB); see
/// [`Ollama::max_response_bytes`].
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 << 20;
/// Default cap on one NDJSON line of a streamed response (4 MiB); see
/// [`Ollama::max_line_bytes`].
pub const DEFAULT_MAX_LINE_BYTES: usize = 4 << 20;

/// Ollama client implementing [`Llm`](rune_chain_core::Llm) and
/// [`Embedder`](rune_chain_embed::Embedder).
///
/// Talks to an [Ollama](https://ollama.com) server's `/api/chat`,
/// `/api/embed` and model-management endpoints. Supports blocking and
/// streaming generation, native tool calling (also streamed, via
/// [`stream_events`](Self::stream_events)), native structured output via
/// [`generate_structured`](rune_chain_core::Llm::generate_structured)
/// (Ollama's `format`), thinking models, and images for vision models.
///
/// # Images
///
/// Ollama's `images` field only accepts base64 data, so image parts must be
/// [`ImageData::Base64`] or a base64 `data:` URL. A remote image URL
/// (`https://…`) is rejected with [`LlmError::other`] before any request is
/// sent; download and encode the image yourself, then pass it with
/// [`ContentPart::image_base64`]. Images are checked with
/// [`ImageData::validate_default`] (well-formed `image/*` base64, size cap).
///
/// # Security
///
/// Ollama has **no authentication**: anyone who can reach its port can run
/// models, read prompts in flight, and pull or delete models. Keep it on
/// loopback, or put it behind a TLS reverse proxy that authenticates (use
/// [`bearer_token`](Self::bearer_token) for proxies that expect one). Plain
/// HTTP is only allowed to loopback hosts unless you opt in with
/// [`allow_http_host`](Self::allow_http_host) or
/// [`allow_insecure_http`](Self::allow_insecure_http). The token never
/// appears in `Debug` output or error messages, and redirects are not
/// followed by the default HTTP client.
///
/// # Quick start
///
/// ```rust,no_run
/// use rune_chain_ollama::Ollama;
/// use rune_chain_core::{Llm, Message};
///
/// # tokio_test::block_on(async {
/// let result = Ollama::new()
///     .generate(&[Message::human("What is the capital of France?")])
///     .await
///     .unwrap();
/// println!("{}", result.generation);
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct Ollama {
    base_url: String,
    model: String,
    sampling: Sampling,
    keep_alive: Option<KeepAlive>,
    think: Option<Think>,
    bearer: Secret,
    http_policy: HttpPolicy,
    timeout: Option<Duration>,
    max_response_bytes: usize,
    max_line_bytes: usize,
    pub(crate) embed_dimensions: Option<u32>,
    pub(crate) embed_truncate: Option<bool>,
    client: reqwest::Client,
}

/// Model options sent in `options`.
#[derive(Debug, Clone, Default)]
struct Sampling {
    temperature: Option<f32>,
    top_p: Option<f32>,
    top_k: Option<u32>,
    seed: Option<i64>,
    stop: Vec<String>,
    num_ctx: Option<u32>,
    num_predict: Option<u32>,
    extra: Map<String, Value>,
}

/// The full reply to [`Ollama::chat`]: the result plus Ollama-specific
/// extras.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ChatReply {
    /// Text, tool calls and token usage.
    pub result: GenerateResult,
    /// The model's reasoning, when [`Ollama::think`] is on and the model
    /// supports it (also in [`GenerateResult::reasoning`]).
    pub thinking: Option<String>,
    /// Ollama's `done_reason` (`"stop"`, `"length"`, …).
    pub done_reason: Option<String>,
}

impl Default for Ollama {
    fn default() -> Self {
        Self::new()
    }
}

fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        // Never follow redirects: one could downgrade to plain HTTP or move
        // the request (and its bearer token) to another host.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

/// A finite `f32` as a JSON number with its shortest decimal form (`0.1`,
/// not `0.10000000149011612`).
fn f32_number(name: &str, v: f32) -> Result<Value, LlmError> {
    format!("{v}")
        .parse::<f64>()
        .ok()
        .and_then(Number::from_f64)
        .map(Value::Number)
        .ok_or_else(|| LlmError::other(format!("option `{name}` must be a finite number")))
}

impl Ollama {
    /// Create a client for a local Ollama server (`http://localhost:11434`,
    /// model `llama3.2`). Building a client does not contact the server.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
            sampling: Sampling::default(),
            keep_alive: None,
            think: None,
            bearer: Secret::default(),
            http_policy: HttpPolicy::default(),
            timeout: Some(DEFAULT_TIMEOUT),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            embed_dimensions: None,
            embed_truncate: None,
            client: default_http_client(),
        }
    }

    /// Set the Ollama server base URL (a trailing `/` is ignored; a path
    /// prefix such as `https://proxy.example.com/ollama` is kept).
    ///
    /// `https` works for any host; plain `http` only for loopback unless
    /// allowed with [`allow_http_host`](Self::allow_http_host). The URL is
    /// checked when a request is made.
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into().trim_end_matches('/').to_string();
        self
    }

    /// The configured base URL.
    #[must_use]
    pub fn base_url_str(&self) -> &str {
        &self.base_url
    }

    /// Allow plain HTTP to `host` (e.g. a GPU box on a trusted LAN),
    /// accepting that prompts and outputs travel unencrypted. Repeatable.
    #[must_use]
    pub fn allow_http_host(mut self, host: impl Into<String>) -> Self {
        self.http_policy.allowed_hosts.push(host.into());
        self
    }

    /// Allow plain HTTP to any host. Prefer
    /// [`allow_http_host`](Self::allow_http_host).
    #[must_use]
    pub const fn allow_insecure_http(mut self) -> Self {
        self.http_policy.allow_any = true;
        self
    }

    /// Send `Authorization: Bearer <token>` with every request, for Ollama
    /// behind an authenticating reverse proxy. Ollama itself ignores it.
    /// The token is marked sensitive and redacted from `Debug` and errors.
    #[must_use]
    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer = Secret::new(token);
        self
    }

    /// Use a preconfigured HTTP client (proxies, TLS settings). The per-request
    /// [`timeout`](Self::timeout) still applies; redirects follow that
    /// client's policy.
    #[must_use]
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Whole-request timeout, including reading the body of a stream
    /// (default [`DEFAULT_TIMEOUT`]). Model pulls are exempt.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Disable the whole-request timeout (connect timeout still applies).
    #[must_use]
    pub const fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// Cap on a response body in bytes, streamed or not (default
    /// [`DEFAULT_MAX_RESPONSE_BYTES`]).
    #[must_use]
    pub const fn max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }

    /// Cap on one line of a streamed response in bytes (default
    /// [`DEFAULT_MAX_LINE_BYTES`]).
    #[must_use]
    pub const fn max_line_bytes(mut self, bytes: usize) -> Self {
        self.max_line_bytes = bytes;
        self
    }

    /// Set the model name (anything `ollama list` shows, e.g. `qwen3:8b`).
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// The configured model name.
    #[must_use]
    pub fn model_id(&self) -> &str {
        &self.model
    }

    /// Sampling temperature (`options.temperature`).
    #[must_use]
    pub const fn temperature(mut self, temperature: f32) -> Self {
        self.sampling.temperature = Some(temperature);
        self
    }

    /// Nucleus sampling threshold (`options.top_p`).
    #[must_use]
    pub const fn top_p(mut self, top_p: f32) -> Self {
        self.sampling.top_p = Some(top_p);
        self
    }

    /// Top-k sampling (`options.top_k`).
    #[must_use]
    pub const fn top_k(mut self, top_k: u32) -> Self {
        self.sampling.top_k = Some(top_k);
        self
    }

    /// Random seed for reproducible sampling (`options.seed`).
    #[must_use]
    pub const fn seed(mut self, seed: i64) -> Self {
        self.sampling.seed = Some(seed);
        self
    }

    /// Add a stop sequence (`options.stop`). Repeatable.
    #[must_use]
    pub fn stop(mut self, sequence: impl Into<String>) -> Self {
        self.sampling.stop.push(sequence.into());
        self
    }

    /// Context window size in tokens (`options.num_ctx`). Ollama's default
    /// is small (2–4K for many models) and silently truncates longer
    /// prompts; raise it for long conversations or documents.
    #[must_use]
    pub const fn num_ctx(mut self, tokens: u32) -> Self {
        self.sampling.num_ctx = Some(tokens);
        self
    }

    /// Maximum number of tokens to generate (`options.num_predict`).
    #[must_use]
    pub const fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.sampling.num_predict = Some(max_tokens);
        self
    }

    /// Set any other model option (`repeat_penalty`, `min_p`, `num_gpu`, …).
    /// The typed setters above take precedence for their own keys.
    #[must_use]
    pub fn option(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.sampling.extra.insert(name.into(), value.into());
        self
    }

    /// How long the model stays loaded after each request (`keep_alive`).
    #[must_use]
    pub const fn keep_alive(mut self, keep_alive: KeepAlive) -> Self {
        self.keep_alive = Some(keep_alive);
        self
    }

    /// Reasoning mode for thinking models (`think`).
    #[must_use]
    pub const fn think(mut self, think: Think) -> Self {
        self.think = Some(think);
        self
    }

    // ── request building ─────────────────────────────────────────────────

    /// The URL for `path`, after the transport policy check.
    pub(crate) fn endpoint(&self, path: &str) -> Result<reqwest::Url, LlmError> {
        http::check_url(&format!("{}{path}", self.base_url), &self.http_policy)
    }

    pub(crate) fn options_map(&self) -> Result<Map<String, Value>, LlmError> {
        let s = &self.sampling;
        let mut map = s.extra.clone();
        if let Some(t) = s.temperature {
            map.insert("temperature".into(), f32_number("temperature", t)?);
        }
        if let Some(p) = s.top_p {
            map.insert("top_p".into(), f32_number("top_p", p)?);
        }
        if let Some(k) = s.top_k {
            map.insert("top_k".into(), k.into());
        }
        if let Some(seed) = s.seed {
            map.insert("seed".into(), seed.into());
        }
        if !s.stop.is_empty() {
            map.insert("stop".into(), s.stop.clone().into());
        }
        if let Some(n) = s.num_ctx {
            map.insert("num_ctx".into(), n.into());
        }
        if let Some(n) = s.num_predict {
            map.insert("num_predict".into(), n.into());
        }
        Ok(map)
    }

    pub(crate) fn keep_alive_value(&self) -> Option<Value> {
        self.keep_alive.map(KeepAlive::to_value)
    }

    pub(crate) const fn limits(&self) -> Limits {
        Limits {
            max_line: self.max_line_bytes,
            max_total: self.max_response_bytes,
        }
    }

    pub(crate) const fn max_response(&self) -> usize {
        self.max_response_bytes
    }

    fn request_body(
        &self,
        messages: &[Message],
        opts: BodyOptions<'_>,
    ) -> Result<ChatRequest, LlmError> {
        let (messages, tools) = apply_tool_choice(messages, opts.tools, opts.tool_choice)?;
        Ok(ChatRequest {
            model: self.model.clone(),
            messages: map_messages(&messages)?,
            stream: opts.stream,
            tools: tools.iter().copied().map(map_tool_def).collect(),
            format: opts.format,
            options: self.options_map()?,
            keep_alive: self.keep_alive_value(),
            think: self.think.map(Think::to_value),
        })
    }

    fn structured_body(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<ChatRequest, LlmError> {
        let native = match format.schema() {
            Some(schema) if schema.is_object() => Some(schema.clone()),
            Some(_) => {
                return Err(LlmError::other(
                    "Ollama `format` needs a JSON Schema object",
                ));
            }
            None if format.is_json() => Some(Value::from("json")),
            None => None,
        };
        // Ollama recommends also stating the format in the prompt: it
        // grounds the model, which otherwise may emit only whitespace.
        let messages = format.apply_to(messages);
        self.request_body(
            &messages,
            BodyOptions {
                format: native,
                ..BodyOptions::default()
            },
        )
    }

    // ── transport ───────────────────────────────────────────────────────

    /// Send a request; returns the response on 2xx, the decoded error
    /// otherwise. `body` is JSON for POST, `None` for GET.
    pub(crate) async fn send(
        &self,
        path: &str,
        body: Option<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Result<reqwest::Response, LlmError> {
        let url = self.endpoint(path)?;
        let mut req = match body {
            Some(payload) => self
                .client
                .post(url)
                .header(CONTENT_TYPE, "application/json")
                .body(payload),
            None => self.client.get(url),
        };
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        if !self.bearer.is_empty() {
            let mut value = HeaderValue::from_str(&format!("Bearer {}", self.bearer.expose()))
                .map_err(|_| {
                    LlmError::other("the bearer token contains characters not allowed in a header")
                })?;
            value.set_sensitive(true);
            req = req.header(AUTHORIZATION, value);
        }
        let response = req.send().await.map_err(|e| {
            let err = if e.is_timeout() {
                LlmError::timeout(e.to_string())
            } else {
                LlmError::request_failed(e.to_string())
            };
            self.scrub(err)
        })?;
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status().as_u16();
        let wait = http::retry_after(response.headers());
        let body = http::read_body(response, http::MAX_ERROR_BODY, true)
            .await
            .unwrap_or_default();
        let err = http::decode_error(status, &body);
        Err(self.scrub(match wait {
            Some(wait) => err.with_retry_after(wait),
            None => err,
        }))
    }

    pub(crate) async fn post_json<T: serde::Serialize + Sync>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<Vec<u8>, LlmError> {
        let payload = encode(body)?;
        let response = self.send(path, Some(payload), self.timeout).await?;
        http::read_body(response, self.max_response_bytes, false)
            .await
            .map_err(|e| self.scrub(e))
    }

    pub(crate) const fn request_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Remove the bearer token from an error message.
    pub(crate) fn scrub(&self, err: LlmError) -> LlmError {
        err.map_message(|m| self.bearer.scrub(m))
    }

    async fn complete(&self, body: &ChatRequest) -> Result<ChatReply, LlmError> {
        let bytes = self.post_json("/api/chat", body).await?;
        decode_response(&bytes).map_err(|e| self.scrub(e))
    }

    async fn open_stream(&self, body: &ChatRequest) -> Result<EventStream, LlmError> {
        let response = self
            .send("/api/chat", Some(encode(body)?), self.timeout)
            .await?;
        Ok(stream::assemble_events(
            Box::pin(response.bytes_stream()),
            self.limits(),
        ))
    }

    /// Chat with optional tools and return the full [`ChatReply`], including
    /// the model's thinking (see [`think`](Self::think)) and `done_reason`.
    ///
    /// # Errors
    ///
    /// As [`generate_with_tools`](rune_chain_core::Llm::generate_with_tools).
    pub async fn chat(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<ChatReply, LlmError> {
        let body = self.request_body(
            messages,
            BodyOptions {
                tools,
                tool_choice: tool_choice.as_ref(),
                ..BodyOptions::default()
            },
        )?;
        self.complete(&body).await
    }

    /// Stream a chat as [`StreamEvent`](crate::StreamEvent)s: thinking and
    /// text fragments, tool calls, the finish reason and token usage.
    ///
    /// Use [`collect_events`](crate::collect_events) to fold the stream into
    /// a [`GenerateResult`].
    ///
    /// # Errors
    ///
    /// Pre-flight failures and HTTP errors before the stream starts; errors
    /// inside the stream (malformed or oversized lines, `{"error": …}` lines,
    /// truncation) are yielded as items and end the stream.
    pub async fn stream_events(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        let body = self.request_body(
            messages,
            BodyOptions {
                tools,
                tool_choice: tool_choice.as_ref(),
                stream: true,
                ..BodyOptions::default()
            },
        )?;
        self.open_stream(&body).await
    }
}

pub fn encode<T: serde::Serialize>(body: &T) -> Result<Vec<u8>, LlmError> {
    serde_json::to_vec(body).map_err(|e| LlmError::other(format!("encode request: {e}")))
}

/// Options for one `/api/chat` body.
#[derive(Default)]
struct BodyOptions<'a> {
    tools: &'a [FunctionDefinition],
    tool_choice: Option<&'a ToolChoice>,
    stream: bool,
    format: Option<Value>,
}

/// Ollama has no `tool_choice`; emulate it. `None` drops the tools,
/// `Required` and `Tool(name)` add a system instruction (and `Tool` sends
/// only that tool). Best effort: the model may still answer in text.
fn apply_tool_choice<'a>(
    messages: &[Message],
    tools: &'a [FunctionDefinition],
    choice: Option<&ToolChoice>,
) -> Result<(Vec<Message>, Vec<&'a FunctionDefinition>), LlmError> {
    let all: Vec<&FunctionDefinition> = tools.iter().collect();
    let (tools, instruction) = match choice {
        _ if tools.is_empty() => (all, None),
        None | Some(ToolChoice::Auto) => (all, None),
        Some(ToolChoice::None) => (Vec::new(), None),
        Some(ToolChoice::Required) => (
            all,
            Some("You must call one of the provided tools; do not answer directly.".to_string()),
        ),
        Some(ToolChoice::Tool(name)) => {
            let chosen: Vec<_> = tools.iter().filter(|t| &t.name == name).collect();
            if chosen.is_empty() {
                return Err(LlmError::other(format!(
                    "tool_choice names `{}`, which is not among the provided tools",
                    http::truncate(name, 80)
                )));
            }
            (
                chosen,
                Some(format!(
                    "You must call the `{name}` tool; do not answer directly."
                )),
            )
        }
    };
    let mut messages = messages.to_vec();
    if let Some(text) = instruction {
        let at = messages
            .iter()
            .take_while(|m| m.role == Role::System)
            .count();
        messages.insert(at, Message::system(text));
    }
    Ok((messages, tools))
}

fn map_tool_def(def: &FunctionDefinition) -> ApiToolDef {
    ApiToolDef {
        kind: "function",
        function: ApiFunctionDef {
            name: def.name.clone(),
            description: def.description.clone(),
            parameters: def.parameters.clone(),
        },
    }
}

fn map_messages(messages: &[Message]) -> Result<Vec<ApiMessage>, LlmError> {
    // Ollama correlates tool results by tool name, not call id.
    let mut call_names: HashMap<&str, &str> = HashMap::new();
    messages
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let role = match m.role {
                Role::System => "system",
                Role::Human => "user",
                Role::Ai => "assistant",
                Role::Tool => "tool",
            };
            let (content, images) = match &m.content {
                MessageContent::Text(s) => (s.clone(), Vec::new()),
                MessageContent::Parts(parts) => {
                    let mut text: Vec<&str> = Vec::new();
                    let mut images = Vec::new();
                    for p in parts {
                        match p {
                            ContentPart::Text { text: t } => text.push(t),
                            ContentPart::Image { image } => images.push(
                                image_base64(image)
                                    .map_err(|e| LlmError::other(format!("message {i}: {e}")))?,
                            ),
                        }
                    }
                    (text.join(" "), images)
                }
            };
            let tool_calls = m
                .tool_calls
                .iter()
                .map(|tc| {
                    call_names.insert(tc.id.as_str(), tc.name.as_str());
                    let arguments: Value = tc
                        .parse_arguments()
                        .map_err(|e| LlmError::other(format!("message {i}: {e}")))?;
                    Ok(ApiToolCallOut {
                        function: ApiFunctionOut {
                            name: tc.name.clone(),
                            arguments,
                        },
                    })
                })
                .collect::<Result<Vec<_>, LlmError>>()?;
            let tool_name = (m.role == Role::Tool)
                .then_some(m.tool_call_id.as_deref())
                .flatten()
                .and_then(|id| call_names.get(id))
                .map(|n| (*n).to_string());
            // Earlier reasoning goes back as `thinking` on assistant turns.
            let thinking = (m.role == Role::Ai && !m.reasoning.is_empty())
                .then(|| m.reasoning_text())
                .filter(|t| !t.is_empty());
            Ok(ApiMessage {
                role,
                content,
                images,
                tool_calls,
                tool_name,
                thinking,
            })
        })
        .collect()
}

/// Return the base64 payload Ollama expects in `images`, after validating
/// it.
///
/// Base64 images pass through; a `data:<mime>;base64,<data>` URL is unwrapped
/// to its payload. Any other URL is an error: Ollama does not fetch images,
/// and this client does not fetch them on the caller's behalf.
fn image_base64(image: &ImageData) -> Result<String, String> {
    let (mime, data) = match image {
        ImageData::Base64 { mime_type, data } => (mime_type.as_str(), data.as_str()),
        ImageData::Url { url } => data_url_parts(url).ok_or_else(|| {
            format!(
                "Ollama only accepts base64 images; fetch {} and pass it with \
                 ContentPart::image_base64",
                http::truncate(url, 200)
            )
        })?,
    };
    ImageData::base64(mime, data)
        .validate_default()
        .map_err(|e| e.to_string())?;
    Ok(data.to_string())
}

/// Split a base64 `data:` URL into MIME type and payload, or `None` for
/// anything else.
fn data_url_parts(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("data:")?;
    let (meta, payload) = rest.split_once(',')?;
    meta.strip_suffix(";base64").map(|mime| (mime, payload))
}

/// Decode a successful non-streaming `/api/chat` body.
fn decode_response(body: &[u8]) -> Result<ChatReply, LlmError> {
    let chat: ChatResponse =
        serde_json::from_slice(body).map_err(|e| LlmError::invalid_response(e.to_string()))?;
    let tool_calls = stream::convert_tool_calls(chat.message.tool_calls, 0)?;
    let thinking = chat.message.thinking.filter(|t| !t.is_empty());
    let mut result = GenerateResult::from_text(chat.message.content)
        .with_tokens(stream::usage(chat.prompt_eval_count, chat.eval_count))
        .with_reasoning(
            thinking
                .iter()
                .map(|t| ReasoningBlock::new(t.clone()))
                .collect(),
        );
    if let Some(reason) = finish_reason(chat.done_reason.as_deref(), !tool_calls.is_empty()) {
        result = result.with_finish_reason(reason);
    }
    Ok(ChatReply {
        result: result.with_tool_calls(tool_calls),
        thinking,
        done_reason: chat.done_reason,
    })
}

/// Map Ollama's `done_reason` onto the portable [`FinishReason`]. A `stop`
/// with tool calls is [`FinishReason::ToolCalls`].
fn finish_reason(done_reason: Option<&str>, has_tool_calls: bool) -> Option<FinishReason> {
    match done_reason? {
        "stop" if has_tool_calls => Some(FinishReason::ToolCalls),
        other => Some(FinishReason::from(other)),
    }
}

#[async_trait]
impl rune_chain_core::Llm for Ollama {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        let body = self.request_body(messages, BodyOptions::default())?;
        Ok(self.complete(&body).await?.result)
    }

    /// Native tool calling via `/api/chat` `tools`. The model must support
    /// tools (`ollama show <model>` lists `tools` among its capabilities).
    /// Ollama has no `tool_choice`: [`ToolChoice::None`] omits the tools,
    /// and [`ToolChoice::Required`] / [`ToolChoice::Tool`] add a system
    /// instruction (best effort). Tool-call ids are Ollama's when it sends
    /// them, otherwise `call_<n>`; tool results are matched back to their
    /// call by id and sent with Ollama's `tool_name`.
    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        Ok(self.chat(messages, tools, tool_choice).await?.result)
    }

    async fn stream(
        &self,
        messages: &[Message],
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>, LlmError> {
        Ok(stream::text_stream(
            Self::stream_events(self, messages, &[], None).await?,
        ))
    }

    /// Native streaming with tool calls on `/api/chat`: thinking and text
    /// deltas as they arrive, each tool call as soon as Ollama sends it
    /// (whole), then the finish reason and usage.
    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<rune_chain_core::EventStream, LlmError> {
        let events =
            Self::stream_events(self, messages, tools.unwrap_or_default(), tool_choice).await?;
        Ok(stream::core_events(events))
    }

    /// Native structured output via Ollama's `format`:
    /// [`ResponseFormat::JsonSchema`] sends the schema (constrained
    /// decoding), [`ResponseFormat::JsonObject`] sends `"json"`. Either way
    /// the format instructions are also added as a system message, as Ollama
    /// recommends. [`ResponseFormat::Text`] is plain `generate`.
    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        let body = self.structured_body(messages, format)?;
        Ok(self.complete(&body).await?.result)
    }
}
