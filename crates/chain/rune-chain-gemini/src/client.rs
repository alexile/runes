use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use rune_chain_core::{
    ContentPart, FunctionDefinition, GenerateResult, LlmError, Message, MessageContent,
    ResponseFormat, Role, StreamData, ToolChoice,
};

use crate::config::{SafetySetting, Thinking, ThinkingBudget};
use crate::convert::{build_contents, function_declaration, response_schema, tool_config};
use crate::http::{self, Credential, Transport};
use crate::models::{self, ModelInfo};
use crate::response::GeminiResponse;
use crate::stream::{
    DEFAULT_MAX_STREAM_BYTES, MAX_SSE_EVENT_BYTES, MAX_STREAM_EVENTS, ResponseAccumulator,
    StreamEvent,
};
use crate::types::{GenerateContentRequest, GenerateContentResponse, GenerationConfig, ToolWire};

pub use crate::http::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT,
};

/// Default Gemini API base URL (version included); see [`Gemini::base_url`].
pub const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta";
/// Environment variables [`Gemini::from_env`] reads, in order.
pub const API_KEY_ENV_VARS: [&str; 2] = ["GEMINI_API_KEY", "GOOGLE_API_KEY"];
/// Most stop sequences the API accepts.
pub const MAX_STOP_SEQUENCES: usize = 5;

/// Boxed stream returned by [`Gemini::stream_content`].
pub type ContentStream = Pin<Box<dyn Stream<Item = Result<StreamEvent, LlmError>> + Send>>;

/// Google Gemini client implementing [`Llm`](rune_chain_core::Llm).
///
/// Talks to the Gemini API (`generateContent` / `streamGenerateContent`)
/// or, with [`vertex_ai`](Self::vertex_ai), to Vertex AI. The model is a
/// free-form id (default [`models::DEFAULT_MODEL`], `gemini-2.5-flash`).
///
/// ```rust,no_run
/// use rune_chain_core::{Llm, Message};
/// use rune_chain_gemini::Gemini;
///
/// # tokio_test::block_on(async {
/// let llm = Gemini::from_env().unwrap();
/// let result = llm
///     .generate(&[Message::system("Be terse."), Message::human("Capital of France?")])
///     .await
///     .unwrap();
/// println!("{}", result.generation);
/// # });
/// ```
///
/// # Transport
///
/// - The API key is sent only in the sensitive `x-goog-api-key` header
///   (never in the URL), is never printed by `Debug`, and is scrubbed from
///   error messages. Vertex AI tokens go in `Authorization: Bearer`.
/// - The base URL must be `https://`, except for `localhost` / loopback;
///   the model id must be a plain id (it is part of the URL path).
/// - Retryable failures (408, 429, 5xx, connection errors) are retried
///   [`DEFAULT_MAX_RETRIES`] times, honouring `Retry-After` or the error's
///   `RetryInfo` up to 60 s, otherwise with jittered exponential backoff.
///   Streams are retried only before the first byte.
/// - Blocking bodies are capped at [`DEFAULT_MAX_RESPONSE_BYTES`], streamed
///   content at [`DEFAULT_MAX_STREAM_BYTES`], single SSE lines and events at
///   [`MAX_SSE_EVENT_BYTES`]; error bodies are truncated.
#[derive(Clone)]
pub struct Gemini {
    transport: Transport,
    model: String,
    temperature: Option<f32>,
    top_p: Option<f32>,
    top_k: Option<u32>,
    max_output_tokens: Option<u32>,
    stop_sequences: Vec<String>,
    seed: Option<i32>,
    safety: Vec<SafetySetting>,
    thinking: Option<Thinking>,
    cached_content: Option<String>,
}

impl fmt::Debug for Gemini {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gemini")
            .field("transport", &self.transport)
            .field("model", &self.model)
            .field("temperature", &self.temperature)
            .field("top_p", &self.top_p)
            .field("top_k", &self.top_k)
            .field("max_output_tokens", &self.max_output_tokens)
            .field("stop_sequences", &self.stop_sequences.len())
            .field("seed", &self.seed)
            .field("safety", &self.safety)
            .field("thinking", &self.thinking)
            .finish_non_exhaustive()
    }
}

impl Gemini {
    /// A Gemini API client with the given API key and default settings.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_transport(Transport::new(
            Credential::ApiKey(api_key.into()),
            DEFAULT_BASE_URL,
        ))
    }

    /// A client from `GEMINI_API_KEY` (or, if unset, `GOOGLE_API_KEY`).
    ///
    /// # Errors
    ///
    /// When neither variable is set.
    pub fn from_env() -> Result<Self, LlmError> {
        API_KEY_ENV_VARS
            .iter()
            .find_map(|name| std::env::var(name).ok().filter(|v| !v.trim().is_empty()))
            .map(Self::new)
            .ok_or_else(|| {
                LlmError::other("GEMINI_API_KEY (or GOOGLE_API_KEY) environment variable not set")
            })
    }

    /// A Vertex AI client for `project` in `location` (e.g. `us-central1`,
    /// or `global`), authenticating with an OAuth access token you obtain
    /// yourself (e.g. `gcloud auth print-access-token`). Tokens expire; build
    /// a new client, or use [`bearer_token`](Self::bearer_token), to swap one.
    ///
    /// ```rust
    /// use rune_chain_gemini::Gemini;
    ///
    /// let llm = Gemini::vertex_ai("my-project", "us-central1", "ya29.token").unwrap();
    /// assert_eq!(
    ///     llm.base_url_str(),
    ///     "https://us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1/publishers/google"
    /// );
    /// ```
    ///
    /// # Errors
    ///
    /// A project or location with characters outside `[a-z0-9-]`.
    pub fn vertex_ai(
        project: &str,
        location: &str,
        access_token: impl Into<String>,
    ) -> Result<Self, LlmError> {
        let plain = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        if !plain(project) || !plain(location) {
            return Err(LlmError::other(
                "Vertex AI project and location may hold only a-z, 0-9 and '-'",
            ));
        }
        let host = if location == "global" {
            "aiplatform.googleapis.com".to_string()
        } else {
            format!("{location}-aiplatform.googleapis.com")
        };
        let base =
            format!("https://{host}/v1/projects/{project}/locations/{location}/publishers/google");
        Ok(Self::with_transport(Transport::new(
            Credential::Bearer(access_token.into()),
            &base,
        )))
    }

    fn with_transport(transport: Transport) -> Self {
        Self {
            transport,
            model: models::DEFAULT_MODEL.to_string(),
            temperature: None,
            top_p: None,
            top_k: None,
            max_output_tokens: None,
            stop_sequences: Vec::new(),
            seed: None,
            safety: Vec::new(),
            thinking: None,
            cached_content: None,
        }
    }

    /// Set the model id; any id the API accepts works, e.g. one of the
    /// [`models`] constants. A `models/` prefix is dropped.
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        let model = model.into();
        self.model = model
            .strip_prefix("models/")
            .map_or_else(|| model.clone(), str::to_string);
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
        models::lookup(self.model_id())
    }

    /// Authenticate with an OAuth access token (`Authorization: Bearer`)
    /// instead of an API key, e.g. for Vertex AI behind a custom
    /// [`base_url`](Self::base_url).
    #[must_use]
    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.transport.credential = Credential::Bearer(token.into());
        self
    }

    /// Set the base URL, version included (default [`DEFAULT_BASE_URL`]);
    /// `/models/{model}:generateContent` and friends are appended and a
    /// trailing slash is ignored. It must be `https://` unless the host is
    /// `localhost` or a loopback address, and may not carry a query;
    /// otherwise every request fails locally before credentials are sent.
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.transport.base_url = url.into().trim_end_matches('/').to_string();
        self
    }

    /// The base URL requests go to.
    #[must_use]
    pub fn base_url_str(&self) -> &str {
        &self.transport.base_url
    }

    /// Use a preconfigured HTTP client (proxies, TLS, timeouts). Its redirect
    /// policy applies: the default client follows none, and since a
    /// followed redirect keeps the credential header, set
    /// `.redirect(reqwest::redirect::Policy::none())` on yours too.
    #[must_use]
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.transport.client = client;
        self
    }

    /// Sampling temperature (`0.0..=2.0`).
    #[must_use]
    pub const fn temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Nucleus sampling (`topP`, `0.0..=1.0`).
    #[must_use]
    pub const fn top_p(mut self, top_p: f32) -> Self {
        self.top_p = Some(top_p);
        self
    }

    /// Top-k sampling (`topK`, at least 1).
    #[must_use]
    pub const fn top_k(mut self, top_k: u32) -> Self {
        self.top_k = Some(top_k);
        self
    }

    /// Cap on generated tokens, thinking included (`maxOutputTokens`;
    /// default: the model's own limit).
    #[must_use]
    pub const fn max_output_tokens(mut self, tokens: u32) -> Self {
        self.max_output_tokens = Some(tokens);
        self
    }

    /// Alias of [`max_output_tokens`](Self::max_output_tokens).
    #[must_use]
    pub const fn max_tokens(self, tokens: u32) -> Self {
        self.max_output_tokens(tokens)
    }

    /// Stop sequences (at most [`MAX_STOP_SEQUENCES`]).
    #[must_use]
    pub fn stop_sequences<I, S>(mut self, stops: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.stop_sequences = stops.into_iter().map(Into::into).collect();
        self
    }

    /// Sampling seed, for best-effort reproducible output.
    #[must_use]
    pub const fn seed(mut self, seed: i32) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Set the threshold of one harm category, replacing an earlier
    /// setting for it.
    ///
    /// ```rust
    /// use rune_chain_gemini::{Gemini, HarmBlockThreshold, HarmCategory};
    ///
    /// let llm = Gemini::new("key")
    ///     .safety(HarmCategory::DangerousContent, HarmBlockThreshold::BlockOnlyHigh);
    /// ```
    #[must_use]
    pub fn safety(
        mut self,
        category: crate::HarmCategory,
        threshold: crate::HarmBlockThreshold,
    ) -> Self {
        self.safety.retain(|s| s.category != category);
        self.safety.push(SafetySetting::new(category, threshold));
        self
    }

    /// Replace all safety settings.
    #[must_use]
    pub fn safety_settings(mut self, settings: impl IntoIterator<Item = SafetySetting>) -> Self {
        self.safety = settings.into_iter().collect();
        self
    }

    /// Thinking configuration (default: the model's own). See [`Thinking`].
    #[must_use]
    pub const fn thinking(mut self, thinking: Thinking) -> Self {
        self.thinking = Some(thinking);
        self
    }

    /// Use explicit context cache `cachedContents/…` created through the
    /// caching API.
    #[must_use]
    pub fn cached_content(mut self, name: impl Into<String>) -> Self {
        self.cached_content = Some(name.into());
        self
    }

    /// Retries after a retryable failure (default [`DEFAULT_MAX_RETRIES`];
    /// `0` disables them).
    #[must_use]
    pub const fn max_retries(mut self, retries: u32) -> Self {
        self.transport.max_retries = retries;
        self
    }

    /// Total timeout of blocking requests (default [`DEFAULT_TIMEOUT`]).
    /// Streams are bounded by the HTTP client's read timeout instead.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.transport.timeout = timeout;
        self
    }

    /// Cap blocking response bodies and streamed content at `bytes`
    /// (defaults [`DEFAULT_MAX_RESPONSE_BYTES`] and
    /// [`DEFAULT_MAX_STREAM_BYTES`]).
    #[must_use]
    pub const fn max_response_bytes(mut self, bytes: usize) -> Self {
        self.transport.max_response_bytes = bytes;
        self
    }

    #[cfg(feature = "embed")]
    pub(crate) const fn transport(&self) -> &Transport {
        &self.transport
    }

    const fn stream_limit(&self) -> usize {
        if self.transport.max_response_bytes == DEFAULT_MAX_RESPONSE_BYTES {
            DEFAULT_MAX_STREAM_BYTES
        } else {
            self.transport.max_response_bytes
        }
    }

    /// Reject, before any network I/O, requests that cannot succeed.
    fn preflight(&self, messages: &[Message]) -> Result<(), LlmError> {
        http::check_base_url(&self.transport.base_url)?;
        http::check_model_id(self.model_id())?;
        if let Some(t) = self.temperature
            && !(t.is_finite() && (0.0..=2.0).contains(&t))
        {
            return Err(LlmError::other("temperature must be within 0.0..=2.0"));
        }
        if let Some(p) = self.top_p
            && !(p.is_finite() && (0.0..=1.0).contains(&p))
        {
            return Err(LlmError::other("top_p must be within 0.0..=1.0"));
        }
        if self.top_k == Some(0) {
            return Err(LlmError::other("top_k must be at least 1"));
        }
        if self.max_output_tokens == Some(0) {
            return Err(LlmError::other("max_output_tokens must be at least 1"));
        }
        if self.stop_sequences.len() > MAX_STOP_SEQUENCES {
            return Err(LlmError::other(format!(
                "at most {MAX_STOP_SEQUENCES} stop sequences are accepted"
            )));
        }
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
        if !messages.iter().any(|m| m.role != Role::System) {
            return Err(LlmError::other(
                "nothing to send: the conversation has no user or model turn",
            ));
        }
        if let Some(thinking) = self.thinking {
            thinking.to_wire().map_err(LlmError::other)?;
            self.check_thinking(thinking)?;
        }
        Ok(())
    }

    /// Thinking settings a known model is documented to reject.
    fn check_thinking(&self, thinking: Thinking) -> Result<(), LlmError> {
        let Some(info) = self.model_info() else {
            return Ok(());
        };
        let id = info.id;
        let Some(support) = info.thinking else {
            return Err(LlmError::other(format!(
                "model `{id}` does not think; remove `.thinking(..)`"
            )));
        };
        match thinking.budget {
            Some(ThinkingBudget::Off) if !support.can_disable => {
                return Err(LlmError::other(format!(
                    "model `{id}` cannot turn thinking off"
                )));
            }
            Some(ThinkingBudget::Tokens(n)) => {
                if let Some((lo, hi)) = support.budget_range
                    && !(lo..=hi).contains(&n)
                {
                    return Err(LlmError::other(format!(
                        "model `{id}` accepts thinking budgets of {lo}..={hi} tokens"
                    )));
                }
            }
            _ => {}
        }
        if let Some(level) = thinking.level
            && !support.levels.contains(&level)
        {
            return Err(LlmError::other(format!(
                "model `{id}` does not accept thinking level `{}`",
                level.as_str()
            )));
        }
        Ok(())
    }

    /// Translate messages, tools and tool choice into a request body.
    fn request_body(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<&ToolChoice>,
    ) -> Result<GenerateContentRequest, LlmError> {
        let (system_instruction, contents) = build_contents(messages)?;
        let declarations = tools
            .iter()
            .map(function_declaration)
            .collect::<Result<Vec<_>, _>>()?;
        let tools_wire = if declarations.is_empty() {
            Vec::new()
        } else {
            vec![ToolWire {
                function_declarations: declarations,
            }]
        };
        let thinking_config = self
            .thinking
            .map(Thinking::to_wire)
            .transpose()
            .map_err(LlmError::other)?;
        Ok(GenerateContentRequest {
            contents,
            system_instruction,
            tools: tools_wire,
            tool_config: tool_config(tool_choice, tools)?,
            safety_settings: self.safety.clone(),
            generation_config: GenerationConfig {
                temperature: self.temperature,
                top_p: self.top_p,
                top_k: self.top_k,
                max_output_tokens: self.max_output_tokens,
                stop_sequences: self.stop_sequences.clone(),
                seed: self.seed,
                response_mime_type: None,
                response_schema: None,
                thinking_config,
            },
            cached_content: self.cached_content.clone(),
        })
    }

    async fn complete(&self, body: &GenerateContentRequest) -> Result<GeminiResponse, LlmError> {
        let url = self
            .transport
            .model_url(self.model_id(), "generateContent")?;
        let bytes = self.transport.post_json(&url, body).await?;
        decode_response(&bytes)
    }

    /// Generate a full [`GeminiResponse`] — thoughts, signatures, the raw
    /// finish reason, safety ratings and the usage breakdown — with optional
    /// tools.
    ///
    /// # Errors
    ///
    /// As [`Llm::generate_with_tools`](rune_chain_core::Llm::generate_with_tools);
    /// a blocked prompt is an error of kind `Provider`.
    pub async fn generate_content(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GeminiResponse, LlmError> {
        self.preflight(messages)?;
        let body = self.request_body(messages, tools, tool_choice.as_ref())?;
        self.complete(&body).await
    }

    /// Stream a response as typed [`StreamEvent`]s (`streamGenerateContent`
    /// with `alt=sse`): text and thought fragments, complete function calls,
    /// and finally the whole [`GeminiResponse`].
    ///
    /// # Errors
    ///
    /// Opening the stream fails like [`generate_content`](Self::generate_content);
    /// the stream itself yields at most one error and then ends.
    pub async fn stream_content(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<ContentStream, LlmError> {
        self.preflight(messages)?;
        let body = self.request_body(messages, tools, tool_choice.as_ref())?;
        let url = self
            .transport
            .model_url(self.model_id(), "streamGenerateContent")?;
        let response = self
            .transport
            .send(&format!("{url}?alt=sse"), &body, true)
            .await?;
        let acc = ResponseAccumulator::with_limit(self.stream_limit())
            .scrubbing(self.transport.credential.clone());
        Ok(Box::pin(assemble_events(
            Box::pin(response.bytes_stream()),
            acc,
        )))
    }
}

/// Decode a successful `generateContent` body.
fn decode_response(body: &[u8]) -> Result<GeminiResponse, LlmError> {
    let wire: GenerateContentResponse =
        serde_json::from_slice(body).map_err(|e| LlmError::invalid_response(e.to_string()))?;
    GeminiResponse::from_wire(wire)
}

/// Reject responses that cannot hold a complete structured answer.
fn check_structured(response: &GeminiResponse) -> Result<(), LlmError> {
    if response.is_filtered() {
        return Err(LlmError::provider(format!(
            "the response was stopped by a content filter (finishReason: {})",
            response.finish_reason.as_deref().unwrap_or_default()
        )));
    }
    if response.is_truncated() {
        return Err(LlmError::invalid_response(
            "structured output was cut off at maxOutputTokens; raise `.max_output_tokens(..)`",
        ));
    }
    Ok(())
}

/// Turn a byte stream of SSE (an HTTP response body) into typed events.
///
/// The stream ends after [`StreamEvent::Done`] or the first error. A body
/// that ends before any chunk carried a finish reason yields a final
/// [`LlmError::invalid_response`].
fn assemble_events<S, B, E>(
    body: S,
    mut acc: ResponseAccumulator,
) -> impl Stream<Item = Result<StreamEvent, LlmError>> + Send
where
    S: Stream<Item = Result<B, E>> + Send + Unpin,
    B: AsRef<[u8]>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let options = rune_sse::Options::default()
        .with_max_event_len(MAX_SSE_EVENT_BYTES)
        .with_max_line_len(MAX_SSE_EVENT_BYTES);
    let mut events = rune_sse::SseStream::with_options(body, options);
    async_stream::stream! {
        let mut seen = 0usize;
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
            seen += 1;
            if seen > MAX_STREAM_EVENTS {
                yield Err(LlmError::invalid_response("too many stream events"));
                return;
            }
            if event.data.trim().is_empty() {
                continue;
            }
            match acc.push(&event.data) {
                Ok(list) => {
                    for ev in list {
                        yield Ok(ev);
                    }
                }
                Err(e) => {
                    yield Err(e);
                    return;
                }
            }
        }
        match acc.finish() {
            Ok(done) => yield Ok(StreamEvent::Done(done)),
            Err(e) => yield Err(e),
        }
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
impl rune_chain_core::Llm for Gemini {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.generate_content(messages, &[], None)
            .await
            .map(|r| r.to_generate_result())
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        self.generate_content(messages, tools, tool_choice)
            .await
            .map(|r| r.to_generate_result())
    }

    /// Streams text only. The final chunk carries no finish reason or
    /// usage; use [`Gemini::stream_content`] when you need those.
    async fn stream(
        &self,
        messages: &[Message],
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>, LlmError> {
        let events = self.stream_content(messages, &[], None).await?;
        Ok(Box::pin(text_chunks(events)))
    }

    /// Native JSON mode: `responseMimeType: application/json`, plus
    /// `responseSchema` for [`ResponseFormat::JsonSchema`] (converted to
    /// Gemini's schema subset). A schema Gemini cannot express falls back to
    /// JSON mode with the schema given as instructions. Responses stopped by
    /// a content filter or cut off at `maxOutputTokens` are errors.
    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        if !format.is_json() {
            return self.generate(messages).await;
        }
        let (schema, prompt_fallback) = format.schema().map_or((None, false), |schema| {
            response_schema(schema).map_or((None, true), |converted| (converted, false))
        });
        let owned;
        let messages = if prompt_fallback {
            owned = format.apply_to(messages);
            &owned[..]
        } else {
            messages
        };
        self.preflight(messages)?;
        let mut body = self.request_body(messages, &[], None)?;
        body.generation_config.response_mime_type = Some("application/json");
        body.generation_config.response_schema = schema;
        let response = self.complete(&body).await?;
        check_structured(&response)?;
        Ok(response.to_generate_result())
    }
}

#[cfg(test)]
mod tests;
