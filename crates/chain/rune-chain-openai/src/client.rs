use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use reqwest::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use rune_chain_core::{
    ContentPart, FinishReason, FunctionDefinition, GenerateResult, ImageData, LlmError, Message,
    MessageContent, ReasoningBlock, ResponseFormat, Role, StreamData, ToolCall, ToolChoice,
};
use serde_json::Value;

use crate::http::{self, ApiKey};
use crate::models::{self, ModelInfo};
use crate::provider::{AuthStyle, MaxTokensField, Provider, Quirks};
use crate::stream::{self, EventStream};
use crate::types::{
    ApiContentPart, ApiFunctionCall, ApiMessage, ApiMessageContent, ApiResponseFormat, ApiToolCall,
    ChatRequest, ChatResponse, ImageUrlContent, JsonSchemaSpec, OpenAiFunctionDef,
    OpenAiNamedFunction, OpenAiNamedTool, OpenAiToolChoice, OpenAiToolDef, StreamOptions,
    error_message,
};

#[cfg(test)]
mod tests;

/// Default API base URL; see [`OpenAi::base_url`].
pub const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
/// `api-version` used by [`OpenAi::azure`] unless overridden with
/// [`OpenAi::api_version`].
pub const AZURE_DEFAULT_API_VERSION: &str = "2024-10-21";
/// Default whole-request timeout (10 minutes: reasoning models can think for
/// a long time before the first byte); see [`OpenAi::timeout`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
/// TCP/TLS connect timeout of the default HTTP client.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Default retries after a 429 or 5xx response; see [`OpenAi::max_retries`].
pub const DEFAULT_MAX_RETRIES: u32 = 2;
/// Default response-size cap (32 MiB); see [`OpenAi::max_response_bytes`].
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 << 20;
const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(500);
const CHAT_PATH: &str = "/chat/completions";

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Chat-completions client implementing [`Llm`](rune_chain_core::Llm) for
/// `OpenAI` and OpenAI-compatible providers.
///
/// Supports multi-modal input, native function/tool calling, streaming
/// (with tool-call and usage reporting via [`stream_events`](Self::stream_events)),
/// and native structured output via
/// [`generate_structured`](rune_chain_core::Llm::generate_structured).
/// The model is a free-form id (default [`models::DEFAULT_MODEL`],
/// `gpt-5-mini`); see [`models`] for constants and capability notes and
/// [`Provider`] for compatible-server presets.
///
/// The `Debug` output never contains the API key.
///
/// # Quick start
///
/// ```rust,no_run
/// use rune_chain_openai::OpenAi;
/// use rune_chain_core::{Llm, Message};
///
/// # tokio_test::block_on(async {
/// let llm = OpenAi::from_env().unwrap();
/// let result = llm.generate(&[
///     Message::system("You are helpful."),
///     Message::human("What is 2 + 2?"),
/// ]).await.unwrap();
/// println!("{}", result.generation);
/// # });
/// ```
#[derive(Clone)]
pub struct OpenAi {
    api_key: ApiKey,
    provider: Provider,
    quirks: Quirks,
    model: String,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
    base_url: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    allowed_http_hosts: Vec<String>,
    timeout: Option<Duration>,
    max_retries: u32,
    retry_delay: Duration,
    max_response_bytes: usize,
    pub(crate) max_upload_bytes: usize,
    pub(crate) max_media_response_bytes: usize,
    client: reqwest::Client,
}

/// Shows custom header and query parameter names only: their values often
/// carry gateway tokens.
impl fmt::Debug for OpenAi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = |pairs: &[(String, String)]| -> Vec<String> {
            pairs.iter().map(|(name, _)| name.clone()).collect()
        };
        f.debug_struct("OpenAi")
            .field("api_key", &self.api_key)
            .field("provider", &self.provider)
            .field("quirks", &self.quirks)
            .field("model", &self.model)
            .field("temperature", &self.temperature)
            .field("max_tokens", &self.max_tokens)
            .field("base_url", &self.base_url)
            .field("query_params", &names(&self.query))
            .field("headers", &names(&self.headers))
            .field("allowed_http_hosts", &self.allowed_http_hosts)
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .field("retry_delay", &self.retry_delay)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_upload_bytes", &self.max_upload_bytes)
            .field("max_media_response_bytes", &self.max_media_response_bytes)
            .field("client", &self.client)
            .finish()
    }
}

fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        // Never follow redirects: a redirect could forward the `api-key`
        // header (which reqwest does not strip) or downgrade to plain HTTP.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

/// Percent-encode a URL path segment (everything but RFC 3986 unreserved).
fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0xF)]));
        }
    }
    out
}

impl OpenAi {
    /// Create an `OpenAI` client with the given API key and default settings.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::for_provider(Provider::OpenAi, api_key)
    }

    /// Create a client for an OpenAI-compatible [`Provider`] preset: its base
    /// URL, quirks and default model. For vLLM and LM Studio the key may be
    /// empty; for Azure use [`azure`](Self::azure).
    ///
    /// ```rust
    /// use rune_chain_openai::{OpenAi, Provider};
    ///
    /// let llm = OpenAi::for_provider(Provider::Groq, "gsk-example")
    ///     .model("llama-3.1-8b-instant");
    /// assert_eq!(llm.base_url_str(), "https://api.groq.com/openai/v1");
    /// ```
    pub fn for_provider(provider: Provider, api_key: impl Into<String>) -> Self {
        Self {
            api_key: ApiKey::new(api_key),
            provider,
            quirks: provider.quirks(),
            model: provider.default_model().unwrap_or_default().to_string(),
            temperature: None,
            max_tokens: None,
            base_url: provider.default_base_url().unwrap_or_default().to_string(),
            query: Vec::new(),
            headers: Vec::new(),
            allowed_http_hosts: Vec::new(),
            timeout: Some(DEFAULT_TIMEOUT),
            max_retries: DEFAULT_MAX_RETRIES,
            retry_delay: DEFAULT_RETRY_DELAY,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_upload_bytes: crate::media::DEFAULT_MAX_UPLOAD_BYTES,
            max_media_response_bytes: crate::media::DEFAULT_MAX_MEDIA_RESPONSE_BYTES,
            client: default_http_client(),
        }
    }

    /// Create an `OpenAI` client from the `OPENAI_API_KEY` environment variable.
    pub fn from_env() -> Result<Self, LlmError> {
        Self::from_provider_env(Provider::OpenAi)
    }

    /// Create a client for `provider`, reading the key from its
    /// [`api_key_env`](Provider::api_key_env) variable (optional for vLLM and
    /// LM Studio). For Azure use [`azure_from_env`](Self::azure_from_env).
    pub fn from_provider_env(provider: Provider) -> Result<Self, LlmError> {
        if provider == Provider::AzureOpenAi {
            return Err(LlmError::other(
                "use OpenAi::azure_from_env(deployment) for Azure OpenAI",
            ));
        }
        let key = match provider.api_key_env() {
            Some(var) => match std::env::var(var) {
                Ok(key) => key,
                Err(_) if provider.key_optional() => String::new(),
                Err(_) => {
                    return Err(LlmError::other(format!(
                        "{var} environment variable not set"
                    )));
                }
            },
            None => String::new(),
        };
        Ok(Self::for_provider(provider, key))
    }

    /// Mistral La Plateforme (default model `mistral-small-latest`).
    pub fn mistral(api_key: impl Into<String>) -> Self {
        Self::for_provider(Provider::Mistral, api_key)
    }

    /// Groq (default model `llama-3.3-70b-versatile`).
    pub fn groq(api_key: impl Into<String>) -> Self {
        Self::for_provider(Provider::Groq, api_key)
    }

    /// Together AI (default model `meta-llama/Llama-3.3-70B-Instruct-Turbo`).
    pub fn together(api_key: impl Into<String>) -> Self {
        Self::for_provider(Provider::Together, api_key)
    }

    /// `DeepSeek` (default model `deepseek-chat`).
    pub fn deepseek(api_key: impl Into<String>) -> Self {
        Self::for_provider(Provider::DeepSeek, api_key)
    }

    /// `OpenRouter` (default model `openrouter/auto`). Models are
    /// `vendor/model` ids; `openai/…` ids get `OpenAI` capability notes.
    pub fn openrouter(api_key: impl Into<String>) -> Self {
        Self::for_provider(Provider::OpenRouter, api_key)
    }

    /// A vLLM server at `base_url` (e.g. `http://localhost:8000/v1`) serving
    /// `model`. Add a key with [`api_key`](Self::api_key) if the server was
    /// started with `--api-key`.
    pub fn vllm(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self::for_provider(Provider::Vllm, "")
            .base_url(base_url)
            .model(model)
    }

    /// LM Studio's local server (`http://localhost:1234/v1`) with `model`
    /// loaded.
    pub fn lm_studio(model: impl Into<String>) -> Self {
        Self::for_provider(Provider::LmStudio, "").model(model)
    }

    /// Azure `OpenAI`: `endpoint` is the resource URL
    /// (`https://<resource>.openai.azure.com`), `deployment` the deployment
    /// name. Requests go to
    /// `{endpoint}/openai/deployments/{deployment}/chat/completions?api-version=…`
    /// with an `api-key` header. The deployment name doubles as the model id
    /// (for capability notes); override with [`model`](Self::model) if the
    /// deployment is named differently from its model.
    ///
    /// ```rust
    /// use rune_chain_openai::{OpenAi, Provider};
    ///
    /// let llm = OpenAi::azure("https://contoso.openai.azure.com/", "gpt-4o", "key")
    ///     .api_version("2024-10-21");
    /// assert_eq!(llm.provider(), Provider::AzureOpenAi);
    /// assert_eq!(
    ///     llm.chat_url().unwrap().as_str(),
    ///     "https://contoso.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21"
    /// );
    /// ```
    pub fn azure(
        endpoint: impl Into<String>,
        deployment: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        let endpoint = endpoint.into();
        let deployment = deployment.into();
        let base = format!(
            "{}/openai/deployments/{}",
            endpoint.trim_end_matches('/'),
            encode_segment(&deployment)
        );
        Self::for_provider(Provider::AzureOpenAi, api_key)
            .base_url(base)
            .model(deployment)
            .api_version(AZURE_DEFAULT_API_VERSION)
    }

    /// Azure `OpenAI` from `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_API_KEY`,
    /// plus `OPENAI_API_VERSION` if set.
    pub fn azure_from_env(deployment: impl Into<String>) -> Result<Self, LlmError> {
        let var = |name: &str| {
            std::env::var(name)
                .map_err(|_| LlmError::other(format!("{name} environment variable not set")))
        };
        let llm = Self::azure(
            var("AZURE_OPENAI_ENDPOINT")?,
            deployment,
            var("AZURE_OPENAI_API_KEY")?,
        );
        Ok(match std::env::var("OPENAI_API_VERSION") {
            Ok(v) if !v.is_empty() => llm.api_version(v),
            _ => llm,
        })
    }

    /// Replace the API key.
    #[must_use]
    pub fn api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = ApiKey::new(api_key);
        self
    }

    /// The provider preset this client was built from.
    #[must_use]
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    /// Override the wire-format [`Quirks`] (start from
    /// [`Provider::quirks`]).
    #[must_use]
    pub const fn quirks(mut self, quirks: Quirks) -> Self {
        self.quirks = quirks;
        self
    }

    /// The wire-format quirks in effect.
    #[must_use]
    pub const fn active_quirks(&self) -> Quirks {
        self.quirks
    }

    /// Set the model id. Any id the server accepts works, e.g. one of the
    /// [`models`] constants or a newer release this crate does not know.
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

    /// Capability note for this client's model, if it is a known `OpenAI`
    /// model (`OpenRouter`'s `openai/…` ids included).
    #[must_use]
    pub fn model_info(&self) -> Option<&'static ModelInfo> {
        let id = match self.provider {
            Provider::OpenRouter => self.model.strip_prefix("openai/")?,
            _ => &self.model,
        };
        models::lookup(id)
    }

    /// Set the sampling temperature.
    ///
    /// Reasoning models accept only the default; for a known model whose
    /// [`ModelInfo::sampling_params`] is `false`, requests fail locally.
    #[must_use]
    pub const fn temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Set the maximum number of tokens to generate (sent as
    /// `max_completion_tokens` or `max_tokens` per
    /// [`Quirks::max_tokens_field`]).
    #[must_use]
    pub const fn max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Set the API base URL (default: the provider's), e.g. an
    /// OpenAI-compatible server, a proxy, or a local mock server in tests.
    /// `/chat/completions` is appended; a trailing slash is ignored.
    ///
    /// The URL must be `https`, or `http` to `localhost`/a loopback address,
    /// or `http` to a host allowed with [`allow_http_host`](Self::allow_http_host);
    /// otherwise requests fail locally before the key is sent.
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

    /// Allow plain `http` to `host` (e.g. a model server on a trusted LAN).
    /// Loopback hosts are always allowed.
    #[must_use]
    pub fn allow_http_host(mut self, host: impl Into<String>) -> Self {
        self.allowed_http_hosts.push(host.into());
        self
    }

    /// Set the Azure `api-version` query parameter.
    #[must_use]
    pub fn api_version(self, version: impl Into<String>) -> Self {
        self.query_param("api-version", version)
    }

    /// Add (or replace) a query parameter sent with every request.
    #[must_use]
    pub fn query_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        self.query.retain(|(n, _)| *n != name);
        self.query.push((name, value.into()));
        self
    }

    /// Add a header sent with every request, e.g. `OpenRouter`'s
    /// `HTTP-Referer`/`X-Title` or `OpenAI-Organization`. Invalid names or
    /// values make requests fail locally.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Whole-request timeout (default [`DEFAULT_TIMEOUT`]), applied per
    /// attempt and overriding any timeout on a custom
    /// [`http_client`](Self::http_client). For streams it bounds the whole
    /// stream.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Retries after a 429 or 5xx response (default
    /// [`DEFAULT_MAX_RETRIES`]; `0` disables). The server's `Retry-After` /
    /// `retry-after-ms` is honoured up to 60 s (a longer one is returned as
    /// the error); otherwise backoff is exponential from
    /// [`retry_delay`](Self::retry_delay). Transport errors and other
    /// statuses are never retried.
    #[must_use]
    pub const fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Base delay of the exponential retry backoff (default 500 ms).
    #[must_use]
    pub const fn retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }

    /// Largest response body accepted (default
    /// [`DEFAULT_MAX_RESPONSE_BYTES`]). For streams it caps the total bytes
    /// read.
    #[must_use]
    pub const fn max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }

    /// Largest audio file [`transcribe`](rune_chain_core::TranscriptionModel::transcribe)
    /// uploads (default [`DEFAULT_MAX_UPLOAD_BYTES`](crate::DEFAULT_MAX_UPLOAD_BYTES),
    /// `OpenAI`'s 25 MB limit). Bigger files fail locally.
    #[must_use]
    pub const fn max_upload_bytes(mut self, bytes: usize) -> Self {
        self.max_upload_bytes = bytes;
        self
    }

    /// Largest image-generation or speech response accepted (default
    /// [`DEFAULT_MAX_MEDIA_RESPONSE_BYTES`](crate::DEFAULT_MAX_MEDIA_RESPONSE_BYTES)).
    /// Base64 images count at their encoded size.
    #[must_use]
    pub const fn max_media_response_bytes(mut self, bytes: usize) -> Self {
        self.max_media_response_bytes = bytes;
        self
    }

    /// The response cap for chat and transcription bodies.
    pub(crate) const fn response_limit(&self) -> usize {
        self.max_response_bytes
    }

    /// Use a preconfigured HTTP client (proxies, TLS settings). The default
    /// client has a connect timeout and does not follow redirects; consider
    /// doing the same.
    #[must_use]
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// The full chat-completions URL, after the transport policy check.
    ///
    /// # Errors
    ///
    /// [`LlmError::other`] for an unparsable URL, embedded credentials, or
    /// plain HTTP to a non-loopback host that was not allowed.
    pub fn chat_url(&self) -> Result<reqwest::Url, LlmError> {
        self.endpoint_url(CHAT_PATH)
    }

    /// `path` (e.g. `/audio/speech`) under the base URL, with the query
    /// parameters, after the transport policy check.
    pub(crate) fn endpoint_url(&self, path: &str) -> Result<reqwest::Url, LlmError> {
        if self.base_url.is_empty() {
            return Err(LlmError::other(format!(
                "no base URL configured for provider `{}`",
                self.provider
            )));
        }
        let mut url = http::check_url(
            &format!("{}{path}", self.base_url),
            &self.allowed_http_hosts,
        )?;
        if !self.query.is_empty() {
            url.query_pairs_mut().extend_pairs(&self.query);
        }
        Ok(url)
    }
}

/// `null` content is only valid on an assistant turn that carries tool calls;
/// every other role gets `""` so the request isn't rejected.
fn content_to_api(content: &MessageContent, null_if_empty: bool) -> Option<ApiMessageContent> {
    match content {
        MessageContent::Text(s) if s.is_empty() && null_if_empty => None,
        MessageContent::Text(s) => Some(ApiMessageContent::Text(s.clone())),
        MessageContent::Parts(parts) => {
            let api_parts: Vec<ApiContentPart> = parts
                .iter()
                .map(|p| match p {
                    ContentPart::Text { text } => ApiContentPart::Text { text: text.clone() },
                    ContentPart::Image { image } => ApiContentPart::ImageUrl {
                        image_url: match image {
                            ImageData::Url { url } => ImageUrlContent {
                                url: url.clone(),
                                detail: None,
                            },
                            ImageData::Base64 { mime_type, data } => ImageUrlContent {
                                url: format!("data:{mime_type};base64,{data}"),
                                detail: None,
                            },
                        },
                    },
                })
                .collect();
            Some(ApiMessageContent::Parts(api_parts))
        }
    }
}

/// Reject malformed or oversized images before they are sent.
fn validate_images(messages: &[Message]) -> Result<(), LlmError> {
    for (i, m) in messages.iter().enumerate() {
        if let MessageContent::Parts(parts) = &m.content {
            for p in parts {
                if let ContentPart::Image { image } = p {
                    image
                        .validate_default()
                        .map_err(|e| LlmError::other(format!("message {i}: {e}")))?;
                }
            }
        }
    }
    Ok(())
}

fn map_messages(messages: &[Message]) -> Vec<ApiMessage> {
    messages
        .iter()
        .map(|m| ApiMessage {
            role: match m.role {
                Role::System => "system",
                Role::Human => "user",
                Role::Ai => "assistant",
                Role::Tool => "tool",
            },
            content: content_to_api(&m.content, m.role == Role::Ai && !m.tool_calls.is_empty()),
            tool_calls: m
                .tool_calls
                .iter()
                .map(|tc| ApiToolCall {
                    id: tc.id.clone(),
                    kind: "function",
                    function: ApiFunctionCall {
                        name: tc.name.clone(),
                        arguments: tc.arguments.clone(),
                    },
                })
                .collect(),
            tool_call_id: m.tool_call_id.clone(),
        })
        .collect()
}

fn map_tool_defs(tools: &[FunctionDefinition]) -> Vec<OpenAiToolDef> {
    tools
        .iter()
        .map(|d| OpenAiToolDef {
            kind: "function",
            function: OpenAiFunctionDef {
                name: d.name.clone(),
                description: d.description.clone(),
                parameters: d.parameters.clone(),
            },
        })
        .collect()
}

fn map_tool_choice(tc: &ToolChoice) -> OpenAiToolChoice {
    match tc {
        ToolChoice::Auto => OpenAiToolChoice::String("auto"),
        ToolChoice::None => OpenAiToolChoice::String("none"),
        ToolChoice::Required => OpenAiToolChoice::String("required"),
        ToolChoice::Tool(name) => OpenAiToolChoice::Named(OpenAiNamedTool {
            kind: "function",
            function: OpenAiNamedFunction { name: name.clone() },
        }),
    }
}

/// `OpenAI` schema names: `[A-Za-z0-9_-]{1,64}`.
fn valid_schema_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Map a non-success response to an error: the kind comes from the status,
/// refined by the body's error code; the message is the provider's when the
/// body is a recognised error object, a truncated raw body otherwise.
fn decode_error(status: u16, body: &[u8], retry_after: Option<Duration>) -> LlmError {
    let text = String::from_utf8_lossy(body);
    let value: Option<Value> = serde_json::from_str(&text).ok();
    let err = value.as_ref().and_then(error_message).map_or_else(
        || {
            LlmError::from_status(
                status,
                format!(
                    "HTTP {status}: {}",
                    http::truncate(&text, http::MAX_ERROR_CHARS)
                ),
            )
        },
        |msg| {
            LlmError::from_status(
                status,
                format!(
                    "{} (HTTP {status})",
                    http::truncate(&msg, http::MAX_ERROR_CHARS)
                ),
            )
        },
    );
    let err = match value.as_ref().and_then(crate::types::error_kind) {
        Some(kind) => err.with_kind(kind),
        None => err,
    };
    match retry_after {
        Some(wait) => err.with_retry_after(wait),
        None => err,
    }
}

/// Decode a successful `/chat/completions` body.
fn decode_response(body: &[u8]) -> Result<GenerateResult, LlmError> {
    let chat: ChatResponse =
        serde_json::from_slice(body).map_err(|e| LlmError::invalid_response(e.to_string()))?;
    Ok(parse_response(chat))
}

fn parse_response(chat: ChatResponse) -> GenerateResult {
    let tokens = chat.usage.map(crate::types::UsageReport::into_usage);
    let Some(choice) = chat.choices.into_iter().next() else {
        return GenerateResult::from_text("").with_tokens(tokens);
    };
    let message = choice.message;
    let mut finish_reason = choice
        .finish_reason
        .as_deref()
        .map(crate::types::finish_reason);

    let mut generation = message
        .content
        .map(|c| match c {
            ApiMessageContent::Text(s) => s,
            ApiMessageContent::Parts(parts) => parts
                .into_iter()
                .filter_map(|p| match p {
                    ApiContentPart::Text { text } => Some(text),
                    _ => None,
                })
                .collect::<String>(),
        })
        .unwrap_or_default();

    if generation.is_empty()
        && message.tool_calls.is_empty()
        && let Some(refusal) = message.refusal.filter(|r| !r.is_empty())
    {
        generation = refusal;
        finish_reason = Some(FinishReason::Refusal);
    }

    let tool_calls: Vec<ToolCall> = message
        .tool_calls
        .into_iter()
        .enumerate()
        .map(|(i, tc)| ToolCall {
            id: if tc.id.is_empty() {
                format!("call_{i}")
            } else {
                tc.id
            },
            name: tc.function.name,
            arguments: tc.function.arguments,
        })
        .collect();

    let reasoning = message
        .reasoning_content
        .filter(|r| !r.is_empty())
        .map(|r| vec![ReasoningBlock::new(r)])
        .unwrap_or_default();

    let result = GenerateResult::from_text(generation)
        .with_tokens(tokens)
        .with_tool_calls(tool_calls)
        .with_reasoning(reasoning);
    match finish_reason {
        Some(reason) => result.with_finish_reason(reason),
        None => result,
    }
}

/// Options for one request body.
#[derive(Default)]
struct BodyOptions<'a> {
    tools: &'a [FunctionDefinition],
    tool_choice: Option<&'a ToolChoice>,
    stream: bool,
    include_usage: bool,
    response_format: Option<ApiResponseFormat>,
}

impl OpenAi {
    /// Reject, before any network I/O, settings that cannot work: a bad URL,
    /// invalid images, or a temperature on a known reasoning model. Unknown
    /// model ids are passed through unchecked.
    fn preflight(&self, messages: &[Message]) -> Result<(), LlmError> {
        self.chat_url()?;
        validate_images(messages)?;
        match self.model_info() {
            Some(info) if self.temperature.is_some() && !info.sampling_params => {
                Err(LlmError::other(format!(
                    "model `{}` does not accept a sampling temperature; remove `.temperature(..)`",
                    info.id
                )))
            }
            _ => Ok(()),
        }
    }

    /// Build the `/chat/completions` body for this client's settings.
    fn request_body(&self, messages: &[Message], opts: BodyOptions<'_>) -> ChatRequest {
        let (max_completion_tokens, max_tokens) = match self.quirks.max_tokens_field {
            MaxTokensField::MaxCompletionTokens => (self.max_tokens, None),
            MaxTokensField::MaxTokens => (None, self.max_tokens),
        };
        ChatRequest {
            model: self.model.clone(),
            messages: map_messages(messages),
            temperature: self.temperature,
            max_completion_tokens,
            max_tokens,
            stream: opts.stream.then_some(true),
            stream_options: (opts.stream && opts.include_usage && self.quirks.stream_usage_option)
                .then_some(StreamOptions {
                    include_usage: true,
                }),
            tools: map_tool_defs(opts.tools),
            tool_choice: opts.tool_choice.map(map_tool_choice),
            response_format: opts.response_format,
        }
    }

    fn build_request(
        &self,
        url: reqwest::Url,
        payload: Vec<u8>,
        content_type: &str,
    ) -> Result<reqwest::RequestBuilder, LlmError> {
        let content_type = HeaderValue::from_str(content_type)
            .map_err(|_| LlmError::other("invalid request content type"))?;
        let mut req = self
            .client
            .post(url)
            .header(CONTENT_TYPE, content_type)
            .body(payload);
        if let Some(t) = self.timeout {
            req = req.timeout(t);
        }
        for (name, value) in &self.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| LlmError::other(format!("invalid header name `{name}`")))?;
            let value = HeaderValue::from_str(value)
                .map_err(|_| LlmError::other(format!("invalid value for header `{name}`")))?;
            req = req.header(name, value);
        }
        if !self.api_key.is_empty() {
            let (name, value) = match self.quirks.auth {
                AuthStyle::Bearer => (
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", self.api_key.expose()),
                ),
                AuthStyle::ApiKeyHeader => (
                    HeaderName::from_static("api-key"),
                    self.api_key.expose().to_string(),
                ),
            };
            let mut value = HeaderValue::from_str(&value).map_err(|_| {
                LlmError::other("the API key contains characters not allowed in a header")
            })?;
            value.set_sensitive(true);
            req = req.header(name, value);
        }
        Ok(req)
    }

    /// Send with retries on 429/5xx; returns the first successful response.
    async fn send(&self, body: &ChatRequest) -> Result<reqwest::Response, LlmError> {
        let url = self.chat_url()?;
        let payload = serde_json::to_vec(body)
            .map_err(|e| LlmError::other(format!("encode request: {e}")))?;
        self.send_payload(url, payload, "application/json").await
    }

    /// POST `payload` to `url` with retries on 429/5xx; returns the first
    /// successful response. Errors are classified and scrubbed of the key.
    pub(crate) async fn send_payload(
        &self,
        url: reqwest::Url,
        payload: Vec<u8>,
        content_type: &str,
    ) -> Result<reqwest::Response, LlmError> {
        let mut attempt = 0;
        loop {
            let response = self
                .build_request(url.clone(), payload.clone(), content_type)?
                .send()
                .await
                .map_err(|e| {
                    let timed_out = e.is_timeout();
                    let message = self.api_key.scrub(e.without_url().to_string());
                    if timed_out {
                        LlmError::timeout(message)
                    } else {
                        LlmError::request_failed(message)
                    }
                })?;
            let status = response.status();
            if status.is_success() {
                return Ok(response);
            }
            if http::is_retryable(status)
                && attempt < self.max_retries
                && let Some(delay) =
                    http::retry_delay(response.headers(), attempt, self.retry_delay)
            {
                drop(response);
                tokio::time::sleep(delay).await;
                attempt += 1;
                continue;
            }
            let retry_after = http::retry_after(response.headers());
            let body = http::read_body(response, http::MAX_ERROR_BODY, true)
                .await
                .unwrap_or_default();
            return Err(self.scrub(decode_error(status.as_u16(), &body, retry_after)));
        }
    }

    pub(crate) fn scrub(&self, err: LlmError) -> LlmError {
        err.map_message(|m| self.api_key.scrub(m))
    }

    async fn complete(&self, body: &ChatRequest) -> Result<GenerateResult, LlmError> {
        let response = self.send(body).await?;
        let bytes = http::read_body(response, self.max_response_bytes, false).await?;
        decode_response(&bytes).map_err(|e| self.scrub(e))
    }

    /// Send `body` and return the response bytes, capped at
    /// `max_response_bytes` in total.
    async fn open_bytes(
        &self,
        body: &ChatRequest,
    ) -> Result<
        impl Stream<Item = Result<impl AsRef<[u8]> + use<>, BoxError>> + Send + Unpin + use<>,
        LlmError,
    > {
        let response = self.send(body).await?;
        let limit = self.max_response_bytes;
        let mut seen = 0usize;
        let bytes = response
            .bytes_stream()
            .map(move |chunk| -> Result<_, BoxError> {
                let chunk = chunk.map_err(|e| -> BoxError { Box::new(e.without_url()) })?;
                seen = seen.saturating_add(chunk.len());
                if seen > limit {
                    return Err(format!("stream exceeds the {limit}-byte limit").into());
                }
                Ok(chunk)
            });
        Ok(Box::pin(bytes))
    }

    async fn open_stream(&self, body: &ChatRequest) -> Result<EventStream, LlmError> {
        let bytes = self.open_bytes(body).await?;
        Ok(stream::assemble_events(bytes, self.max_response_bytes))
    }

    /// Stream a completion as [`StreamEvent`](crate::StreamEvent)s: text
    /// fragments, assembled tool calls, the finish reason and — where the
    /// provider reports it — token usage (`stream_options.include_usage` is
    /// sent when [`Quirks::stream_usage_option`] is set).
    ///
    /// Use [`collect_events`](crate::collect_events) to fold the stream into
    /// a [`GenerateResult`].
    ///
    /// # Errors
    ///
    /// Pre-flight failures and HTTP errors before the stream starts; errors
    /// inside the stream are yielded as items.
    pub async fn stream_events(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        self.preflight(messages)?;
        let body = self.request_body(
            messages,
            BodyOptions {
                tools,
                tool_choice: tool_choice.as_ref(),
                stream: true,
                include_usage: true,
                ..BodyOptions::default()
            },
        );
        self.open_stream(&body).await
    }

    /// Body and message list for a structured-output request.
    fn structured_body(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<ChatRequest, LlmError> {
        let q = self.quirks;
        let (messages, response_format) = match format {
            ResponseFormat::JsonSchema {
                name,
                schema,
                strict,
            } if q.json_schema => {
                if !valid_schema_name(name) {
                    return Err(LlmError::other(format!(
                        "schema name `{}` must match [A-Za-z0-9_-]{{1,64}}",
                        http::truncate(name, 80)
                    )));
                }
                (
                    messages.to_vec(),
                    Some(ApiResponseFormat::JsonSchema {
                        json_schema: JsonSchemaSpec {
                            name: name.clone(),
                            schema: schema.clone(),
                            strict: *strict,
                        },
                    }),
                )
            }
            f if f.is_json() && q.json_object => {
                (f.apply_to(messages), Some(ApiResponseFormat::JsonObject))
            }
            f => (f.apply_to(messages), None),
        };
        Ok(self.request_body(
            &messages,
            BodyOptions {
                response_format,
                ..BodyOptions::default()
            },
        ))
    }
}

#[async_trait]
impl rune_chain_core::Llm for OpenAi {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.preflight(messages)?;
        self.complete(&self.request_body(messages, BodyOptions::default()))
            .await
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        self.preflight(messages)?;
        let body = self.request_body(
            messages,
            BodyOptions {
                tools,
                tool_choice: tool_choice.as_ref(),
                ..BodyOptions::default()
            },
        );
        self.complete(&body).await
    }

    async fn stream(
        &self,
        messages: &[Message],
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>, LlmError> {
        self.preflight(messages)?;
        let body = self.request_body(
            messages,
            BodyOptions {
                stream: true,
                ..BodyOptions::default()
            },
        );
        Ok(stream::text_stream(self.open_stream(&body).await?))
    }

    /// Native streaming with tool calls: text, reasoning and each tool
    /// call's argument fragments arrive as the server sends them, then usage
    /// (when reported) and the finish reason.
    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<rune_chain_core::EventStream, LlmError> {
        self.preflight(messages)?;
        let body = self.request_body(
            messages,
            BodyOptions {
                tools: tools.unwrap_or_default(),
                tool_choice: tool_choice.as_ref(),
                stream: true,
                include_usage: true,
                ..BodyOptions::default()
            },
        );
        let bytes = self.open_bytes(&body).await?;
        Ok(stream::assemble_core_events(bytes, self.max_response_bytes))
    }

    /// Native structured output. [`ResponseFormat::JsonSchema`] is sent as
    /// `response_format: {"type": "json_schema", …}` with the format's
    /// `strict` flag (strict mode requires `additionalProperties: false` and
    /// every property listed in `required`). Providers without JSON Schema
    /// support ([`Quirks::json_schema`] off) get JSON-object mode plus the
    /// schema in a system prompt; [`ResponseFormat::JsonObject`] adds a
    /// "respond in JSON" system message (`OpenAI` requires the word) and
    /// `json_object` mode. A model refusal, which carries no JSON, is
    /// returned as an [`LlmErrorKind::Provider`](rune_chain_core::LlmErrorKind::Provider)
    /// error.
    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        self.preflight(messages)?;
        let body = self.structured_body(messages, format)?;
        let result = self.complete(&body).await?;
        if result.finish_reason == Some(FinishReason::Refusal) {
            return Err(LlmError::provider(format!(
                "the model refused: {}",
                http::truncate(&result.generation, http::MAX_ERROR_CHARS)
            )));
        }
        Ok(result)
    }
}
