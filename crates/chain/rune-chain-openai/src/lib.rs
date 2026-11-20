//! `OpenAI` and OpenAI-compatible LLM provider for the `rune-chain` framework.
//!
//! Implements [`Llm`](rune_chain_core::Llm) for the chat completions API of
//! `OpenAI` and of servers that speak its dialect. The model is a free-form
//! id: [`models`] has constants for the GPT-5 family (`gpt-5-mini` is the
//! default), GPT-4.1, GPT-4o and the o-series, each with a capability note
//! and list pricing; newer ids work without a crate update.
//!
//! # Features
//!
//! - [`OpenAi`] — the client; configure once, call many times, cheap to clone
//! - **OpenAI-compatible mode** — [`Provider`] presets with per-server
//!   [`Quirks`] for Azure `OpenAI` (deployment URL, `api-version`, `api-key`
//!   header), Mistral, Groq, Together, `DeepSeek`, `OpenRouter`, vLLM and
//!   LM Studio, or any server via [`OpenAi::base_url`]
//! - `generate()` / `generate_with_tools()` — full response with token usage
//!   and native tool calls
//! - `generate_structured()` — native `response_format: json_schema`
//!   (strict), falling back to JSON mode or prompting where unsupported
//! - `stream()` — text chunks; [`OpenAi::stream_events`] adds assembled tool
//!   calls, the finish reason and usage (`stream_options.include_usage`)
//! - **Hardened transport** — the API key is redacted from `Debug` and
//!   errors and sent as a sensitive header; HTTPS is required except to
//!   loopback or explicitly allowed hosts; redirects are not followed;
//!   request timeout, response-size cap, truncated error bodies, and retries
//!   on 429/5xx only, honouring `Retry-After`
//! - **Audio and images** — [`TranscriptionModel`](rune_chain_core::TranscriptionModel)
//!   (`/audio/transcriptions`, multipart upload with a size cap),
//!   [`ImageGenerationModel`](rune_chain_core::ImageGenerationModel)
//!   (`/images/generations`, base64 decoded, `https`-only URLs) and
//!   [`SpeechModel`](rune_chain_core::SpeechModel) (`/audio/speech`), with
//!   capped response bodies
//! - pre-flight checks — a temperature on a known reasoning model, a bad URL
//!   or an invalid image fail locally before any network I/O
//!
//! # OpenAI-compatible servers
//!
//! ```rust
//! use rune_chain_openai::{OpenAi, Provider};
//!
//! let mistral = OpenAi::mistral("key").model("mistral-large-latest");
//! let local = OpenAi::vllm("http://localhost:8000/v1", "Qwen/Qwen2.5-7B-Instruct");
//! let azure = OpenAi::azure("https://contoso.openai.azure.com", "gpt-4o", "key");
//! let custom = OpenAi::for_provider(Provider::OpenRouter, "key")
//!     .model("anthropic/claude-sonnet-4")
//!     .header("X-Title", "my-app");
//!
//! // Plain HTTP to a non-loopback host is refused unless allowed.
//! assert!(OpenAi::new("k").base_url("http://10.0.0.7:8000/v1").chat_url().is_err());
//! assert!(
//!     OpenAi::new("k")
//!         .base_url("http://gpu-box:8000/v1")
//!         .allow_http_host("gpu-box")
//!         .chat_url()
//!         .is_ok()
//! );
//! # let _ = (mistral, local, azure, custom);
//! ```
//!
//! # Configuring a client
//!
//! Building a client is cheap and offline. It implements
//! [`Llm`](rune_chain_core::Llm), so it can be handed to any provider-agnostic
//! chain or agent as a trait object:
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use rune_chain_core::Llm;
//! use rune_chain_openai::{OpenAi, models};
//!
//! fn shared(llm: impl Llm + 'static) -> Arc<dyn Llm> {
//!     Arc::new(llm)
//! }
//!
//! let _llm: Arc<dyn Llm> = shared(
//!     OpenAi::new("sk-example")
//!         .model(models::GPT_4_1_MINI)
//!         .temperature(0.2)
//!         .max_tokens(256),
//! );
//! ```
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use rune_chain_openai::OpenAi;
//! use rune_chain_core::{Llm, Message};
//!
//! # tokio_test::block_on(async {
//! let llm = OpenAi::from_env().unwrap();
//!
//! let result = llm.generate(&[
//!     Message::system("You are a helpful assistant."),
//!     Message::human("What is the capital of France?"),
//! ]).await.unwrap();
//!
//! println!("{}", result.generation); // "Paris"
//! # });
//! ```
//!
//! Stream tokens as they arrive:
//!
//! ```rust,no_run
//! use rune_chain_openai::OpenAi;
//! use rune_chain_core::{Llm, Message};
//! use futures::StreamExt;
//!
//! # tokio_test::block_on(async {
//! let llm = OpenAi::from_env().unwrap();
//! let mut stream = llm.stream(&[Message::human("Count to five.")]).await.unwrap();
//!
//! while let Some(chunk) = stream.next().await {
//!     let data = chunk.unwrap();
//!     if data.is_finished { break; }
//!     print!("{}", data.content);
//! }
//! # });
//! ```
//!
//! [`Stream`]: futures::Stream
//! [`GenerateResult`]: rune_chain_core::GenerateResult
//! [`StreamData`]: rune_chain_core::StreamData
//!
//!
//! Structured output with a strict JSON Schema:
//!
//! ```rust,no_run
//! use rune_chain_core::{Llm, Message, ResponseFormat};
//! use rune_chain_openai::OpenAi;
//! use serde_json::json;
//!
//! # tokio_test::block_on(async {
//! let format = ResponseFormat::json_schema(
//!     "city",
//!     json!({
//!         "type": "object",
//!         "properties": { "name": { "type": "string" } },
//!         "required": ["name"],
//!         "additionalProperties": false
//!     }),
//! );
//! let llm = OpenAi::from_env().unwrap();
//! let out = llm
//!     .generate_structured(&[Message::human("Capital of France?")], &format)
//!     .await
//!     .unwrap();
//! let value = format.parse_json(&out.generation).unwrap();
//! assert_eq!(value["name"], "Paris");
//! # });
//! ```

mod client;
mod http;
mod media;
pub mod models;
pub mod provider;
mod stream;
mod types;

pub use client::{
    AZURE_DEFAULT_API_VERSION, DEFAULT_BASE_URL, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT, OpenAi,
};
pub use media::{
    DEFAULT_MAX_MEDIA_RESPONSE_BYTES, DEFAULT_MAX_UPLOAD_BYTES, MAX_IMAGE_PROMPT_CHARS,
    MAX_SPEECH_INPUT_CHARS,
};
pub use models::ModelInfo;
pub use provider::{AuthStyle, MaxTokensField, Provider, Quirks};
pub use stream::{EventStream, StreamEvent, collect_events};
