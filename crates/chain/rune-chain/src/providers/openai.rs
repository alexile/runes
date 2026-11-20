//! `OpenAI` and OpenAI-compatible providers: everything from
//! `rune-chain-openai`, plus [`Client`].

use std::fmt;

pub use rune_chain_openai::*;

use rune_chain_core::LlmError;
use rune_chain_embed::OpenAiEmbedder;

use crate::{
    CompletionClient, CompletionModel, EmbeddingsClient, ImageGenerationClient, SpeechClient,
    TranscriptionClient,
};

/// Environment variable read by [`Client::from_env`] for the API key.
pub const API_KEY_ENV: &str = "OPENAI_API_KEY";
/// Optional environment variable for a custom base URL.
pub const BASE_URL_ENV: &str = "OPENAI_BASE_URL";

/// `OpenAI` client: hands out chat models ([`OpenAi`]) and embedding models
/// ([`OpenAiEmbedder`]) that share one key and base URL.
///
/// ```rust
/// use rune_chain::openai;
/// use rune_chain::prelude::*;
///
/// let client = openai::Client::new("sk-example");
/// let model = client.completion_model("gpt-4o-mini");
/// assert_eq!(model.model_id(), "gpt-4o-mini");
/// // The key never shows up in debug output.
/// assert!(!format!("{client:?}").contains("sk-example"));
/// ```
#[derive(Clone)]
pub struct Client {
    llm: OpenAi,
    api_key: String,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("provider", &self.llm.provider())
            .field("base_url", &self.llm.base_url_str())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for api.openai.com with `api_key`.
    pub fn new(api_key: impl Into<String>) -> Self {
        let api_key = api_key.into();
        Self {
            llm: OpenAi::new(api_key.clone()),
            api_key,
        }
    }

    /// A client for an OpenAI-compatible [`Provider`] preset (Groq, Mistral,
    /// `DeepSeek`, `OpenRouter`, …).
    pub fn for_provider(provider: Provider, api_key: impl Into<String>) -> Self {
        let api_key = api_key.into();
        Self {
            llm: OpenAi::for_provider(provider, api_key.clone()),
            api_key,
        }
    }

    /// A client from `OPENAI_API_KEY`, and `OPENAI_BASE_URL` when set.
    ///
    /// # Errors
    ///
    /// When `OPENAI_API_KEY` is not set.
    pub fn from_env() -> Result<Self, LlmError> {
        let key = std::env::var(API_KEY_ENV)
            .map_err(|_| LlmError::other(format!("{API_KEY_ENV} environment variable not set")))?;
        let client = Self::new(key);
        Ok(match std::env::var(BASE_URL_ENV) {
            Ok(url) if !url.trim().is_empty() => client.configure(|llm| llm.base_url(url)),
            _ => client,
        })
    }

    /// Adjust the underlying [`OpenAi`] template (base URL, timeouts,
    /// headers, quirks). Every model handed out afterwards starts from it.
    #[must_use]
    pub fn configure(mut self, f: impl FnOnce(OpenAi) -> OpenAi) -> Self {
        self.llm = f(self.llm);
        self
    }
}

impl CompletionModel for OpenAi {
    fn with_temperature(self, temperature: f32) -> Self {
        self.temperature(temperature)
    }

    fn with_max_tokens(self, max_tokens: u32) -> Self {
        self.max_tokens(max_tokens)
    }
}

impl CompletionClient for Client {
    type Model = OpenAi;

    fn completion_model(&self, name: &str) -> OpenAi {
        self.llm.clone().model(name)
    }
}

impl EmbeddingsClient for Client {
    type Embedder = OpenAiEmbedder;

    fn embedding_model(&self, name: &str) -> OpenAiEmbedder {
        OpenAiEmbedder::new(self.api_key.clone())
            .base_url(self.llm.base_url_str())
            .model(name)
    }
}

impl TranscriptionClient for Client {
    type TranscriptionModel = OpenAi;

    fn transcription_model(&self, name: &str) -> OpenAi {
        self.llm.clone().model(name)
    }
}

impl ImageGenerationClient for Client {
    type ImageGenerationModel = OpenAi;

    fn image_generation_model(&self, name: &str) -> OpenAi {
        self.llm.clone().model(name)
    }
}

impl SpeechClient for Client {
    type SpeechModel = OpenAi;

    fn speech_model(&self, name: &str) -> OpenAi {
        self.llm.clone().model(name)
    }
}
