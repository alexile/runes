//! Google Gemini: everything from `rune-chain-gemini`, plus [`Client`].

use std::fmt;

pub use rune_chain_gemini::*;

use rune_chain_core::LlmError;

use crate::{CompletionClient, CompletionModel, EmbeddingsClient};

/// Gemini client: hands out chat models ([`Gemini`]) and embedding models
/// ([`GeminiEmbedder`]) that share one key and configuration.
///
/// ```rust
/// use rune_chain::gemini;
/// use rune_chain::prelude::*;
///
/// let client = gemini::Client::new("AIza-example");
/// let model = client.completion_model("gemini-2.5-flash");
/// assert_eq!(model.model_id(), "gemini-2.5-flash");
/// let _embedder = client.embedding_model("gemini-embedding-001");
/// // The key never shows up in debug output.
/// assert!(!format!("{client:?}").contains("AIza-example"));
/// ```
#[derive(Clone)]
pub struct Client {
    llm: Gemini,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.llm.base_url_str())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for the Gemini API with `api_key`.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            llm: Gemini::new(api_key),
        }
    }

    /// A client from `GEMINI_API_KEY` (or `GOOGLE_API_KEY`).
    ///
    /// # Errors
    ///
    /// When neither is set.
    pub fn from_env() -> Result<Self, LlmError> {
        Ok(Self {
            llm: Gemini::from_env()?,
        })
    }

    /// A Vertex AI client for `project` in `location`, with an OAuth access
    /// token; see [`Gemini::vertex_ai`]. Embeddings need the Gemini API.
    ///
    /// # Errors
    ///
    /// A project or location with characters outside `[a-z0-9-]`.
    pub fn vertex_ai(
        project: &str,
        location: &str,
        access_token: impl Into<String>,
    ) -> Result<Self, LlmError> {
        Ok(Self {
            llm: Gemini::vertex_ai(project, location, access_token)?,
        })
    }

    /// Adjust the underlying [`Gemini`] template (base URL, thinking,
    /// safety settings, timeouts). Every model handed out afterwards starts
    /// from it.
    #[must_use]
    pub fn configure(mut self, f: impl FnOnce(Gemini) -> Gemini) -> Self {
        self.llm = f(self.llm);
        self
    }
}

impl CompletionModel for Gemini {
    fn with_temperature(self, temperature: f32) -> Self {
        self.temperature(temperature)
    }

    fn with_max_tokens(self, max_tokens: u32) -> Self {
        self.max_output_tokens(max_tokens)
    }
}

impl CompletionClient for Client {
    type Model = Gemini;

    fn completion_model(&self, name: &str) -> Gemini {
        self.llm.clone().model(name)
    }
}

impl EmbeddingsClient for Client {
    type Embedder = GeminiEmbedder;

    fn embedding_model(&self, name: &str) -> GeminiEmbedder {
        self.llm.embedder(name)
    }
}
