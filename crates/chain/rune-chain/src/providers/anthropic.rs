//! Anthropic Claude: everything from `rune-chain-anthropic`, plus
//! [`Client`].

use std::fmt;

pub use rune_chain_anthropic::*;

use rune_chain_core::LlmError;

use crate::{CompletionClient, CompletionModel};

/// Anthropic client: hands out [`Anthropic`] chat models that share one key
/// and configuration. Anthropic has no embeddings API.
///
/// ```rust
/// use rune_chain::anthropic;
/// use rune_chain::prelude::*;
///
/// let client = anthropic::Client::new("sk-ant-example");
/// let model = client.completion_model("claude-sonnet-5-5");
/// assert_eq!(model.model_id(), "claude-sonnet-5-5");
/// ```
#[derive(Clone)]
pub struct Client {
    llm: Anthropic,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// A client for api.anthropic.com with `api_key`.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            llm: Anthropic::new(api_key),
        }
    }

    /// A client from `ANTHROPIC_API_KEY`.
    ///
    /// # Errors
    ///
    /// When `ANTHROPIC_API_KEY` is not set.
    pub fn from_env() -> Result<Self, LlmError> {
        Ok(Self {
            llm: Anthropic::from_env()?,
        })
    }

    /// Adjust the underlying [`Anthropic`] template (base URL, caching,
    /// thinking, betas, timeouts). Every model handed out afterwards starts
    /// from it.
    #[must_use]
    pub fn configure(mut self, f: impl FnOnce(Anthropic) -> Anthropic) -> Self {
        self.llm = f(self.llm);
        self
    }
}

impl CompletionModel for Anthropic {
    fn with_temperature(self, temperature: f32) -> Self {
        self.temperature(temperature)
    }

    fn with_max_tokens(self, max_tokens: u32) -> Self {
        self.max_tokens(max_tokens)
    }
}

impl CompletionClient for Client {
    type Model = Anthropic;

    fn completion_model(&self, name: &str) -> Anthropic {
        self.llm.clone().model(name)
    }
}
