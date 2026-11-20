//! Ollama local models: everything from `rune-chain-ollama`, plus
//! [`Client`].

pub use rune_chain_ollama::*;

use rune_chain_core::LlmError;

use crate::{CompletionClient, CompletionModel, EmbeddingsClient};

/// Environment variable read by [`Client::from_env`] for the server address.
pub const HOST_ENV: &str = "OLLAMA_HOST";
/// Optional environment variable for a bearer token (hosted Ollama or a
/// proxy).
pub const API_KEY_ENV: &str = "OLLAMA_API_KEY";

/// Ollama client: hands out chat and embedding models from one server.
///
/// ```rust
/// use rune_chain::ollama;
/// use rune_chain::prelude::*;
///
/// let client = ollama::Client::new();
/// let model = client.completion_model("llama3.2");
/// assert_eq!(model.model_id(), "llama3.2");
/// assert_eq!(model.base_url_str(), "http://localhost:11434");
/// ```
#[derive(Debug, Clone, Default)]
pub struct Client {
    llm: Ollama,
}

impl Client {
    /// A client for the local server at `http://localhost:11434`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A client for the server at `base_url`.
    #[must_use]
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            llm: Ollama::new().base_url(base_url),
        }
    }

    /// A client for `OLLAMA_HOST` (`host:port` or a URL; the local default
    /// when unset), with `OLLAMA_API_KEY` as bearer token when set.
    ///
    /// Plain `http` is used only for loopback hosts unless you allow the
    /// host with [`configure`](Self::configure) and
    /// [`Ollama::allow_http_host`].
    ///
    /// # Errors
    ///
    /// Never at the moment; the `Result` matches the other providers.
    pub fn from_env() -> Result<Self, LlmError> {
        let mut llm = Ollama::new();
        if let Ok(host) = std::env::var(HOST_ENV) {
            let host = host.trim();
            if !host.is_empty() {
                llm = llm.base_url(normalize_host(host));
            }
        }
        if let Ok(key) = std::env::var(API_KEY_ENV)
            && !key.trim().is_empty()
        {
            llm = llm.bearer_token(key);
        }
        Ok(Self { llm })
    }

    /// Adjust the underlying [`Ollama`] template (timeouts, context size,
    /// keep-alive, allowed HTTP hosts). Every model handed out afterwards
    /// starts from it.
    #[must_use]
    pub fn configure(mut self, f: impl FnOnce(Ollama) -> Ollama) -> Self {
        self.llm = f(self.llm);
        self
    }
}

/// `OLLAMA_HOST` may be a bare `host:port`; give it a scheme.
fn normalize_host(host: &str) -> String {
    if host.contains("://") {
        host.to_owned()
    } else {
        format!("http://{host}")
    }
}

impl CompletionModel for Ollama {
    fn with_temperature(self, temperature: f32) -> Self {
        self.temperature(temperature)
    }

    fn with_max_tokens(self, max_tokens: u32) -> Self {
        self.max_tokens(max_tokens)
    }
}

impl CompletionClient for Client {
    type Model = Ollama;

    fn completion_model(&self, name: &str) -> Ollama {
        self.llm.clone().model(name)
    }
}

impl EmbeddingsClient for Client {
    type Embedder = Ollama;

    fn embedding_model(&self, name: &str) -> Ollama {
        self.llm.clone().model(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_host_gets_a_scheme() {
        assert_eq!(normalize_host("127.0.0.1:11434"), "http://127.0.0.1:11434");
        assert_eq!(
            normalize_host("https://ollama.example.com"),
            "https://ollama.example.com"
        );
    }
}
