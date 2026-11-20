//! Azure `OpenAI`: a [`Client`] that hands out chat models by deployment
//! name.

use std::fmt;
use std::sync::Arc;

pub use rune_chain_openai::{AZURE_DEFAULT_API_VERSION, OpenAi, Provider, Quirks};

use rune_chain_core::LlmError;

use crate::CompletionClient;

/// Environment variable read by [`Client::from_env`] for the API key.
pub const API_KEY_ENV: &str = "AZURE_OPENAI_API_KEY";
/// Environment variable for the resource URL
/// (`https://<resource>.openai.azure.com`).
pub const ENDPOINT_ENV: &str = "AZURE_OPENAI_ENDPOINT";
/// Optional environment variables for the `api-version`, checked in order.
pub const API_VERSION_ENVS: &[&str] = &["AZURE_OPENAI_API_VERSION", "OPENAI_API_VERSION"];

type Configure = Arc<dyn Fn(OpenAi) -> OpenAi + Send + Sync>;

/// Azure `OpenAI` client. The name given to
/// [`completion_model`](CompletionClient::completion_model) is the
/// deployment name; requests go to
/// `{endpoint}/openai/deployments/{name}/chat/completions?api-version=…`
/// with an `api-key` header.
///
/// ```rust
/// use rune_chain::azure;
/// use rune_chain::prelude::*;
///
/// let client = azure::Client::new("https://contoso.openai.azure.com", "azure-secret")
///     .api_version("2024-10-21");
/// let model = client.completion_model("gpt-4o");
/// assert_eq!(
///     model.chat_url().unwrap().as_str(),
///     "https://contoso.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21"
/// );
/// assert!(!format!("{client:?}").contains("azure-secret"));
/// ```
#[derive(Clone)]
pub struct Client {
    endpoint: String,
    api_key: String,
    api_version: String,
    configure: Option<Configure>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("endpoint", &self.endpoint)
            .field("api_version", &self.api_version)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for the resource at `endpoint` with `api_key` and the
    /// default `api-version` ([`AZURE_DEFAULT_API_VERSION`]).
    pub fn new(endpoint: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            api_key: api_key.into(),
            api_version: AZURE_DEFAULT_API_VERSION.to_owned(),
            configure: None,
        }
    }

    /// A client from `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_API_KEY`,
    /// with the `api-version` from `AZURE_OPENAI_API_VERSION` or
    /// `OPENAI_API_VERSION` when set.
    ///
    /// # Errors
    ///
    /// When the endpoint or key variable is not set.
    pub fn from_env() -> Result<Self, LlmError> {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| LlmError::other(format!("{name} environment variable not set")))
        };
        let client = Self::new(var(ENDPOINT_ENV)?, var(API_KEY_ENV)?);
        Ok(
            match API_VERSION_ENVS.iter().find_map(|name| var(name).ok()) {
                Some(version) => client.api_version(version),
                None => client,
            },
        )
    }

    /// Set the `api-version` query parameter.
    #[must_use]
    pub fn api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = version.into();
        self
    }

    /// Adjust every [`OpenAi`] model handed out (timeouts, headers,
    /// quirks). Calls compose in order.
    #[must_use]
    pub fn configure(mut self, f: impl Fn(OpenAi) -> OpenAi + Send + Sync + 'static) -> Self {
        self.configure = Some(match self.configure.take() {
            Some(prev) => Arc::new(move |llm| f(prev(llm))),
            None => Arc::new(f),
        });
        self
    }
}

impl CompletionClient for Client {
    type Model = OpenAi;

    fn completion_model(&self, name: &str) -> OpenAi {
        let llm = OpenAi::azure(&self.endpoint, name, &self.api_key).api_version(&self.api_version);
        match &self.configure {
            Some(f) => f(llm),
            None => llm,
        }
    }
}
