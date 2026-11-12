//! Jina AI embeddings (`POST /v1/embeddings`).

use std::fmt::{self, Write as _};

use async_trait::async_trait;
use serde::Serialize;

use crate::http::{Transport, transport_builders};
use crate::openai::decode_embeddings;
use crate::{EmbedError, Embedder, InputKind};

/// Default API base URL of [`JinaEmbedder`].
pub const JINA_BASE_URL: &str = "https://api.jina.ai/v1";
/// Default model of [`JinaEmbedder`].
pub const DEFAULT_JINA_MODEL: &str = "jina-embeddings-v3";
/// Default inputs per request of [`JinaEmbedder`].
pub const DEFAULT_JINA_BATCH_SIZE: usize = 256;
const EMBED_PATH: &str = "/embeddings";

/// [Jina AI](https://jina.ai/embeddings/) embedding client implementing
/// [`Embedder`].
///
/// Queries are sent with `task: "retrieval.query"`, documents with
/// `"retrieval.passage"`, unless [`task`](Self::task) fixes one for both
/// (e.g. `"text-matching"`, `"classification"`, `"separation"`). Transport
/// hardening, batching and response checks are as for
/// [`OpenAiEmbedder`](crate::OpenAiEmbedder).
///
/// ```rust
/// use rune_chain_embed::JinaEmbedder;
///
/// let embedder = JinaEmbedder::new("jina_...").dimensions(256);
/// ```
#[derive(Clone)]
pub struct JinaEmbedder {
    transport: Transport,
    model: String,
    dimensions: Option<u32>,
    task: Option<String>,
}

impl fmt::Debug for JinaEmbedder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JinaEmbedder")
            .field("api_key", &self.transport.api_key)
            .field("model", &self.model)
            .field("dimensions", &self.dimensions)
            .field("task", &self.task)
            .field("base_url", &self.transport.base_url)
            .finish_non_exhaustive()
    }
}

impl JinaEmbedder {
    /// Create a client with the given API key and [`DEFAULT_JINA_MODEL`].
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            transport: Transport::new(api_key, JINA_BASE_URL, DEFAULT_JINA_BATCH_SIZE),
            model: DEFAULT_JINA_MODEL.to_string(),
            dimensions: None,
            task: None,
        }
    }

    /// Create a client from the `JINA_API_KEY` environment variable.
    ///
    /// # Errors
    ///
    /// [`EmbedError::InvalidConfig`] if it is unset.
    pub fn from_env() -> Result<Self, EmbedError> {
        std::env::var("JINA_API_KEY")
            .map(Self::new)
            .map_err(|_| EmbedError::InvalidConfig("JINA_API_KEY not set".into()))
    }

    /// Override the model.
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Request `dimensions` (Matryoshka truncation) and require every vector
    /// to have that length.
    #[must_use]
    pub const fn dimensions(mut self, dims: u32) -> Self {
        self.dimensions = Some(dims);
        self
    }

    /// Send this `task` for queries and documents alike.
    #[must_use]
    pub fn task(mut self, task: impl Into<String>) -> Self {
        self.task = Some(task.into());
        self
    }

    async fn request(&self, texts: &[&str], kind: InputKind) -> Result<Vec<Vec<f32>>, EmbedError> {
        let task = self.task.as_deref().unwrap_or(match kind {
            InputKind::Query => "retrieval.query",
            InputKind::Document => "retrieval.passage",
        });
        let body = EmbedRequest {
            model: &self.model,
            input: texts,
            task,
            dimensions: self.dimensions,
            embedding_type: "float",
        };
        let bytes = self.transport.post_json(EMBED_PATH, &body).await?;
        decode_embeddings(&bytes, texts.len())
    }

    async fn run(&self, texts: &[&str], kind: InputKind) -> Result<Vec<Vec<f32>>, EmbedError> {
        let dims = self.dimensions.map(|d| d as usize);
        self.batched(texts, dims, |chunk| self.request(chunk, kind))
            .await
    }
}

transport_builders!(JinaEmbedder, JINA_BASE_URL);

#[async_trait]
impl Embedder for JinaEmbedder {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        self.run(texts, InputKind::Document).await
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        self.embed_query(text).await
    }

    async fn embed_query(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        self.run(&[text], InputKind::Query)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| EmbedError::InvalidResponse("no embedding returned".into()))
    }

    fn model_id(&self) -> Option<String> {
        let mut id = format!("jina/{}", self.model);
        if let Some(d) = self.dimensions {
            let _ = write!(id, "/{d}");
        }
        if let Some(t) = &self.task {
            id.push('/');
            id.push_str(t);
        }
        Some(id)
    }
}

#[derive(Serialize)]
struct EmbedRequest<'a> {
    model: &'a str,
    input: &'a [&'a str],
    task: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<u32>,
    embedding_type: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_id_and_debug() {
        let e = JinaEmbedder::new("jina_secret_key_1").task("text-matching");
        assert_eq!(
            e.model_id().as_deref(),
            Some("jina/jina-embeddings-v3/text-matching")
        );
        assert!(!format!("{e:?}").contains("jina_secret_key_1"));
    }
}
