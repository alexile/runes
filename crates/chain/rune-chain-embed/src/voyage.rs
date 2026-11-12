//! Voyage AI embeddings (`POST /v1/embeddings`).

use std::fmt::{self, Write as _};

use async_trait::async_trait;
use serde::Serialize;

use crate::http::{Transport, transport_builders};
use crate::openai::decode_embeddings;
use crate::{EmbedError, Embedder, InputKind};

/// Default API base URL of [`VoyageEmbedder`].
pub const VOYAGE_BASE_URL: &str = "https://api.voyageai.com/v1";
/// Default model of [`VoyageEmbedder`].
pub const DEFAULT_VOYAGE_MODEL: &str = "voyage-3.5";
/// Default inputs per request of [`VoyageEmbedder`] (the API accepts 1000).
pub const DEFAULT_VOYAGE_BATCH_SIZE: usize = 128;
const EMBED_PATH: &str = "/embeddings";

/// [Voyage AI](https://docs.voyageai.com/reference/embeddings-api) embedding
/// client implementing [`Embedder`].
///
/// Queries are sent with `input_type: "query"`, documents with
/// `"document"` (Voyage prepends a retrieval prompt for each); call
/// [`symmetric`](Self::symmetric) to send no `input_type`. Transport
/// hardening, batching and response checks are as for
/// [`OpenAiEmbedder`](crate::OpenAiEmbedder).
///
/// ```rust
/// use rune_chain_embed::VoyageEmbedder;
///
/// let embedder = VoyageEmbedder::new("pa-...").model("voyage-3-large").dimensions(1024);
/// ```
#[derive(Clone)]
pub struct VoyageEmbedder {
    transport: Transport,
    model: String,
    dimensions: Option<u32>,
    symmetric: bool,
}

impl fmt::Debug for VoyageEmbedder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VoyageEmbedder")
            .field("api_key", &self.transport.api_key)
            .field("model", &self.model)
            .field("dimensions", &self.dimensions)
            .field("symmetric", &self.symmetric)
            .field("base_url", &self.transport.base_url)
            .finish_non_exhaustive()
    }
}

impl VoyageEmbedder {
    /// Create a client with the given API key and [`DEFAULT_VOYAGE_MODEL`].
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            transport: Transport::new(api_key, VOYAGE_BASE_URL, DEFAULT_VOYAGE_BATCH_SIZE),
            model: DEFAULT_VOYAGE_MODEL.to_string(),
            dimensions: None,
            symmetric: false,
        }
    }

    /// Create a client from the `VOYAGE_API_KEY` environment variable.
    ///
    /// # Errors
    ///
    /// [`EmbedError::InvalidConfig`] if it is unset.
    pub fn from_env() -> Result<Self, EmbedError> {
        std::env::var("VOYAGE_API_KEY")
            .map(Self::new)
            .map_err(|_| EmbedError::InvalidConfig("VOYAGE_API_KEY not set".into()))
    }

    /// Override the model (e.g. `voyage-3-large`, `voyage-code-3`).
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Request `output_dimension` dimensions (256, 512, 1024 or 2048 on
    /// models that support it) and require every vector to have that length.
    #[must_use]
    pub const fn dimensions(mut self, dims: u32) -> Self {
        self.dimensions = Some(dims);
        self
    }

    /// Send no `input_type`: queries and documents are embedded alike.
    #[must_use]
    pub const fn symmetric(mut self) -> Self {
        self.symmetric = true;
        self
    }

    async fn request(&self, texts: &[&str], kind: InputKind) -> Result<Vec<Vec<f32>>, EmbedError> {
        let input_type = (!self.symmetric).then_some(match kind {
            InputKind::Query => "query",
            InputKind::Document => "document",
        });
        let body = EmbedRequest {
            model: &self.model,
            input: texts,
            input_type,
            output_dimension: self.dimensions,
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

transport_builders!(VoyageEmbedder, VOYAGE_BASE_URL);

#[async_trait]
impl Embedder for VoyageEmbedder {
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
        let mut id = format!("voyage/{}", self.model);
        if let Some(d) = self.dimensions {
            let _ = write!(id, "/{d}");
        }
        if self.symmetric {
            id.push_str("/symmetric");
        }
        Some(id)
    }
}

#[derive(Serialize)]
struct EmbedRequest<'a> {
    model: &'a str,
    input: &'a [&'a str],
    #[serde(skip_serializing_if = "Option::is_none")]
    input_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_dimension: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_id_and_debug() {
        let e = VoyageEmbedder::new("pa-secret-key-123").symmetric();
        assert_eq!(e.model_id().as_deref(), Some("voyage/voyage-3.5/symmetric"));
        assert!(!format!("{e:?}").contains("pa-secret-key-123"));
    }
}
