//! Cohere embeddings (`POST /v2/embed`).

use std::fmt::{self, Write as _};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::http::{Transport, transport_builders};
use crate::{EmbedError, Embedder, InputKind};

/// Default API base URL of [`CohereEmbedder`].
pub const COHERE_BASE_URL: &str = "https://api.cohere.com/v2";
/// Default model of [`CohereEmbedder`].
pub const DEFAULT_COHERE_MODEL: &str = "embed-v4.0";
/// Default (and API maximum) inputs per request of [`CohereEmbedder`].
pub const DEFAULT_COHERE_BATCH_SIZE: usize = 96;
const EMBED_PATH: &str = "/embed";

/// Cohere's `input_type`, which v3+ models require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CohereInputType {
    /// Documents stored for search (used for documents by default).
    SearchDocument,
    /// Search queries (used for queries by default).
    SearchQuery,
    /// Texts fed to a classifier.
    Classification,
    /// Texts to be clustered.
    Clustering,
}

impl CohereInputType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SearchDocument => "search_document",
            Self::SearchQuery => "search_query",
            Self::Classification => "classification",
            Self::Clustering => "clustering",
        }
    }
}

/// [Cohere](https://docs.cohere.com/reference/embed) embedding client
/// implementing [`Embedder`].
///
/// Queries ([`embed`](Embedder::embed), [`embed_query`](Embedder::embed_query))
/// are sent as `search_query`, documents
/// ([`embed_batch`](Embedder::embed_batch),
/// [`embed_documents`](Embedder::embed_documents)) as `search_document`,
/// unless [`input_type`](Self::input_type) fixes one for both. Transport
/// hardening, batching and response checks are as for
/// [`OpenAiEmbedder`](crate::OpenAiEmbedder).
///
/// ```rust
/// use rune_chain_embed::CohereEmbedder;
///
/// let embedder = CohereEmbedder::new("co-...")
///     .model("embed-v4.0")
///     .dimensions(512);
/// ```
#[derive(Clone)]
pub struct CohereEmbedder {
    transport: Transport,
    model: String,
    dimensions: Option<u32>,
    input_type: Option<CohereInputType>,
}

impl fmt::Debug for CohereEmbedder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CohereEmbedder")
            .field("api_key", &self.transport.api_key)
            .field("model", &self.model)
            .field("dimensions", &self.dimensions)
            .field("input_type", &self.input_type)
            .field("base_url", &self.transport.base_url)
            .finish_non_exhaustive()
    }
}

impl CohereEmbedder {
    /// Create a client with the given API key and [`DEFAULT_COHERE_MODEL`].
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            transport: Transport::new(api_key, COHERE_BASE_URL, DEFAULT_COHERE_BATCH_SIZE),
            model: DEFAULT_COHERE_MODEL.to_string(),
            dimensions: None,
            input_type: None,
        }
    }

    /// Create a client from the `COHERE_API_KEY` (or `CO_API_KEY`)
    /// environment variable.
    ///
    /// # Errors
    ///
    /// [`EmbedError::InvalidConfig`] if neither is set.
    pub fn from_env() -> Result<Self, EmbedError> {
        std::env::var("COHERE_API_KEY")
            .or_else(|_| std::env::var("CO_API_KEY"))
            .map(Self::new)
            .map_err(|_| EmbedError::InvalidConfig("COHERE_API_KEY not set".into()))
    }

    /// Override the model (e.g. `embed-english-v3.0`,
    /// `embed-multilingual-v3.0`).
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Request `output_dimension` dimensions (embed-v4: 256, 512, 1024 or
    /// 1536) and require every returned vector to have that length.
    #[must_use]
    pub const fn dimensions(mut self, dims: u32) -> Self {
        self.dimensions = Some(dims);
        self
    }

    /// Send this `input_type` for queries and documents alike (e.g.
    /// [`CohereInputType::Classification`]).
    #[must_use]
    pub const fn input_type(mut self, input_type: CohereInputType) -> Self {
        self.input_type = Some(input_type);
        self
    }

    async fn request(&self, texts: &[&str], kind: InputKind) -> Result<Vec<Vec<f32>>, EmbedError> {
        let input_type = self.input_type.unwrap_or(match kind {
            InputKind::Query => CohereInputType::SearchQuery,
            InputKind::Document => CohereInputType::SearchDocument,
        });
        let body = EmbedRequest {
            model: &self.model,
            texts,
            input_type,
            embedding_types: ["float"],
            output_dimension: self.dimensions,
        };
        let bytes = self.transport.post_json(EMBED_PATH, &body).await?;
        decode(&bytes, texts.len())
    }

    async fn run(&self, texts: &[&str], kind: InputKind) -> Result<Vec<Vec<f32>>, EmbedError> {
        let dims = self.dimensions.map(|d| d as usize);
        self.batched(texts, dims, |chunk| self.request(chunk, kind))
            .await
    }
}

transport_builders!(CohereEmbedder, COHERE_BASE_URL);

#[async_trait]
impl Embedder for CohereEmbedder {
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
        let mut id = format!("cohere/{}", self.model);
        if let Some(d) = self.dimensions {
            let _ = write!(id, "/{d}");
        }
        if let Some(t) = self.input_type {
            id.push('/');
            id.push_str(t.as_str());
        }
        Some(id)
    }
}

fn decode(body: &[u8], expected: usize) -> Result<Vec<Vec<f32>>, EmbedError> {
    let response: EmbedResponse =
        serde_json::from_slice(body).map_err(|e| EmbedError::InvalidResponse(e.to_string()))?;
    let vectors = response.embeddings.float;
    if vectors.len() != expected {
        return Err(EmbedError::InvalidResponse(format!(
            "expected {expected} embeddings, got {}",
            vectors.len()
        )));
    }
    Ok(vectors)
}

#[derive(Serialize)]
struct EmbedRequest<'a> {
    model: &'a str,
    texts: &'a [&'a str],
    input_type: CohereInputType,
    embedding_types: [&'static str; 1],
    #[serde(skip_serializing_if = "Option::is_none")]
    output_dimension: Option<u32>,
}

#[derive(Deserialize)]
struct EmbedResponse {
    embeddings: EmbeddingsByType,
}

#[derive(Deserialize)]
struct EmbeddingsByType {
    float: Vec<Vec<f32>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_v2_fixture() {
        let body = br#"{
            "id": "5807ee2e",
            "embeddings": { "float": [[0.1, 0.2], [0.3, 0.4]] },
            "texts": ["a", "b"],
            "meta": { "api_version": { "version": "2" }, "billed_units": { "input_tokens": 2 } },
            "response_type": "embeddings_by_type"
        }"#;
        assert_eq!(
            decode(body, 2).unwrap(),
            vec![vec![0.1, 0.2], vec![0.3, 0.4]]
        );
        assert!(decode(body, 3).is_err());
        assert!(decode(br#"{"embeddings":{}}"#, 1).is_err());
    }

    #[test]
    fn model_id_and_debug() {
        let e = CohereEmbedder::new("co-secret-key-123")
            .dimensions(256)
            .input_type(CohereInputType::Clustering);
        assert_eq!(
            e.model_id().as_deref(),
            Some("cohere/embed-v4.0/256/clustering")
        );
        assert!(!format!("{e:?}").contains("co-secret-key-123"));
    }
}
