//! Gemini embeddings (`embedContent` / `batchEmbedContents`) and the
//! [`Embedder`] implementation.

use std::fmt::{self, Write as _};
use std::time::Duration;

use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt};
use rune_chain_core::{LlmError, LlmErrorKind};
use rune_chain_embed::{EmbedError, Embedder, check_dimensions};
use serde::{Deserialize, Serialize};

use crate::Gemini;
use crate::client::{API_KEY_ENV_VARS, DEFAULT_BASE_URL};
use crate::http::{Credential, Transport};
use crate::models::GEMINI_EMBEDDING_001;
use crate::types::{Content, Part};

/// Default model of [`GeminiEmbedder`].
pub const DEFAULT_EMBEDDING_MODEL: &str = GEMINI_EMBEDDING_001;
/// Default texts per `batchEmbedContents` request (the API's limit is 100).
pub const DEFAULT_EMBED_BATCH_SIZE: usize = 100;
/// Default batch requests in flight at once.
pub const DEFAULT_EMBED_CONCURRENCY: usize = 4;

/// What the embedding is for (`taskType`); Gemini tunes the vector to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum TaskType {
    /// A search query.
    RetrievalQuery,
    /// A document to be searched.
    RetrievalDocument,
    /// Semantic similarity between texts.
    SemanticSimilarity,
    /// Classification input.
    Classification,
    /// Clustering input.
    Clustering,
    /// A question for question answering.
    QuestionAnswering,
    /// A claim for fact verification.
    FactVerification,
    /// A natural-language query for code retrieval.
    CodeRetrievalQuery,
}

/// Gemini API embedding client implementing [`Embedder`].
///
/// [`embed_query`](Embedder::embed_query) sends `RETRIEVAL_QUERY` and
/// [`embed_documents`](Embedder::embed_documents) /
/// [`embed_batch`](Embedder::embed_batch) send `RETRIEVAL_DOCUMENT`, unless
/// [`task_type`](Self::task_type) pins one task for both. Batches are split
/// into requests of [`DEFAULT_EMBED_BATCH_SIZE`] texts, sent a few at a
/// time; vectors come back in input order, all of one length, and finite.
///
/// With [`dimensions`](Self::dimensions) below the model's full size
/// (3072 for `gemini-embedding-001`), vectors are truncated and no longer
/// unit length; normalise them before using dot-product similarity.
///
/// Embeddings use the Gemini API. A client made for Vertex AI (bearer
/// token) fails locally.
///
/// ```rust
/// use rune_chain_gemini::GeminiEmbedder;
///
/// let embedder = GeminiEmbedder::new("key").dimensions(768);
/// ```
#[derive(Clone)]
pub struct GeminiEmbedder {
    transport: Transport,
    model: String,
    dimensions: Option<u32>,
    task_type: Option<TaskType>,
    batch_size: usize,
    concurrency: usize,
}

impl fmt::Debug for GeminiEmbedder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeminiEmbedder")
            .field("transport", &self.transport)
            .field("model", &self.model)
            .field("dimensions", &self.dimensions)
            .field("task_type", &self.task_type)
            .field("batch_size", &self.batch_size)
            .field("concurrency", &self.concurrency)
            .finish()
    }
}

impl GeminiEmbedder {
    /// An embedder with the given API key and [`DEFAULT_EMBEDDING_MODEL`].
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::from_transport(Transport::new(
            Credential::ApiKey(api_key.into()),
            DEFAULT_BASE_URL,
        ))
    }

    /// An embedder from `GEMINI_API_KEY` (or `GOOGLE_API_KEY`).
    ///
    /// # Errors
    ///
    /// [`EmbedError::InvalidConfig`] when neither is set.
    pub fn from_env() -> Result<Self, EmbedError> {
        API_KEY_ENV_VARS
            .iter()
            .find_map(|name| std::env::var(name).ok().filter(|v| !v.trim().is_empty()))
            .map(Self::new)
            .ok_or_else(|| EmbedError::InvalidConfig("GEMINI_API_KEY not set".into()))
    }

    fn from_transport(transport: Transport) -> Self {
        Self {
            transport,
            model: DEFAULT_EMBEDDING_MODEL.to_string(),
            dimensions: None,
            task_type: None,
            batch_size: DEFAULT_EMBED_BATCH_SIZE,
            concurrency: DEFAULT_EMBED_CONCURRENCY,
        }
    }

    /// Set the embedding model.
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        let model = model.into();
        self.model = model
            .strip_prefix("models/")
            .map_or_else(|| model.clone(), str::to_string);
        self
    }

    /// Request `outputDimensionality` dimensions and require every vector
    /// to have that length.
    #[must_use]
    pub const fn dimensions(mut self, dims: u32) -> Self {
        self.dimensions = Some(dims);
        self
    }

    /// Use one task type for queries and documents alike.
    #[must_use]
    pub const fn task_type(mut self, task: TaskType) -> Self {
        self.task_type = Some(task);
        self
    }

    /// Texts per batch request (clamped to 1..=100).
    #[must_use]
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = size.clamp(1, DEFAULT_EMBED_BATCH_SIZE);
        self
    }

    /// Batch requests in flight at once (default
    /// [`DEFAULT_EMBED_CONCURRENCY`]; `0` is treated as `1`).
    #[must_use]
    pub fn max_concurrency(mut self, requests: usize) -> Self {
        self.concurrency = requests.max(1);
        self
    }

    /// Set the base URL (default [`DEFAULT_BASE_URL`]); same rules as
    /// [`Gemini::base_url`].
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.transport.base_url = url.into().trim_end_matches('/').to_string();
        self
    }

    /// Use a preconfigured HTTP client; see [`Gemini::http_client`].
    #[must_use]
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.transport.client = client;
        self
    }

    /// Retries after a retryable failure.
    #[must_use]
    pub const fn max_retries(mut self, retries: u32) -> Self {
        self.transport.max_retries = retries;
        self
    }

    /// Total timeout of each request.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.transport.timeout = timeout;
        self
    }

    /// Cap each response body at `bytes`.
    #[must_use]
    pub const fn max_response_bytes(mut self, bytes: usize) -> Self {
        self.transport.max_response_bytes = bytes;
        self
    }

    fn task(&self, default: TaskType) -> TaskType {
        self.task_type.unwrap_or(default)
    }

    fn check(&self) -> Result<(), EmbedError> {
        if self.transport.is_bearer() {
            return Err(EmbedError::InvalidConfig(
                "embeddings use the Gemini API; this client authenticates for Vertex AI".into(),
            ));
        }
        if self.dimensions == Some(0) {
            return Err(EmbedError::InvalidConfig(
                "dimensions must be at least 1".into(),
            ));
        }
        Ok(())
    }

    async fn embed_one(&self, text: &str, task: TaskType) -> Result<Vec<f32>, EmbedError> {
        let url = self
            .transport
            .model_url(&self.model, "embedContent")
            .map_err(|e| to_embed_error(&e))?;
        let body = EmbedRequest {
            model: None,
            content: content(text),
            task_type: task,
            output_dimensionality: self.dimensions,
        };
        let bytes = self
            .transport
            .post_json(&url, &body)
            .await
            .map_err(|e| to_embed_error(&e))?;
        let response: EmbedResponse = serde_json::from_slice(&bytes)
            .map_err(|e| EmbedError::InvalidResponse(e.to_string()))?;
        checked(response.embedding.values)
    }

    async fn embed_chunk(
        &self,
        texts: &[&str],
        task: TaskType,
    ) -> Result<Vec<Vec<f32>>, EmbedError> {
        let url = self
            .transport
            .model_url(&self.model, "batchEmbedContents")
            .map_err(|e| to_embed_error(&e))?;
        let model = format!("models/{}", self.model);
        let body = BatchRequest {
            requests: texts
                .iter()
                .map(|t| EmbedRequest {
                    model: Some(&model),
                    content: content(t),
                    task_type: task,
                    output_dimensionality: self.dimensions,
                })
                .collect(),
        };
        let bytes = self
            .transport
            .post_json(&url, &body)
            .await
            .map_err(|e| to_embed_error(&e))?;
        let response: BatchResponse = serde_json::from_slice(&bytes)
            .map_err(|e| EmbedError::InvalidResponse(e.to_string()))?;
        if response.embeddings.len() != texts.len() {
            return Err(EmbedError::InvalidResponse(format!(
                "expected {} embeddings, got {}",
                texts.len(),
                response.embeddings.len()
            )));
        }
        response
            .embeddings
            .into_iter()
            .map(|e| checked(e.values))
            .collect()
    }

    async fn run(&self, texts: &[&str], task: TaskType) -> Result<Vec<Vec<f32>>, EmbedError> {
        self.check()?;
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let slices: Vec<&[&str]> = texts.chunks(self.batch_size).collect();
        // Index instead of iterating the slices so the closure has no
        // higher-ranked argument lifetime, which `async_trait` rejects.
        let chunks: Vec<Vec<Vec<f32>>> = futures::stream::iter(0..slices.len())
            .map(|i| self.embed_chunk(slices[i], task))
            .buffered(self.concurrency)
            .try_collect()
            .await?;
        let vectors: Vec<Vec<f32>> = chunks.into_iter().flatten().collect();
        check_dimensions(&vectors, self.dimensions.map(|d| d as usize))?;
        Ok(vectors)
    }
}

impl Gemini {
    /// An embedder sharing this client's key, base URL, HTTP client and
    /// limits, using `model` (e.g. [`DEFAULT_EMBEDDING_MODEL`]).
    #[must_use]
    pub fn embedder(&self, model: impl Into<String>) -> GeminiEmbedder {
        GeminiEmbedder::from_transport(self.transport().clone()).model(model)
    }
}

fn content(text: &str) -> Content {
    Content {
        role: None,
        parts: vec![Part::text(text)],
    }
}

/// Reject empty vectors and non-finite values.
fn checked(values: Vec<f32>) -> Result<Vec<f32>, EmbedError> {
    if values.is_empty() {
        return Err(EmbedError::InvalidResponse("empty embedding".into()));
    }
    if values.iter().any(|v| !v.is_finite()) {
        return Err(EmbedError::InvalidResponse(
            "embedding holds a non-finite value".into(),
        ));
    }
    Ok(values)
}

fn to_embed_error(err: &LlmError) -> EmbedError {
    let message = err.to_string();
    match err.kind() {
        LlmErrorKind::Network | LlmErrorKind::Timeout => EmbedError::RequestFailed(message),
        LlmErrorKind::InvalidResponse => EmbedError::InvalidResponse(message),
        LlmErrorKind::Other => EmbedError::InvalidConfig(message),
        LlmErrorKind::Unsupported => EmbedError::Other(message),
        _ => EmbedError::ProviderError(message),
    }
}

#[async_trait]
impl Embedder for GeminiEmbedder {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        self.run(texts, self.task(TaskType::RetrievalDocument))
            .await
    }

    async fn embed_query(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        self.check()?;
        let vector = self
            .embed_one(text, self.task(TaskType::RetrievalQuery))
            .await?;
        check_dimensions(
            std::slice::from_ref(&vector),
            self.dimensions.map(|d| d as usize),
        )?;
        Ok(vector)
    }

    fn model_id(&self) -> Option<String> {
        let mut id = format!("gemini/{}", self.model);
        if let Some(d) = self.dimensions {
            let _ = write!(id, "/{d}");
        }
        if let Some(task) = self.task_type {
            let _ = write!(id, "/{task:?}");
        }
        Some(id)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EmbedRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<&'a str>,
    content: Content,
    task_type: TaskType,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_dimensionality: Option<u32>,
}

#[derive(Serialize)]
struct BatchRequest<'a> {
    requests: Vec<EmbedRequest<'a>>,
}

#[derive(Deserialize)]
struct Values {
    #[serde(default)]
    values: Vec<f32>,
}

#[derive(Deserialize)]
struct EmbedResponse {
    embedding: Values,
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    embeddings: Vec<Values>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;

    #[test]
    fn debug_hides_key_and_model_id() {
        let e = GeminiEmbedder::new("AIza-secret-key-123")
            .dimensions(768)
            .task_type(TaskType::SemanticSimilarity);
        assert!(!format!("{e:?}").contains("AIza-secret-key-123"));
        assert_eq!(
            e.model_id().as_deref(),
            Some("gemini/gemini-embedding-001/768/SemanticSimilarity")
        );
    }

    #[test]
    fn request_shapes() {
        let model = "models/gemini-embedding-001".to_string();
        let body = BatchRequest {
            requests: vec![EmbedRequest {
                model: Some(&model),
                content: content("hi"),
                task_type: TaskType::RetrievalDocument,
                output_dimensionality: Some(8),
            }],
        };
        assert_eq!(
            serde_json::to_value(&body).unwrap(),
            serde_json::json!({ "requests": [{
                "model": "models/gemini-embedding-001",
                "content": { "parts": [{ "text": "hi" }] },
                "taskType": "RETRIEVAL_DOCUMENT",
                "outputDimensionality": 8
            }]})
        );
    }

    #[test]
    fn rejects_bad_vectors() {
        assert!(checked(vec![]).is_err());
        assert!(checked(vec![1.0, f32::NAN]).is_err());
        assert!(checked(vec![1.0, f32::INFINITY]).is_err());
        assert_eq!(checked(vec![0.5]).unwrap(), [0.5]);
    }

    #[test]
    fn vertex_clients_fail_locally() {
        let llm = Gemini::vertex_ai("p", "us-central1", "ya29.x").unwrap();
        let e = llm.embedder(DEFAULT_EMBEDDING_MODEL);
        let err = tokio_test::block_on(e.embed_batch(&["x"])).unwrap_err();
        assert!(matches!(err, EmbedError::InvalidConfig(_)));
    }
}
