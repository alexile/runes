use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::embedder::{EmbedError, Embedder};
use crate::http::{Transport, transport_builders};

/// Default API base URL; see [`OpenAiEmbedder::base_url`].
pub const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
/// Default model of [`OpenAiEmbedder`].
pub const DEFAULT_OPENAI_MODEL: &str = "text-embedding-3-small";
/// Default [`max_batch_size`](OpenAiEmbedder::max_batch_size) of
/// [`OpenAiEmbedder`] (the API accepts up to 2048 inputs and 300k tokens per
/// request).
pub const DEFAULT_OPENAI_BATCH_SIZE: usize = 512;
const EMBED_PATH: &str = "/embeddings";

/// How the server encodes vectors on the wire; see
/// [`OpenAiEmbedder::encoding_format`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum EncodingFormat {
    /// JSON arrays of numbers (the API default; the field is omitted).
    #[default]
    Float,
    /// Base64 of little-endian `f32`s: about 4× smaller responses and
    /// exact values, decoded transparently.
    Base64,
}

/// `OpenAI` (and OpenAI-compatible) text embedding client implementing
/// [`Embedder`].
///
/// Works with `text-embedding-3-small` (default), `text-embedding-3-large`,
/// the legacy `text-embedding-ada-002`, and any server that speaks the
/// `/v1/embeddings` protocol (vLLM, LM Studio, `LocalAI`, Together, Mistral,
/// Azure-style proxies, …) via [`base_url`](Self::base_url).
///
/// Transport: requests time out (default [`DEFAULT_TIMEOUT`](crate::DEFAULT_TIMEOUT)),
/// 429/5xx are retried honouring `Retry-After`, responses are size-capped,
/// error bodies are truncated, the base URL must be `https` (plain `http`
/// only to loopback or allowed hosts), and the API key never appears in
/// `Debug` output or error messages. Large batches are split into requests of
/// at most [`max_batch_size`](Self::max_batch_size) inputs, sent with bounded
/// concurrency, results in input order.
///
/// Every returned vector is checked: one per input, each index exactly once,
/// all of the configured [`dimensions`](Self::dimensions) (or of one length
/// when unset) — a mismatch is [`EmbedError::DimensionMismatch`], never a
/// panic.
///
/// # Quick Start
///
/// ```rust,no_run
/// use rune_chain_embed::{Embedder, OpenAiEmbedder};
///
/// # tokio_test::block_on(async {
/// let embedder = OpenAiEmbedder::from_env().unwrap();
/// let vector = embedder.embed("the quick brown fox").await.unwrap();
/// println!("dims: {}", vector.len()); // 1536
/// # });
/// ```
///
/// Use the builder for a custom model, truncated dimensions or an
/// OpenAI-compatible server:
///
/// ```rust
/// use rune_chain_embed::{EncodingFormat, OpenAiEmbedder};
///
/// let embedder = OpenAiEmbedder::new("sk-...")
///     .model("text-embedding-3-large")
///     .dimensions(256)
///     .encoding_format(EncodingFormat::Base64);
///
/// let local = OpenAiEmbedder::new("")
///     .base_url("http://localhost:8000/v1")
///     .model("BAAI/bge-small-en-v1.5");
/// ```
#[derive(Clone)]
pub struct OpenAiEmbedder {
    transport: Transport,
    model: String,
    dimensions: Option<u32>,
    encoding_format: EncodingFormat,
}

impl fmt::Debug for OpenAiEmbedder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiEmbedder")
            .field("api_key", &self.transport.api_key)
            .field("model", &self.model)
            .field("dimensions", &self.dimensions)
            .field("encoding_format", &self.encoding_format)
            .field("base_url", &self.transport.base_url)
            .finish_non_exhaustive()
    }
}

impl OpenAiEmbedder {
    /// Create a client with the given API key and default settings
    /// ([`DEFAULT_OPENAI_MODEL`], full dimensions, [`DEFAULT_BASE_URL`]).
    /// An empty key sends no `Authorization` header (for local servers).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_embed::OpenAiEmbedder;
    ///
    /// let embedder = OpenAiEmbedder::new("sk-test-key");
    /// ```
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            transport: Transport::new(api_key, DEFAULT_BASE_URL, DEFAULT_OPENAI_BATCH_SIZE),
            model: DEFAULT_OPENAI_MODEL.to_string(),
            dimensions: None,
            encoding_format: EncodingFormat::Float,
        }
    }

    /// Create a client from the `OPENAI_API_KEY` environment variable, and
    /// `OPENAI_BASE_URL` when set.
    ///
    /// # Errors
    ///
    /// [`EmbedError::InvalidConfig`] if `OPENAI_API_KEY` is unset.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use rune_chain_embed::OpenAiEmbedder;
    ///
    /// let embedder = OpenAiEmbedder::from_env().expect("OPENAI_API_KEY must be set");
    /// ```
    pub fn from_env() -> Result<Self, EmbedError> {
        let api_key = std::env::var("OPENAI_API_KEY").map_err(|_| {
            EmbedError::InvalidConfig("OPENAI_API_KEY environment variable not set".into())
        })?;
        let embedder = Self::new(api_key);
        Ok(match std::env::var("OPENAI_BASE_URL") {
            Ok(url) if !url.trim().is_empty() => embedder.base_url(url),
            _ => embedder,
        })
    }

    /// Override the embedding model.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_embed::OpenAiEmbedder;
    ///
    /// let embedder = OpenAiEmbedder::new("sk-key").model("text-embedding-3-large");
    /// ```
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Truncate output vectors to `dims` dimensions (`dimensions`), and
    /// require every returned vector to have exactly that length.
    ///
    /// Only supported by `text-embedding-3-*` (and compatible servers with
    /// Matryoshka models). Truncating reduces storage and similarity-search
    /// cost at the expense of some retrieval quality.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_embed::OpenAiEmbedder;
    ///
    /// let embedder = OpenAiEmbedder::new("sk-key").dimensions(256);
    /// ```
    #[must_use]
    pub const fn dimensions(mut self, dims: u32) -> Self {
        self.dimensions = Some(dims);
        self
    }

    /// Wire encoding of the vectors (`encoding_format`, default
    /// [`EncodingFormat::Float`]). [`EncodingFormat::Base64`] shrinks
    /// responses about fourfold; the result is the same.
    #[must_use]
    pub const fn encoding_format(mut self, format: EncodingFormat) -> Self {
        self.encoding_format = format;
        self
    }

    async fn request(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        let body = EmbedRequest {
            model: &self.model,
            input: texts,
            dimensions: self.dimensions,
            encoding_format: (self.encoding_format != EncodingFormat::Float)
                .then_some(self.encoding_format),
        };
        let bytes = self.transport.post_json(EMBED_PATH, &body).await?;
        decode_embeddings(&bytes, texts.len())
    }
}

transport_builders!(OpenAiEmbedder, DEFAULT_BASE_URL);

#[async_trait]
impl Embedder for OpenAiEmbedder {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        let dims = self.dimensions.map(|d| d as usize);
        self.batched(texts, dims, |chunk| self.request(chunk)).await
    }

    fn model_id(&self) -> Option<String> {
        Some(
            self.dimensions
                .map_or_else(|| self.model.clone(), |d| format!("{}/{d}", self.model)),
        )
    }
}

/// Decode an OpenAI-style `{"data":[{"index":…,"embedding":…}]}` body into
/// `expected` vectors in input order. Every index in `0..expected` must
/// appear exactly once. Embeddings may be float arrays or base64 strings.
pub fn decode_embeddings(body: &[u8], expected: usize) -> Result<Vec<Vec<f32>>, EmbedError> {
    let data: EmbedResponse =
        serde_json::from_slice(body).map_err(|e| EmbedError::InvalidResponse(e.to_string()))?;
    if data.data.len() != expected {
        return Err(EmbedError::InvalidResponse(format!(
            "expected {expected} embeddings, got {}",
            data.data.len()
        )));
    }
    let mut slots: Vec<Option<Vec<f32>>> = vec![None; expected];
    for item in data.data {
        let slot = slots.get_mut(item.index).ok_or_else(|| {
            EmbedError::InvalidResponse(format!("embedding index {} out of range", item.index))
        })?;
        if slot.is_some() {
            return Err(EmbedError::InvalidResponse(format!(
                "duplicate embedding index {}",
                item.index
            )));
        }
        *slot = Some(item.embedding.into_vector()?);
    }
    // Every slot is filled: `expected` distinct in-range indices.
    Ok(slots.into_iter().flatten().collect())
}

// --- Wire types ---

#[derive(Serialize)]
struct EmbedRequest<'a> {
    model: &'a str,
    input: &'a [&'a str],
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding_format: Option<EncodingFormat>,
}

#[derive(Deserialize)]
struct EmbedResponse {
    data: Vec<EmbedItem>,
}

#[derive(Deserialize)]
struct EmbedItem {
    index: usize,
    embedding: RawEmbedding,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawEmbedding {
    Floats(Vec<f32>),
    Base64(String),
}

impl RawEmbedding {
    fn into_vector(self) -> Result<Vec<f32>, EmbedError> {
        match self {
            Self::Floats(v) => Ok(v),
            Self::Base64(s) => {
                let bytes = rune_base64::decode(&s).map_err(|e| {
                    EmbedError::InvalidResponse(format!("invalid base64 embedding: {e}"))
                })?;
                if bytes.len() % 4 != 0 {
                    return Err(EmbedError::InvalidResponse(format!(
                        "base64 embedding of {} bytes is not a whole number of f32s",
                        bytes.len()
                    )));
                }
                Ok(bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| f32::from_le_bytes(*b))
                    .collect())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn request_omits_optional_fields_by_default() {
        let body = EmbedRequest {
            model: DEFAULT_OPENAI_MODEL,
            input: &["a", "b"],
            dimensions: None,
            encoding_format: None,
        };
        assert_eq!(
            serde_json::to_value(&body).unwrap(),
            json!({ "model": "text-embedding-3-small", "input": ["a", "b"] })
        );
    }

    #[test]
    fn builder_sets_fields_and_debug_redacts_key() {
        let embedder = OpenAiEmbedder::new("sk-very-secret-key")
            .model("text-embedding-3-large")
            .dimensions(256);
        assert_eq!(embedder.transport.api_key.expose(), "sk-very-secret-key");
        assert_eq!(
            embedder.model_id().as_deref(),
            Some("text-embedding-3-large/256")
        );
        let debug = format!("{embedder:?}");
        assert!(!debug.contains("sk-very-secret-key"), "{debug}");
        assert!(debug.contains("[REDACTED]"));
        assert_eq!(
            OpenAiEmbedder::new("k").model_id().as_deref(),
            Some(DEFAULT_OPENAI_MODEL)
        );
    }

    #[test]
    fn decodes_fixture_and_restores_input_order() {
        // Shape of a real `/v1/embeddings` response, items deliberately out of order.
        let body = br#"{
            "object": "list",
            "data": [
                { "object": "embedding", "index": 1, "embedding": [0.5, -0.5] },
                { "object": "embedding", "index": 0, "embedding": [0.25, 0.75] }
            ],
            "model": "text-embedding-3-small",
            "usage": { "prompt_tokens": 4, "total_tokens": 4 }
        }"#;
        assert_eq!(
            decode_embeddings(body, 2).unwrap(),
            vec![vec![0.25, 0.75], vec![0.5, -0.5]]
        );
    }

    #[test]
    fn decodes_base64_embeddings() {
        let raw: Vec<u8> = [1.0f32, -2.5]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();
        let body = json!({ "data": [{ "index": 0, "embedding": rune_base64::encode(&raw) }] });
        assert_eq!(
            decode_embeddings(body.to_string().as_bytes(), 1).unwrap(),
            vec![vec![1.0, -2.5]]
        );
        let bad = json!({ "data": [{ "index": 0, "embedding": "AAA=" }] });
        assert!(decode_embeddings(bad.to_string().as_bytes(), 1).is_err());
    }

    #[test]
    fn malformed_bodies_are_invalid_response() {
        let invalid = |body: &str, n| {
            matches!(
                decode_embeddings(body.as_bytes(), n),
                Err(EmbedError::InvalidResponse(_))
            )
        };
        assert!(invalid(r#"{"data": [{"index": 0}]}"#, 1));
        assert!(invalid("<html>", 1));
        assert!(invalid(r#"{"data": [{"index": 0, "embedding": [1]}]}"#, 2));
        assert!(invalid(
            r#"{"data": [{"index": 0, "embedding": [1]}, {"index": 0, "embedding": [2]}]}"#,
            2
        ));
        assert!(invalid(r#"{"data": [{"index": 5, "embedding": [1]}]}"#, 1));
    }

    #[tokio::test]
    async fn empty_batch_short_circuits_without_network() {
        let embedder = OpenAiEmbedder::new("unused");
        assert_eq!(
            embedder.embed_batch(&[]).await.unwrap(),
            Vec::<Vec<f32>>::new()
        );
    }

    #[tokio::test]
    async fn plain_http_to_remote_host_is_refused_before_sending() {
        let embedder = OpenAiEmbedder::new("sk-secret-123456").base_url("http://example.com/v1");
        let err = embedder.embed("x").await.unwrap_err();
        assert!(matches!(err, EmbedError::InvalidConfig(_)), "{err:?}");
    }
}
