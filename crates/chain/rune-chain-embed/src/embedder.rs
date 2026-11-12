use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

/// Errors produced by an [`Embedder`].
///
/// Messages never contain the provider API key, and provider error bodies
/// are truncated before they are put into a message.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EmbedError {
    /// HTTP or network-level failure contacting the provider (including
    /// timeouts and non-JSON error replies).
    #[error("request failed: {0}")]
    RequestFailed(String),
    /// The provider rejected the request (auth, quota, rate limit, …).
    #[error("provider error: {0}")]
    ProviderError(String),
    /// The provider returned a response that could not be decoded, exceeded
    /// the response-size cap, or did not match the request (wrong count,
    /// duplicate or missing indices).
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    /// A vector has a different length than expected: the configured
    /// `dimensions`, the other vectors of the same batch, or the other
    /// operand of a similarity function.
    #[error("dimension mismatch: expected {expected} dimensions, got {actual}")]
    DimensionMismatch {
        /// The expected length.
        expected: usize,
        /// The length found.
        actual: usize,
    },
    /// The embedder is misconfigured: an invalid or plain-HTTP base URL, an
    /// API key that cannot be sent in a header, a zero batch size, …
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// Any error not covered by the variants above (e.g. a cache store
    /// failure).
    #[error("{0}")]
    Other(String),
}

impl From<EmbedError> for rune_chain_core::ChainError {
    fn from(err: EmbedError) -> Self {
        Self::Other(err.to_string())
    }
}

/// Provider-agnostic interface for converting text into embedding vectors.
///
/// Implement this trait to plug any embedding backend — `OpenAI`, Ollama, a local
/// ONNX model, or a test double — into `rune-chain-retrieval` or any other
/// pipeline that needs dense vector representations of text.
///
/// # Implementing
///
/// Only [`embed_batch`](Embedder::embed_batch) is required. The default
/// [`embed`](Embedder::embed) calls it with a one-element slice, which is
/// correct but makes one round-trip per call. Override `embed` if your provider
/// offers a cheaper single-input path.
///
/// # Queries and documents
///
/// Some models embed a search query differently from the documents it is
/// matched against (Cohere `input_type`, Voyage `input_type`, Jina `task`).
/// [`embed_query`](Embedder::embed_query) and
/// [`embed_documents`](Embedder::embed_documents) make the distinction
/// explicit; by default they are [`embed`](Embedder::embed) and
/// [`embed_batch`](Embedder::embed_batch). The providers in this crate treat
/// `embed` as a query and `embed_batch` as documents, which matches how
/// `rune-chain-retrieval` calls them.
///
/// ```rust
/// use rune_chain_embed::{EmbedError, Embedder};
/// use async_trait::async_trait;
///
/// struct OnesEmbedder {
///     dims: usize,
/// }
///
/// #[async_trait]
/// impl Embedder for OnesEmbedder {
///     async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
///         Ok(texts.iter().map(|_| vec![1.0f32; self.dims]).collect())
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let embedder = OnesEmbedder { dims: 4 };
/// let vec = embedder.embed("hello").await.unwrap();
/// assert_eq!(vec, vec![1.0, 1.0, 1.0, 1.0]);
/// # });
/// ```
#[async_trait]
pub trait Embedder: Sync + Send {
    /// Embed a batch of texts in a single provider round-trip.
    ///
    /// Returns one embedding vector per input text, in the same order as
    /// `texts`. An empty `texts` slice must return an empty `Vec`.
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError>;

    /// Embed a single text.
    ///
    /// Calls [`embed_batch`](Embedder::embed_batch) with a one-element slice
    /// by default. Override for providers that offer a cheaper single-input API.
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        self.embed_batch(&[text])
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| EmbedError::Other("provider returned an empty embedding list".into()))
    }

    /// Embed a search query, for providers that distinguish queries from
    /// documents. Defaults to [`embed`](Embedder::embed).
    async fn embed_query(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        self.embed(text).await
    }

    /// Embed documents to be searched, for providers that distinguish
    /// queries from documents. Defaults to
    /// [`embed_batch`](Embedder::embed_batch).
    async fn embed_documents(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        self.embed_batch(texts).await
    }

    /// An identifier of the vector space this embedder produces: the model
    /// plus any option that changes the vectors (e.g.
    /// `"text-embedding-3-small/256"`). `None` (the default) when unknown.
    ///
    /// [`CacheBackedEmbedder`](crate::CacheBackedEmbedder) uses it as its
    /// default cache namespace, so two embedders that report the same id must
    /// return the same vector for the same text.
    fn model_id(&self) -> Option<String> {
        None
    }
}

macro_rules! forward_embedder {
    ($($ty:ty),*) => {$(
        #[async_trait]
        impl<E: Embedder + ?Sized> Embedder for $ty {
            async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
                (**self).embed_batch(texts).await
            }
            async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
                (**self).embed(text).await
            }
            async fn embed_query(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
                (**self).embed_query(text).await
            }
            async fn embed_documents(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
                (**self).embed_documents(texts).await
            }
            fn model_id(&self) -> Option<String> {
                (**self).model_id()
            }
        }
    )*};
}

forward_embedder!(Arc<E>, Box<E>, &E);

#[cfg(test)]
mod tests {
    use rune_chain_core::ChainError;

    use super::*;

    /// Embeds each text as `[len, vowel count]`, so results are easy to predict.
    struct Counting;

    #[async_trait]
    impl Embedder for Counting {
        async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            Ok(texts
                .iter()
                .map(|t| {
                    let vowels = t.chars().filter(|c| "aeiou".contains(*c)).count();
                    #[allow(clippy::cast_precision_loss, reason = "tiny test counts")]
                    let v = vec![t.len() as f32, vowels as f32];
                    v
                })
                .collect())
        }
    }

    struct Empty;

    #[async_trait]
    impl Embedder for Empty {
        async fn embed_batch(&self, _texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn default_embed_delegates_to_batch() {
        assert_eq!(Counting.embed("banana").await.unwrap(), vec![6.0, 3.0]);
        assert_eq!(
            Counting.embed_batch(&["a", "xyz"]).await.unwrap(),
            vec![vec![1.0, 1.0], vec![3.0, 0.0]]
        );
    }

    #[tokio::test]
    async fn query_and_documents_default_to_embed_and_batch() {
        assert_eq!(
            Counting.embed_query("banana").await.unwrap(),
            vec![6.0, 3.0]
        );
        assert_eq!(
            Counting.embed_documents(&["a"]).await.unwrap(),
            vec![vec![1.0, 1.0]]
        );
        assert_eq!(Counting.model_id(), None);
    }

    #[tokio::test]
    async fn smart_pointers_forward() {
        let shared: Arc<dyn Embedder> = Arc::new(Counting);
        assert_eq!(shared.embed("ae").await.unwrap(), vec![2.0, 2.0]);
        let boxed: Box<dyn Embedder> = Box::new(Counting);
        assert_eq!(boxed.embed_query("x").await.unwrap(), vec![1.0, 0.0]);
        let by_ref = &Counting;
        assert_eq!(
            by_ref.embed_documents(&["io"]).await.unwrap(),
            vec![vec![2.0, 2.0]]
        );
    }

    #[tokio::test]
    async fn default_embed_reports_empty_provider_reply() {
        assert!(matches!(Empty.embed("x").await, Err(EmbedError::Other(_))));
    }

    #[test]
    fn errors_display_and_convert_to_chain_error() {
        let err = EmbedError::ProviderError("quota exceeded".into());
        assert_eq!(err.to_string(), "provider error: quota exceeded");
        let chain: ChainError = err.into();
        assert!(matches!(chain, ChainError::Other(ref m) if m == "provider error: quota exceeded"));
        let dims = EmbedError::DimensionMismatch {
            expected: 3,
            actual: 2,
        };
        assert_eq!(
            dims.to_string(),
            "dimension mismatch: expected 3 dimensions, got 2"
        );
    }
}
