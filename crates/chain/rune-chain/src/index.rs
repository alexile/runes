//! [`EmbeddingIndex`]: any vector store plus any embedder, as a retriever.

use std::collections::HashMap;
use std::fmt;

use async_trait::async_trait;
use rune_chain_embed::Embedder;
use rune_chain_retrieval::{Document, RetrievalError, Retriever, ScoredDocument, StoreError};
use rune_vectorstore::{Query, Record, Value, VectorStore};

/// A searchable index: an [`Embedder`] for text plus a
/// [`VectorStore`](rune_vectorstore::VectorStore) for the vectors.
///
/// It is a [`Retriever`] with the store's real similarity scores, so it
/// plugs into [`AgentBuilder::dynamic_context`](crate::AgentBuilder::dynamic_context)
/// and the retrievers of `rune-chain-retrieval` (thresholds, hybrid, MMR,
/// reranking).
///
/// ```rust
/// use rune_chain::EmbeddingIndex;
/// use rune_chain::embed::{EmbedError, Embedder};
/// use rune_chain::retrieval::Retriever;
/// use rune_chain::vectorstore::InMemoryVectorStore;
///
/// /// Toy embedder: one feature per keyword.
/// struct Keywords;
///
/// #[async_trait::async_trait]
/// impl Embedder for Keywords {
///     async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
///         Ok(texts.iter().map(|t| {
///             let t = t.to_lowercase();
///             vec![f32::from(u8::from(t.contains("rust"))), f32::from(u8::from(t.contains("python")))]
///         }).collect())
///     }
/// }
///
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// let index = EmbeddingIndex::new(Keywords, InMemoryVectorStore::default());
/// index.add_documents([
///     ("rust", "Rust has no garbage collector."),
///     ("python", "Python is dynamically typed."),
/// ]).await.unwrap();
///
/// let hits = index.retrieve("Tell me about Rust", 1).await.unwrap();
/// assert_eq!(hits[0].document.content, "Rust has no garbage collector.");
/// assert_eq!(hits[0].document.metadata["id"], "rust");
/// # });
/// ```
pub struct EmbeddingIndex<E, S> {
    embedder: E,
    store: S,
}

impl<E, S> fmt::Debug for EmbeddingIndex<E, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbeddingIndex").finish_non_exhaustive()
    }
}

impl<E: Embedder, S: VectorStore> EmbeddingIndex<E, S> {
    /// Index text with `embedder` into `store`.
    pub const fn new(embedder: E, store: S) -> Self {
        Self { embedder, store }
    }

    /// Embed `documents` (`(id, text)` pairs) in one batch and upsert them.
    /// An existing id is replaced.
    ///
    /// # Errors
    ///
    /// Embedding failures and store errors (bad ids, dimension mismatch,
    /// non-finite vectors).
    pub async fn add_documents<I, K, V>(&self, documents: I) -> Result<(), RetrievalError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.add_records(
            documents
                .into_iter()
                .map(|(id, text)| (id.into(), text.into(), Vec::new())),
        )
        .await
    }

    /// [`add_documents`](Self::add_documents) with metadata per document
    /// (`(id, text, [(key, value)])`). Metadata comes back with each hit.
    ///
    /// # Errors
    ///
    /// As for [`add_documents`](Self::add_documents).
    pub async fn add_records<I>(&self, records: I) -> Result<(), RetrievalError>
    where
        I: IntoIterator<Item = (String, String, Vec<(String, Value)>)>,
    {
        let records: Vec<_> = records.into_iter().collect();
        if records.is_empty() {
            return Ok(());
        }
        let texts: Vec<&str> = records.iter().map(|(_, t, _)| t.as_str()).collect();
        let vectors = self.embedder.embed_documents(&texts).await?;
        if vectors.len() != records.len() {
            return Err(RetrievalError::Embed(format!(
                "the embedder returned {} vectors for {} texts",
                vectors.len(),
                records.len()
            )));
        }
        let records = records
            .into_iter()
            .zip(vectors)
            .map(|((id, text, meta), vector)| {
                meta.into_iter()
                    .fold(Record::new(id, vector).with_content(text), |r, (k, v)| {
                        r.with_meta(k, v)
                    })
            })
            .collect();
        self.store.upsert(records).await.map_err(store_error)
    }

    /// The vector store.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// The embedder.
    pub const fn embedder(&self) -> &E {
        &self.embedder
    }
}

#[allow(clippy::needless_pass_by_value, reason = "used with map_err")]
fn store_error(err: rune_vectorstore::StoreError) -> RetrievalError {
    RetrievalError::Store(StoreError::Other(err.to_string()))
}

#[async_trait]
impl<E: Embedder, S: VectorStore> Retriever for EmbeddingIndex<E, S> {
    /// Embeds `query` and returns the `top_k` nearest records. Each
    /// document's metadata holds its `id` plus the stored metadata (strings
    /// as they are, other values as JSON text).
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }
        let vector = self.embedder.embed_query(query).await?;
        let hits = self
            .store
            .query(&Query::new(vector, top_k).with_vectors(false))
            .await
            .map_err(store_error)?;
        Ok(hits
            .into_iter()
            .take(top_k)
            .map(|hit| {
                let record = hit.record;
                let mut metadata: HashMap<String, String> = record
                    .metadata
                    .into_iter()
                    .map(|(k, v)| match v {
                        Value::String(s) => (k, s),
                        other => (k, other.to_string()),
                    })
                    .collect();
                metadata.insert("id".to_owned(), record.id);
                let mut document = Document::new(record.content);
                document.metadata = metadata;
                ScoredDocument::new(document, hit.score)
            })
            .collect())
    }
}
