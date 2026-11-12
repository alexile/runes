use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_embed::{EmbedError, Embedder, cosine_similarity};
use tokio::sync::RwLock;

use crate::document::{Document, StoreError};
use crate::scored::ScoredDocument;

/// A store that can hold embedded documents and retrieve the most similar ones.
///
/// Implementations are responsible for storage and nearest-neighbour lookup.
/// The trait works with pre-computed embedding vectors so that any external
/// vector database (Qdrant, Pinecone, pgvector, …) can implement it without
/// needing an [`Embedder`] reference.
///
/// For in-process use see [`InMemoryVectorStore`], which wraps an [`Embedder`]
/// and handles embedding automatically.
///
/// # Implementing
///
/// ```rust
/// use async_trait::async_trait;
/// use rune_chain_retrieval::{Document, StoreError, VectorStore};
///
/// struct AlwaysEmptyStore;
///
/// #[async_trait]
/// impl VectorStore for AlwaysEmptyStore {
///     async fn add(&self, _docs: &[(Document, Vec<f32>)]) -> Result<(), StoreError> {
///         Ok(())
///     }
///     async fn search(&self, _emb: &[f32], _top_k: usize) -> Result<Vec<Document>, StoreError> {
///         Ok(vec![])
///     }
/// }
/// ```
#[async_trait]
pub trait VectorStore: Sync + Send {
    /// Store documents together with their pre-computed embedding vectors.
    ///
    /// Duplicate documents are added as-is; deduplication is the caller's
    /// responsibility.
    async fn add(&self, documents: &[(Document, Vec<f32>)]) -> Result<(), StoreError>;

    /// Return the `top_k` documents most similar to `query_embedding`.
    ///
    /// Results are returned in descending similarity order. Fewer than `top_k`
    /// documents may be returned if the store holds fewer entries.
    async fn search(
        &self,
        query_embedding: &[f32],
        top_k: usize,
    ) -> Result<Vec<Document>, StoreError>;
}

/// In-process vector store backed by a flat list and cosine similarity search.
///
/// `InMemoryVectorStore` is intentionally simple — all similarity computations
/// are linear scans. It is suitable for development, testing, and small document
/// sets. For production workloads with tens of thousands of documents, use a
/// purpose-built vector database and implement [`VectorStore`] for it.
///
/// It holds an [`Embedder`] internally so that [`add_texts`](Self::add_texts) and
/// [`similarity_search`](Self::similarity_search) can work directly with text strings. The lower-level
/// [`VectorStore`] trait methods accept pre-computed embeddings for callers
/// that manage embedding themselves.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use rune_chain_embed::{Embedder, OpenAiEmbedder};
/// use rune_chain_retrieval::InMemoryVectorStore;
///
/// # tokio_test::block_on(async {
/// let embedder: Arc<dyn Embedder> = Arc::new(OpenAiEmbedder::from_env().unwrap());
/// let store = InMemoryVectorStore::new(Arc::clone(&embedder));
///
/// store.add_texts(&[
///     "Rust is a systems programming language.",
///     "Python is a dynamic scripting language.",
/// ]).await.unwrap();
///
/// let docs = store.similarity_search("low-level programming", 1).await.unwrap();
/// println!("{}", docs[0].content);
/// # });
/// ```
pub struct InMemoryVectorStore {
    embedder: Arc<dyn Embedder>,
    entries: RwLock<Vec<(Document, Vec<f32>)>>,
}

impl InMemoryVectorStore {
    /// Create an empty store with the given embedder.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use rune_chain_embed::OpenAiEmbedder;
    /// use rune_chain_retrieval::InMemoryVectorStore;
    ///
    /// let store = InMemoryVectorStore::new(
    ///     Arc::new(OpenAiEmbedder::from_env().unwrap())
    /// );
    /// ```
    pub fn new(embedder: Arc<dyn Embedder>) -> Self {
        Self {
            embedder,
            entries: RwLock::new(Vec::new()),
        }
    }

    /// Embed `texts`, create [`Document`]s, and add them to the store.
    ///
    /// Uses a single [`Embedder::embed_batch`] call for efficiency.
    ///
    /// # Errors
    ///
    /// Returns [`EmbedError`] if the embedding provider fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use std::sync::Arc;
    /// # use rune_chain_embed::OpenAiEmbedder;
    /// # use rune_chain_retrieval::InMemoryVectorStore;
    /// # tokio_test::block_on(async {
    /// let store = InMemoryVectorStore::new(Arc::new(OpenAiEmbedder::from_env().unwrap()));
    /// store.add_texts(&["The capital of France is Paris."]).await.unwrap();
    /// # });
    /// ```
    pub async fn add_texts(&self, texts: &[&str]) -> Result<(), EmbedError> {
        if texts.is_empty() {
            return Ok(());
        }
        let embeddings = self.embedder.embed_batch(texts).await?;
        let pairs: Vec<(Document, Vec<f32>)> = texts
            .iter()
            .zip(embeddings)
            .map(|(&text, embedding)| (Document::new(text), embedding))
            .collect();
        self.entries.write().await.extend(pairs);
        Ok(())
    }

    /// Add [`Document`]s with their metadata, embedding the content.
    ///
    /// Useful when documents carry source URLs, page numbers, or other metadata
    /// that should be preserved in retrieval results.
    ///
    /// # Errors
    ///
    /// Returns [`EmbedError`] if the embedding provider fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use std::sync::Arc;
    /// # use rune_chain_embed::OpenAiEmbedder;
    /// # use rune_chain_retrieval::{Document, InMemoryVectorStore};
    /// # tokio_test::block_on(async {
    /// let store = InMemoryVectorStore::new(Arc::new(OpenAiEmbedder::from_env().unwrap()));
    /// let docs = vec![
    ///     Document::from_content("Paris is the capital of France.")
    ///         .with_meta("source", "geography.md"),
    /// ];
    /// store.add_documents(docs).await.unwrap();
    /// # });
    /// ```
    pub async fn add_documents(&self, documents: Vec<Document>) -> Result<(), EmbedError> {
        if documents.is_empty() {
            return Ok(());
        }
        let texts: Vec<&str> = documents.iter().map(|d| d.content.as_str()).collect();
        let embeddings = self.embedder.embed_batch(&texts).await?;
        let pairs: Vec<(Document, Vec<f32>)> = documents.into_iter().zip(embeddings).collect();
        self.entries.write().await.extend(pairs);
        Ok(())
    }

    /// Embed `query` and return the `top_k` most similar documents.
    ///
    /// Convenience wrapper that avoids holding an embedder reference on the
    /// call site. For use from outside a [`RetrievalQaChain`](crate::RetrievalQaChain).
    ///
    /// # Errors
    ///
    /// Returns [`EmbedError`] if the embedding provider fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use std::sync::Arc;
    /// # use rune_chain_embed::OpenAiEmbedder;
    /// # use rune_chain_retrieval::InMemoryVectorStore;
    /// # tokio_test::block_on(async {
    /// # let store = InMemoryVectorStore::new(Arc::new(OpenAiEmbedder::from_env().unwrap()));
    /// let docs = store.similarity_search("capital cities", 3).await.unwrap();
    /// for doc in &docs {
    ///     println!("{}", doc.content);
    /// }
    /// # });
    /// ```
    pub async fn similarity_search(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<Document>, EmbedError> {
        Ok(self
            .similarity_search_with_scores(query, top_k)
            .await?
            .into_iter()
            .map(|s| s.document)
            .collect())
    }

    /// Like [`similarity_search`](Self::similarity_search), returning each
    /// document with its cosine similarity to the query.
    ///
    /// `top_k = 0` returns an empty list without calling the embedder.
    ///
    /// # Errors
    ///
    /// Returns [`EmbedError`] if the embedding provider fails.
    pub async fn similarity_search_with_scores(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, EmbedError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }
        let query_embedding = self.embedder.embed(query).await?;
        Ok(self.scored_search(&query_embedding, top_k).await)
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "the read guard backs the borrowed documents until they are cloned"
    )]
    async fn scored_search(&self, query_embedding: &[f32], top_k: usize) -> Vec<ScoredDocument> {
        if top_k == 0 {
            return Vec::new();
        }
        let entries = self.entries.read().await;
        let mut scored: Vec<(f32, &Document)> = entries
            .iter()
            .map(|(doc, emb)| (cosine_similarity(query_embedding, emb), doc))
            .collect();
        // NaN (e.g. from a non-finite embedding) sinks below every real score.
        let key = |s: f32| if s.is_nan() { f32::NEG_INFINITY } else { s };
        scored.sort_by(|a, b| key(b.0).total_cmp(&key(a.0)));
        scored
            .into_iter()
            .take(top_k)
            .map(|(score, doc)| ScoredDocument::new(doc.clone(), score))
            .collect()
    }

    /// The number of documents currently in the store.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use std::sync::Arc;
    /// # use rune_chain_embed::OpenAiEmbedder;
    /// # use rune_chain_retrieval::InMemoryVectorStore;
    /// # tokio_test::block_on(async {
    /// let store = InMemoryVectorStore::new(Arc::new(OpenAiEmbedder::from_env().unwrap()));
    /// assert_eq!(store.len().await, 0);
    /// # });
    /// ```
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Returns `true` if the store contains no documents.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

#[async_trait]
impl VectorStore for InMemoryVectorStore {
    async fn add(&self, documents: &[(Document, Vec<f32>)]) -> Result<(), StoreError> {
        self.entries.write().await.extend(documents.iter().cloned());
        Ok(())
    }

    async fn search(
        &self,
        query_embedding: &[f32],
        top_k: usize,
    ) -> Result<Vec<Document>, StoreError> {
        Ok(self
            .scored_search(query_embedding, top_k)
            .await
            .into_iter()
            .map(|s| s.document)
            .collect())
    }
}
