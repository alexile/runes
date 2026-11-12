use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_embed::Embedder;

use crate::document::Document;
use crate::error::RetrievalError;
use crate::scored::{ScoredDocument, dedupe_by_content, filter_min_score};
use crate::store::{InMemoryVectorStore, VectorStore};

/// Anything that turns a text query into a ranked list of documents.
///
/// Every retriever in this crate implements it: [`Bm25Retriever`](crate::Bm25Retriever)
/// (keyword), [`EmbeddingRetriever`] and [`InMemoryVectorStore`] (vector),
/// [`HybridRetriever`](crate::HybridRetriever) (fusion),
/// [`MmrRetriever`](crate::MmrRetriever), [`MultiQueryRetriever`](crate::MultiQueryRetriever),
/// [`RerankingRetriever`](crate::RerankingRetriever) and
/// [`ContextualCompressionRetriever`](crate::ContextualCompressionRetriever).
///
/// # Contract
///
/// - Results are sorted by descending score and hold at most `top_k` items.
/// - `top_k = 0` returns an empty list; it never errors or panics.
///
/// ```rust
/// use async_trait::async_trait;
/// use rune_chain_retrieval::{Document, RetrievalError, Retriever, ScoredDocument};
///
/// struct Fixed;
///
/// #[async_trait]
/// impl Retriever for Fixed {
///     async fn retrieve(&self, _query: &str, top_k: usize)
///         -> Result<Vec<ScoredDocument>, RetrievalError>
///     {
///         let all = vec![ScoredDocument::new(Document::new("hello"), 1.0)];
///         Ok(all.into_iter().take(top_k).collect())
///     }
/// }
/// ```
#[async_trait]
pub trait Retriever: Send + Sync {
    /// Return up to `top_k` documents for `query`, best first.
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError>;
}

#[async_trait]
impl<T: Retriever + ?Sized> Retriever for Arc<T> {
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        (**self).retrieve(query, top_k).await
    }
}

#[async_trait]
impl Retriever for InMemoryVectorStore {
    /// Cosine-similarity search; scores are cosine similarities.
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }
        Ok(self.similarity_search_with_scores(query, top_k).await?)
    }
}

/// Vector retriever over any [`VectorStore`]: embeds the query and searches.
///
/// The [`VectorStore`] trait does not return similarities, so scores are
/// derived from rank: `1 / (rank + 1)` (1.0, 0.5, 0.33, …). Use them for
/// ordering and rank fusion; prefer the [`InMemoryVectorStore`] retriever
/// when real cosine scores matter (e.g. for score thresholds).
pub struct EmbeddingRetriever {
    embedder: Arc<dyn Embedder>,
    store: Arc<dyn VectorStore>,
}

impl EmbeddingRetriever {
    /// Retrieve from `store`, embedding queries with `embedder`.
    pub fn new(embedder: Arc<dyn Embedder>, store: Arc<dyn VectorStore>) -> Self {
        Self { embedder, store }
    }
}

impl std::fmt::Debug for EmbeddingRetriever {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingRetriever").finish_non_exhaustive()
    }
}

#[async_trait]
impl Retriever for EmbeddingRetriever {
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }
        let embedding = self.embedder.embed(query).await?;
        let docs = self.store.search(&embedding, top_k).await?;
        Ok(rank_scored(docs.into_iter().take(top_k)))
    }
}

/// Score documents by rank: `1 / (rank + 1)`.
#[allow(
    clippy::cast_precision_loss,
    reason = "ranks are small; precision loss past 2^24 is irrelevant for scores"
)]
pub fn rank_scored(docs: impl IntoIterator<Item = Document>) -> Vec<ScoredDocument> {
    docs.into_iter()
        .enumerate()
        .map(|(rank, doc)| ScoredDocument::new(doc, 1.0 / (rank as f32 + 1.0)))
        .collect()
}

/// Retriever wrapper that drops results scoring below a threshold.
/// Built by [`RetrieverExt::with_min_score`].
#[derive(Debug, Clone)]
pub struct ScoreThreshold<R> {
    inner: R,
    min_score: f32,
}

#[async_trait]
impl<R: Retriever> Retriever for ScoreThreshold<R> {
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        let docs = self.inner.retrieve(query, top_k).await?;
        Ok(filter_min_score(docs, self.min_score))
    }
}

/// Retriever wrapper that removes documents with duplicate content.
/// Built by [`RetrieverExt::deduplicated`].
#[derive(Debug, Clone)]
pub struct Deduplicated<R> {
    inner: R,
    overfetch: usize,
}

#[async_trait]
impl<R: Retriever> Retriever for Deduplicated<R> {
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }
        let fetch = top_k.saturating_add(self.overfetch);
        let mut docs = dedupe_by_content(self.inner.retrieve(query, fetch).await?);
        docs.truncate(top_k);
        Ok(docs)
    }
}

/// Combinators for any [`Retriever`].
///
/// ```rust
/// use rune_chain_retrieval::{Bm25Retriever, Document, RetrieverExt};
///
/// let retriever = Bm25Retriever::from_documents(vec![Document::new("rust")])
///     .deduplicated()
///     .with_min_score(0.1)?;
/// # Ok::<(), rune_chain_retrieval::RetrievalError>(())
/// ```
pub trait RetrieverExt: Retriever + Sized {
    /// Drop results whose score is below `min_score`.
    ///
    /// # Errors
    ///
    /// [`RetrievalError::InvalidArgument`] if `min_score` is `NaN`.
    fn with_min_score(self, min_score: f32) -> Result<ScoreThreshold<Self>, RetrievalError> {
        if min_score.is_nan() {
            return Err(RetrievalError::InvalidArgument(
                "min_score must not be NaN".into(),
            ));
        }
        Ok(ScoreThreshold {
            inner: self,
            min_score,
        })
    }

    /// Remove documents whose content repeats a better-ranked one. Fetches
    /// `top_k + 8` candidates so that duplicates do not shrink the result;
    /// see [`deduplicated_with_overfetch`](Self::deduplicated_with_overfetch).
    fn deduplicated(self) -> Deduplicated<Self> {
        self.deduplicated_with_overfetch(8)
    }

    /// Like [`deduplicated`](Self::deduplicated), fetching `top_k + overfetch`
    /// candidates.
    fn deduplicated_with_overfetch(self, overfetch: usize) -> Deduplicated<Self> {
        Deduplicated {
            inner: self,
            overfetch,
        }
    }
}

impl<R: Retriever> RetrieverExt for R {}
