//! Second-stage reranking of retrieved documents.

mod http;

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

pub use http::{
    ApiReranker, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_TIMEOUT, RerankProvider, build_request_body,
    parse_response,
};

use crate::bm25::{SimpleTokenizer, Tokenizer};
use crate::error::RetrievalError;
use crate::retriever::Retriever;
use crate::scored::{ScoredDocument, sort_by_score};

/// Errors produced by a [`Reranker`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RerankError {
    /// Bad configuration (non-HTTPS base URL, missing API key, …).
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// Network failure or timeout.
    #[error("request failed: {0}")]
    Request(String),
    /// The provider answered with a non-success status. `body` is truncated.
    #[error("provider returned HTTP {status}: {body}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// Start of the response body.
        body: String,
    },
    /// The response exceeded the configured size cap.
    #[error("response larger than {limit} bytes")]
    ResponseTooLarge {
        /// The cap in bytes.
        limit: usize,
    },
    /// The response could not be decoded or referenced unknown documents.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

/// Reorders candidate documents by relevance to a query, typically with a
/// cross-encoder that is too slow for first-stage retrieval.
///
/// Implementations return at most `top_n` documents, best first, with
/// `score` replaced by the reranker's relevance score. `top_n = 0` or no
/// documents returns an empty list without doing any work.
#[async_trait]
pub trait Reranker: Send + Sync {
    /// Rerank `documents` for `query`, keeping the best `top_n`.
    async fn rerank(
        &self,
        query: &str,
        documents: Vec<ScoredDocument>,
        top_n: usize,
    ) -> Result<Vec<ScoredDocument>, RerankError>;
}

#[async_trait]
impl<T: Reranker + ?Sized> Reranker for Arc<T> {
    async fn rerank(
        &self,
        query: &str,
        documents: Vec<ScoredDocument>,
        top_n: usize,
    ) -> Result<Vec<ScoredDocument>, RerankError> {
        (**self).rerank(query, documents, top_n).await
    }
}

/// Deterministic local reranker: scores each document by the fraction of
/// distinct query terms it contains (`0.0`–`1.0`), using
/// [`SimpleTokenizer`]. Ties keep the incoming order.
///
/// No model, no network — a baseline, a test double, and a fallback when
/// no rerank API is configured.
///
/// ```rust
/// use rune_chain_retrieval::{Document, Reranker, ScoredDocument, TokenOverlapReranker};
///
/// # tokio_test::block_on(async {
/// let docs = vec![
///     ScoredDocument::new(Document::new("cats and dogs"), 0.9),
///     ScoredDocument::new(Document::new("rust borrow checker"), 0.1),
/// ];
/// let ranked = TokenOverlapReranker::new().rerank("rust checker", docs, 1).await?;
/// assert_eq!(ranked[0].document.content, "rust borrow checker");
/// assert_eq!(ranked[0].score, 1.0);
/// # Ok::<(), rune_chain_retrieval::RerankError>(())
/// # }).unwrap();
/// ```
#[derive(Debug, Clone, Default)]
pub struct TokenOverlapReranker {
    tokenizer: SimpleTokenizer,
}

impl TokenOverlapReranker {
    /// Reranker with the default [`SimpleTokenizer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Use a configured tokenizer (e.g. with stop words).
    #[must_use]
    pub const fn with_tokenizer(tokenizer: SimpleTokenizer) -> Self {
        Self { tokenizer }
    }
}

#[async_trait]
impl Reranker for TokenOverlapReranker {
    #[allow(
        clippy::cast_precision_loss,
        reason = "term counts are small; the ratio tolerates rounding"
    )]
    async fn rerank(
        &self,
        query: &str,
        documents: Vec<ScoredDocument>,
        top_n: usize,
    ) -> Result<Vec<ScoredDocument>, RerankError> {
        if top_n == 0 || documents.is_empty() {
            return Ok(Vec::new());
        }
        let terms: HashSet<String> = self.tokenizer.tokenize(query).into_iter().collect();
        let mut scored: Vec<ScoredDocument> = documents
            .into_iter()
            .map(|mut d| {
                d.score = if terms.is_empty() {
                    0.0
                } else {
                    let words: HashSet<String> = self
                        .tokenizer
                        .tokenize(&d.document.content)
                        .into_iter()
                        .collect();
                    terms.intersection(&words).count() as f32 / terms.len() as f32
                };
                d
            })
            .collect();
        sort_by_score(&mut scored);
        scored.truncate(top_n);
        Ok(scored)
    }
}

/// Retrieve `fetch_k` candidates from a base retriever, then rerank them
/// down to `top_k`.
///
/// ```rust
/// use std::sync::Arc;
/// use rune_chain_retrieval::{
///     Bm25Retriever, Document, RerankingRetriever, Retriever, TokenOverlapReranker,
/// };
///
/// # tokio_test::block_on(async {
/// let base = Arc::new(Bm25Retriever::from_documents(vec![Document::new("rust")]));
/// let r = RerankingRetriever::new(base, Arc::new(TokenOverlapReranker::new()));
/// assert_eq!(r.retrieve("rust", 3).await?.len(), 1);
/// # Ok::<(), rune_chain_retrieval::RetrievalError>(())
/// # }).unwrap();
/// ```
pub struct RerankingRetriever {
    base: Arc<dyn Retriever>,
    reranker: Arc<dyn Reranker>,
    fetch_k: usize,
}

impl std::fmt::Debug for RerankingRetriever {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RerankingRetriever")
            .field("fetch_k", &self.fetch_k)
            .finish_non_exhaustive()
    }
}

impl RerankingRetriever {
    /// Rerank the base retriever's top 20 (or `top_k`, if larger).
    pub fn new(base: Arc<dyn Retriever>, reranker: Arc<dyn Reranker>) -> Self {
        Self {
            base,
            reranker,
            fetch_k: 20,
        }
    }

    /// Candidates fetched before reranking (never fewer than `top_k`).
    #[must_use]
    pub const fn with_fetch_k(mut self, fetch_k: usize) -> Self {
        self.fetch_k = fetch_k;
        self
    }
}

#[async_trait]
impl Retriever for RerankingRetriever {
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }
        let candidates = self.base.retrieve(query, top_k.max(self.fetch_k)).await?;
        Ok(self.reranker.rerank(query, candidates, top_k).await?)
    }
}
