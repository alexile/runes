use std::sync::Arc;

use async_trait::async_trait;

use crate::error::RetrievalError;
use crate::rerank::Reranker;
use crate::retriever::Retriever;
use crate::scored::{ScoredDocument, dedupe_by_content, filter_min_score};

/// Post-retrieval hook that shrinks, filters or rewrites retrieved
/// documents given the query — e.g. an LLM extracting only the relevant
/// sentences, a reranker, or a relevance filter.
///
/// Implementations may drop, reorder, rewrite and rescore documents.
///
/// ```rust
/// use async_trait::async_trait;
/// use rune_chain_retrieval::{DocumentCompressor, RetrievalError, ScoredDocument};
///
/// /// Keeps only the first sentence of each document.
/// struct FirstSentence;
///
/// #[async_trait]
/// impl DocumentCompressor for FirstSentence {
///     async fn compress(&self, _query: &str, docs: Vec<ScoredDocument>)
///         -> Result<Vec<ScoredDocument>, RetrievalError>
///     {
///         Ok(docs.into_iter().map(|mut d| {
///             if let Some(end) = d.document.content.find(". ") {
///                 d.document.content.truncate(end + 1);
///             }
///             d
///         }).collect())
///     }
/// }
/// ```
#[async_trait]
pub trait DocumentCompressor: Send + Sync {
    /// Compress `documents` retrieved for `query`.
    async fn compress(
        &self,
        query: &str,
        documents: Vec<ScoredDocument>,
    ) -> Result<Vec<ScoredDocument>, RetrievalError>;
}

/// Ready-made compressors, applied in order by [`CompressorPipeline`].
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum CompressionStep {
    /// Remove documents with duplicate content (keeps the first).
    Dedupe,
    /// Drop documents scoring below the value.
    MinScore(f32),
    /// Keep at most this many documents.
    Truncate(usize),
}

/// A sequence of [`CompressionStep`]s plus optional custom compressors,
/// run in insertion order.
#[derive(Default, Clone)]
pub struct CompressorPipeline {
    steps: Vec<PipelineStep>,
}

#[derive(Clone)]
enum PipelineStep {
    Builtin(CompressionStep),
    Custom(Arc<dyn DocumentCompressor>),
}

impl std::fmt::Debug for CompressorPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<String> = self
            .steps
            .iter()
            .map(|s| match s {
                PipelineStep::Builtin(b) => format!("{b:?}"),
                PipelineStep::Custom(_) => "Custom".to_owned(),
            })
            .collect();
        f.debug_struct("CompressorPipeline")
            .field("steps", &names)
            .finish()
    }
}

impl CompressorPipeline {
    /// Empty pipeline (passes documents through).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a built-in step.
    ///
    /// # Errors
    ///
    /// [`RetrievalError::InvalidArgument`] for `MinScore(NaN)`.
    pub fn step(mut self, step: CompressionStep) -> Result<Self, RetrievalError> {
        if matches!(step, CompressionStep::MinScore(s) if s.is_nan()) {
            return Err(RetrievalError::InvalidArgument(
                "min_score must not be NaN".into(),
            ));
        }
        self.steps.push(PipelineStep::Builtin(step));
        Ok(self)
    }

    /// Append a custom compressor.
    #[must_use]
    pub fn compressor(mut self, compressor: Arc<dyn DocumentCompressor>) -> Self {
        self.steps.push(PipelineStep::Custom(compressor));
        self
    }
}

#[async_trait]
impl DocumentCompressor for CompressorPipeline {
    async fn compress(
        &self,
        query: &str,
        mut documents: Vec<ScoredDocument>,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        for step in &self.steps {
            documents = match step {
                PipelineStep::Builtin(CompressionStep::Dedupe) => dedupe_by_content(documents),
                PipelineStep::Builtin(CompressionStep::MinScore(s)) => {
                    filter_min_score(documents, *s)
                }
                PipelineStep::Builtin(CompressionStep::Truncate(n)) => {
                    documents.truncate(*n);
                    documents
                }
                PipelineStep::Custom(c) => c.compress(query, documents).await?,
            };
        }
        Ok(documents)
    }
}

/// Adapts a [`Reranker`] into a [`DocumentCompressor`] keeping `top_n`.
pub struct RerankCompressor {
    reranker: Arc<dyn Reranker>,
    top_n: usize,
}

impl std::fmt::Debug for RerankCompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RerankCompressor")
            .field("top_n", &self.top_n)
            .finish_non_exhaustive()
    }
}

impl RerankCompressor {
    /// Rerank and keep the best `top_n`.
    pub fn new(reranker: Arc<dyn Reranker>, top_n: usize) -> Self {
        Self { reranker, top_n }
    }
}

#[async_trait]
impl DocumentCompressor for RerankCompressor {
    async fn compress(
        &self,
        query: &str,
        documents: Vec<ScoredDocument>,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        Ok(self.reranker.rerank(query, documents, self.top_n).await?)
    }
}

/// Retrieve with a base retriever, then pass the results through a
/// [`DocumentCompressor`] and keep at most `top_k`.
///
/// ```rust
/// use std::sync::Arc;
/// use rune_chain_retrieval::{
///     Bm25Retriever, CompressionStep, CompressorPipeline, ContextualCompressionRetriever,
///     Document, Retriever,
/// };
///
/// # tokio_test::block_on(async {
/// let base = Arc::new(Bm25Retriever::from_documents(vec![
///     Document::new("rust"), Document::new("rust"), Document::new("go"),
/// ]));
/// let pipeline = CompressorPipeline::new().step(CompressionStep::Dedupe)?;
/// let r = ContextualCompressionRetriever::new(base, Arc::new(pipeline));
/// assert_eq!(r.retrieve("rust", 5).await?.len(), 1);
/// # Ok::<(), rune_chain_retrieval::RetrievalError>(())
/// # }).unwrap();
/// ```
pub struct ContextualCompressionRetriever {
    base: Arc<dyn Retriever>,
    compressor: Arc<dyn DocumentCompressor>,
    fetch_k: Option<usize>,
}

impl std::fmt::Debug for ContextualCompressionRetriever {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextualCompressionRetriever")
            .field("fetch_k", &self.fetch_k)
            .finish_non_exhaustive()
    }
}

impl ContextualCompressionRetriever {
    /// Compress the base retriever's `top_k` results.
    pub fn new(base: Arc<dyn Retriever>, compressor: Arc<dyn DocumentCompressor>) -> Self {
        Self {
            base,
            compressor,
            fetch_k: None,
        }
    }

    /// Fetch this many candidates (never fewer than `top_k`) before
    /// compressing, for compressors that drop documents.
    #[must_use]
    pub const fn with_fetch_k(mut self, fetch_k: usize) -> Self {
        self.fetch_k = Some(fetch_k);
        self
    }
}

#[async_trait]
impl Retriever for ContextualCompressionRetriever {
    async fn retrieve(
        &self,
        query: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }
        let fetch = top_k.max(self.fetch_k.unwrap_or(top_k));
        let docs = self.base.retrieve(query, fetch).await?;
        let mut out = self.compressor.compress(query, docs).await?;
        out.truncate(top_k);
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]
mod tests {
    use super::*;
    use crate::document::Document;
    use crate::rerank::TokenOverlapReranker;

    fn sd(text: &str, score: f32) -> ScoredDocument {
        ScoredDocument::new(Document::new(text), score)
    }

    #[tokio::test]
    async fn pipeline_runs_steps_in_order() {
        let p = CompressorPipeline::new()
            .step(CompressionStep::Dedupe)
            .unwrap()
            .step(CompressionStep::MinScore(0.5))
            .unwrap()
            .compressor(Arc::new(RerankCompressor::new(
                Arc::new(TokenOverlapReranker::new()),
                5,
            )))
            .step(CompressionStep::Truncate(1))
            .unwrap();
        let out = p
            .compress(
                "beta",
                vec![
                    sd("alpha", 0.9),
                    sd("alpha", 0.8),
                    sd("beta", 0.7),
                    sd("low", 0.1),
                ],
            )
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].document.content, "beta");
        assert!(
            CompressorPipeline::new()
                .step(CompressionStep::MinScore(f32::NAN))
                .is_err()
        );
    }
}
