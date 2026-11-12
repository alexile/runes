use thiserror::Error;

use crate::document::StoreError;
use crate::rerank::RerankError;

/// Errors produced by a [`Retriever`](crate::Retriever) and the retrieval
/// building blocks (fusion, MMR, multi-query, compression).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RetrievalError {
    /// A parameter was out of range (negative `k1`, `b` outside `[0, 1]`,
    /// non-finite weight, …). Raised when the component is configured, never
    /// for `top_k = 0`, which yields an empty result.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// The embedding provider failed.
    #[error("embedding failed: {0}")]
    Embed(String),
    /// The underlying [`VectorStore`](crate::VectorStore) failed.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    /// The LLM (e.g. generating query variants) failed.
    #[error("llm error: {0}")]
    Llm(String),
    /// A [`Reranker`](crate::Reranker) failed.
    #[error("rerank failed: {0}")]
    Rerank(#[from] RerankError),
    /// Any error not covered by the variants above.
    #[error("{0}")]
    Other(String),
}

impl From<rune_chain_embed::EmbedError> for RetrievalError {
    fn from(err: rune_chain_embed::EmbedError) -> Self {
        Self::Embed(err.to_string())
    }
}

impl From<rune_chain_core::LlmError> for RetrievalError {
    fn from(err: rune_chain_core::LlmError) -> Self {
        Self::Llm(err.to_string())
    }
}

impl From<RetrievalError> for rune_chain_core::ChainError {
    fn from(err: RetrievalError) -> Self {
        Self::Other(err.to_string())
    }
}

/// Return `Err(InvalidArgument)` unless `value` is finite and `>= 0`.
pub fn check_non_negative(name: &str, value: f32) -> Result<f32, RetrievalError> {
    if value.is_finite() && value >= 0.0 {
        Ok(value)
    } else {
        Err(RetrievalError::InvalidArgument(format!(
            "{name} must be finite and >= 0, got {value}"
        )))
    }
}

/// Return `Err(InvalidArgument)` unless `value` is in `[0, 1]`.
pub fn check_unit(name: &str, value: f32) -> Result<f32, RetrievalError> {
    if (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err(RetrievalError::InvalidArgument(format!(
            "{name} must be in [0, 1], got {value}"
        )))
    }
}
