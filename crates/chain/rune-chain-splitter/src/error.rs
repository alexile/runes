use std::error::Error as StdError;

/// Errors reported by the fallible splitting APIs.
///
/// The infallible [`TextSplitter::split`](crate::TextSplitter::split) and
/// [`TextSplitter::chunks`](crate::TextSplitter::chunks) clamp invalid
/// settings instead (a zero size becomes 1, an overlap is cut below the
/// size); [`TextSplitter::try_chunks`](crate::TextSplitter::try_chunks),
/// [`TextSplitter::validate`](crate::TextSplitter::validate) and the
/// [`SemanticChunker`](crate::SemanticChunker) report them as errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SplitError {
    /// A chunk size of zero can never make progress.
    #[error("chunk size must be greater than zero")]
    ZeroChunkSize,
    /// The overlap is at least as large as the chunk size, so a chunk could
    /// consist of nothing but the previous chunk's tail.
    #[error("chunk overlap ({overlap}) must be smaller than the chunk size ({chunk_size})")]
    OverlapTooLarge {
        /// The configured overlap.
        overlap: usize,
        /// The configured chunk size.
        chunk_size: usize,
    },
    /// Any other invalid setting (threshold out of range, zero batch size, …).
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// A sentence span is out of bounds, not on a `char` boundary, or out of order.
    #[error("invalid span {start}..{end} at index {index}")]
    InvalidSpan {
        /// Position of the span in the input slice.
        index: usize,
        /// Span start (bytes).
        start: usize,
        /// Span end (bytes).
        end: usize,
    },
    /// The embedder returned a different number of vectors than inputs.
    #[error("expected {expected} embeddings, got {got}")]
    EmbeddingCountMismatch {
        /// Number of inputs sent.
        expected: usize,
        /// Number of vectors received.
        got: usize,
    },
    /// An embedding's dimension differs from the first one's.
    #[error("embedding {index} has {got} dimensions, expected {expected}")]
    DimensionMismatch {
        /// Index of the offending embedding.
        index: usize,
        /// Dimension of the first embedding.
        expected: usize,
        /// Dimension of the offending embedding.
        got: usize,
    },
    /// An embedding contains `NaN` or an infinity.
    #[error("embedding {index} contains a non-finite value")]
    NonFiniteEmbedding {
        /// Index of the offending embedding.
        index: usize,
    },
    /// The embedding backend failed.
    #[error("embedding failed: {0}")]
    Embed(#[source] Box<dyn StdError + Send + Sync>),
}

/// Check a size/overlap pair: the size must be positive and the overlap smaller.
pub const fn check_sizes(chunk_size: usize, overlap: usize) -> Result<(), SplitError> {
    if chunk_size == 0 {
        return Err(SplitError::ZeroChunkSize);
    }
    if overlap >= chunk_size {
        return Err(SplitError::OverlapTooLarge {
            overlap,
            chunk_size,
        });
    }
    Ok(())
}
