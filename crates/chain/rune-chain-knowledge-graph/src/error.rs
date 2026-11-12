use rune_chain_core::{ChainError, LlmError};
use rune_graph::GraphError;

/// Boxed error returned by an [`EntityEmbedder`](crate::EntityEmbedder).
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Errors produced by knowledge graph operations.
///
/// The enum is `#[non_exhaustive]`: match it with a wildcard arm.
#[derive(Debug)]
#[non_exhaustive]
pub enum KgError {
    /// The LLM call failed.
    Llm(LlmError),
    /// The LLM's structured output was not usable JSON of the expected
    /// shape, or it was cut off by the output-token limit.
    Parse(String),
    /// Storing a fact in the underlying graph failed.
    Graph(GraphError),
    /// The entity embedder failed or returned malformed vectors.
    Embed(BoxError),
    /// An input was larger than the configured limit.
    InputTooLarge {
        /// What was too large (for example `"chunk"` or `"document"`).
        what: &'static str,
        /// Its size, in bytes or chunks.
        size: usize,
        /// The configured maximum.
        limit: usize,
    },
    /// An argument or configuration value is invalid.
    InvalidInput(String),
}

impl std::fmt::Display for KgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Llm(e) => write!(f, "LLM error: {e}"),
            Self::Parse(s) => write!(f, "parse error: {s}"),
            Self::Graph(e) => write!(f, "graph error: {e}"),
            Self::Embed(e) => write!(f, "embedding error: {e}"),
            Self::InputTooLarge { what, size, limit } => {
                write!(
                    f,
                    "{what} is too large: {size} exceeds the limit of {limit}"
                )
            }
            Self::InvalidInput(s) => write!(f, "invalid input: {s}"),
        }
    }
}

impl std::error::Error for KgError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Llm(e) => Some(e),
            Self::Graph(e) => Some(e),
            Self::Embed(e) => Some(e.as_ref()),
            Self::Parse(_) | Self::InputTooLarge { .. } | Self::InvalidInput(_) => None,
        }
    }
}

impl From<LlmError> for KgError {
    fn from(e: LlmError) -> Self {
        Self::Llm(e)
    }
}

impl From<GraphError> for KgError {
    fn from(e: GraphError) -> Self {
        Self::Graph(e)
    }
}

impl From<KgError> for ChainError {
    fn from(e: KgError) -> Self {
        match e {
            KgError::Llm(e) => Self::LlmError(e),
            KgError::Parse(s) => Self::ParseError(s),
            other => Self::Other(other.to_string()),
        }
    }
}
