use rune_chain_core::{ChainError, LlmError};
use rune_graph::GraphError;

/// Errors produced by knowledge graph operations.
#[derive(Debug)]
pub enum KgError {
    /// The LLM call failed.
    Llm(LlmError),
    /// The LLM returned output that could not be parsed as a triple list.
    Parse(String),
    /// Storing an extracted triple in the underlying graph failed.
    Graph(GraphError),
}

impl std::fmt::Display for KgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Llm(e) => write!(f, "LLM error: {e}"),
            Self::Parse(s) => write!(f, "parse error: {s}"),
            Self::Graph(e) => write!(f, "graph error: {e}"),
        }
    }
}

impl std::error::Error for KgError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Llm(e) => Some(e),
            Self::Graph(e) => Some(e),
            Self::Parse(_) => None,
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
        Self::Other(e.to_string())
    }
}
