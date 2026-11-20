use rune_chain_embed::EmbedError;
use rune_chain_output_parser::StructuredError;

/// Errors from loading datasets, configuring a run, or scoring one example.
///
/// An evaluator that fails returns one of these; the runner records it as
/// an error outcome for that example, which never counts as a pass.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EvalError {
    /// The dataset is malformed, too large, or has duplicate ids.
    #[error("dataset: {0}")]
    Dataset(String),
    /// Reading a dataset or report failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A builder or evaluator was given an invalid setting.
    #[error("invalid config: {0}")]
    Config(String),
    /// The example or output lacks something the evaluator needs (a
    /// reference, a question, retrieved contexts, …).
    #[error("missing {0}")]
    Missing(String),
    /// The input is too large for the evaluator's caps.
    #[error("too large: {0}")]
    TooLarge(String),
    /// The judge model failed or its reply could not be parsed into a
    /// verdict, even after re-asking.
    #[error("judge: {0}")]
    Judge(String),
    /// The embedder failed.
    #[error("embedding: {0}")]
    Embed(#[from] EmbedError),
    /// The evaluator did not finish within the run's timeout.
    #[error("evaluator timed out")]
    Timeout,
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

impl From<StructuredError> for EvalError {
    fn from(e: StructuredError) -> Self {
        Self::Judge(e.to_string())
    }
}

impl From<serde_json::Error> for EvalError {
    fn from(e: serde_json::Error) -> Self {
        Self::Other(format!("json: {e}"))
    }
}
