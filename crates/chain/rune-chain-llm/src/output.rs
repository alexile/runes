use rune_chain_core::{ChainError, FinishReason, GenerateResult, TokenUsage};
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Everything one [`LlmChain`](crate::LlmChain) run produced: the model's
/// [`GenerateResult`] (text, token usage, finish reason, reasoning) and, when
/// an output parser or a JSON response format is configured, the parsed
/// value.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::{FinishReason, GenerateResult, TokenUsage};
/// use rune_chain_llm::LlmOutput;
/// use serde_json::json;
///
/// let out = LlmOutput::new(
///     GenerateResult::from_text(r#"{"n": 4}"#)
///         .with_tokens(TokenUsage::new(10, 3))
///         .with_finish_reason(FinishReason::Stop),
///     Some(json!({"n": 4})),
/// );
/// assert_eq!(out.usage().map(|u| u.total_tokens), Some(13));
/// assert_eq!(out.finish_reason(), Some(&FinishReason::Stop));
/// #[derive(serde::Deserialize)]
/// struct N { n: u32 }
/// assert_eq!(out.parse_as::<N>().unwrap().n, 4);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LlmOutput {
    /// The model's full result.
    pub result: GenerateResult,
    /// The parsed output, when a parser or a JSON response format is set.
    pub parsed: Option<Value>,
}

impl LlmOutput {
    /// Bundle a result with its parsed value.
    #[must_use]
    pub const fn new(result: GenerateResult, parsed: Option<Value>) -> Self {
        Self { result, parsed }
    }

    /// The generated text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.result.generation
    }

    /// Token usage, if the provider reported it.
    #[must_use]
    pub const fn usage(&self) -> Option<&TokenUsage> {
        self.result.tokens.as_ref()
    }

    /// Why the model stopped, if the provider said.
    #[must_use]
    pub const fn finish_reason(&self) -> Option<&FinishReason> {
        self.result.finish_reason.as_ref()
    }

    /// `true` if the output hit the token limit.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.result.is_truncated()
    }

    /// The parsed value, if any.
    #[must_use]
    pub const fn parsed(&self) -> Option<&Value> {
        self.parsed.as_ref()
    }

    /// Deserialize the parsed value into `T`.
    ///
    /// # Errors
    ///
    /// [`ChainError::ParseError`] when there is no parsed value or it does
    /// not match `T`.
    pub fn parse_as<T: DeserializeOwned>(&self) -> Result<T, ChainError> {
        let value = self.parsed.clone().ok_or_else(|| {
            ChainError::ParseError(
                "no parsed output: configure an output parser or a JSON response format".into(),
            )
        })?;
        serde_json::from_value(value)
            .map_err(|e| ChainError::ParseError(format!("parsed output does not match: {e}")))
    }

    /// The model's result, dropping the parsed value.
    #[must_use]
    pub fn into_result(self) -> GenerateResult {
        self.result
    }
}
