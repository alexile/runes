use serde::{Deserialize, Serialize};

/// A single chunk delivered by a streaming LLM response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamData {
    /// The partial text content of this chunk.
    pub content: String,
    /// `true` for the final chunk; after this the stream ends.
    pub is_finished: bool,
}

impl StreamData {
    /// Create a non-terminal chunk carrying the given text fragment.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::StreamData;
    ///
    /// let chunk = StreamData::chunk("Hello");
    /// assert_eq!(chunk.content, "Hello");
    /// assert!(!chunk.is_finished);
    /// ```
    pub fn chunk(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            is_finished: false,
        }
    }

    /// Create the terminal chunk signalling the end of the stream.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::StreamData;
    ///
    /// let done = StreamData::done();
    /// assert!(done.is_finished);
    /// assert!(done.content.is_empty());
    /// ```
    #[must_use]
    pub const fn done() -> Self {
        Self {
            content: String::new(),
            is_finished: true,
        }
    }
}
