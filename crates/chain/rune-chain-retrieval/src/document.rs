use std::collections::HashMap;

use thiserror::Error;

/// A piece of text with optional key-value metadata.
///
/// Documents are the unit of storage in a [`VectorStore`](crate::VectorStore).
/// Each document holds arbitrary text content and a metadata map that callers
/// can use to attach source URLs, titles, page numbers, or any other provenance
/// information.
///
/// # Examples
///
/// ```rust
/// use rune_chain_retrieval::Document;
///
/// let doc = Document::new("Rust is a systems programming language.");
/// assert_eq!(doc.content, "Rust is a systems programming language.");
///
/// let doc_with_meta = Document::from_content("Page 42 of the manual.")
///     .with_meta("source", "manual.pdf")
///     .with_meta("page", "42");
/// assert_eq!(doc_with_meta.metadata["source"], "manual.pdf");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// The text content of this document.
    pub content: String,
    /// Arbitrary key-value metadata (source URL, title, page number, …).
    pub metadata: HashMap<String, String>,
}

impl Document {
    /// Create a document with the given content and no metadata.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_retrieval::Document;
    ///
    /// let doc = Document::new("hello world");
    /// assert!(doc.metadata.is_empty());
    /// ```
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            metadata: HashMap::new(),
        }
    }

    /// Start a builder chain from the given content.
    ///
    /// Equivalent to [`Document::new`]; use this for readability when
    /// chaining `.with_meta` calls.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_retrieval::Document;
    ///
    /// let doc = Document::from_content("hello")
    ///     .with_meta("lang", "en");
    /// assert_eq!(doc.metadata["lang"], "en");
    /// ```
    pub fn from_content(content: impl Into<String>) -> Self {
        Self::new(content)
    }

    /// Attach a single metadata key-value pair, returning `self` for chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_retrieval::Document;
    ///
    /// let doc = Document::from_content("text")
    ///     .with_meta("url", "https://example.com")
    ///     .with_meta("page", "1");
    /// assert_eq!(doc.metadata.len(), 2);
    /// ```
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Errors produced by a [`VectorStore`](crate::VectorStore).
#[derive(Debug, Error)]
pub enum StoreError {
    /// Any store error not covered by a more specific variant.
    #[error("{0}")]
    Other(String),
}

impl From<StoreError> for rune_chain_core::ChainError {
    fn from(err: StoreError) -> Self {
        Self::Other(err.to_string())
    }
}
