use std::collections::HashMap;

/// A loaded document: its text content plus arbitrary key-value metadata.
///
/// Documents are the unit of input for the RAG pipeline — they flow from a
/// loader into a splitter (`rune-chain-splitter`) and then into an embedder
/// (`rune-chain-embed`).
///
/// # Example
///
/// ```rust
/// use rune_chain_loader::Document;
///
/// let doc = Document::new("hello world").with_metadata("source", "readme.txt");
/// assert_eq!(doc.content, "hello world");
/// assert_eq!(doc.metadata["source"], "readme.txt");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// The text content of the document.
    pub content: String,
    /// Arbitrary metadata: source path, page number, URL, etc.
    pub metadata: HashMap<String, String>,
}

impl Document {
    /// Create a document with the given `content` and no metadata.
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            metadata: HashMap::new(),
        }
    }

    /// Attach a single metadata key-value pair (builder-style).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_loader::Document;
    ///
    /// let doc = Document::new("text")
    ///     .with_metadata("source", "file.txt")
    ///     .with_metadata("page", "1");
    /// assert_eq!(doc.metadata.len(), 2);
    /// ```
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// The `source` metadata value, if set.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.metadata.get(crate::meta::SOURCE).map(String::as_str)
    }

    /// Lower-case hex SHA-256 of [`content`](Self::content), as stored by
    /// the loaders under [`meta::CONTENT_SHA256`](crate::meta::CONTENT_SHA256).
    ///
    /// ```rust
    /// use rune_chain_loader::Document;
    ///
    /// assert_eq!(
    ///     Document::new("").content_sha256(),
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    /// );
    /// ```
    #[must_use]
    pub fn content_sha256(&self) -> String {
        rune_sha256::hash_bytes(self.content.as_bytes())
    }
}
