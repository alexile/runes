use std::fmt;
use std::ops::Range;

/// A single fact: a directed relationship between two named entities.
///
/// Triples are the atomic unit of a knowledge graph. The `subject` and
/// `object` are entity names; the `relation` is the edge label connecting
/// them.
///
/// # Example
///
/// ```rust
/// use rune_chain_knowledge_graph::Triple;
///
/// let t = Triple::new("Alice", "works_at", "Acme Corp");
/// assert_eq!(t.subject(), "Alice");
/// assert_eq!(t.relation(), "works_at");
/// assert_eq!(t.object(), "Acme Corp");
/// assert_eq!(t.to_string(), "Alice --[works_at]--> Acme Corp");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Triple {
    subject: String,
    relation: String,
    object: String,
}

impl Triple {
    /// Create a triple. Whitespace is trimmed from all three fields.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_knowledge_graph::Triple;
    ///
    /// assert_eq!(Triple::new(" A ", "r", "B").subject(), "A");
    /// ```
    pub fn new(
        subject: impl Into<String>,
        relation: impl Into<String>,
        object: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into().trim().to_string(),
            relation: relation.into().trim().to_string(),
            object: object.into().trim().to_string(),
        }
    }

    /// The entity the relationship starts from.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The relationship type label.
    #[must_use]
    pub fn relation(&self) -> &str {
        &self.relation
    }

    /// The entity the relationship points to.
    #[must_use]
    pub fn object(&self) -> &str {
        &self.object
    }

    /// Return `true` if no field is empty.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_knowledge_graph::Triple;
    ///
    /// assert!(Triple::new("A", "r", "B").is_valid());
    /// assert!(!Triple::new("A", " ", "B").is_valid());
    /// ```
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        !self.subject.is_empty() && !self.relation.is_empty() && !self.object.is_empty()
    }
}

impl fmt::Display for Triple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} --[{}]--> {}",
            self.subject, self.relation, self.object
        )
    }
}

/// Where a node or edge came from: a document, a chunk of it, and a byte
/// span inside the document.
///
/// `span` is in bytes of the whole document (the chunk's offset is already
/// added). When the model's evidence quote is found verbatim in the chunk,
/// the span covers that quote and `exact` is `true`; otherwise the span
/// covers the whole chunk and `exact` is `false`.
///
/// # Example
///
/// ```rust
/// use rune_chain_knowledge_graph::Provenance;
///
/// let p = Provenance::new("doc-1", 0, 10..24, true);
/// assert_eq!(p.to_string(), "doc-1@10-24");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Provenance {
    /// Caller-supplied identifier of the source document.
    pub document_id: String,
    /// Index of the chunk within its document.
    pub chunk: usize,
    /// Byte range within the document.
    pub span: Range<usize>,
    /// Whether `span` points at the exact evidence quote (`true`) or at the
    /// whole chunk (`false`).
    pub exact: bool,
}

impl Provenance {
    /// Build a provenance record.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_knowledge_graph::Provenance;
    ///
    /// let p = Provenance::new("a.txt", 2, 100..140, false);
    /// assert_eq!(p.chunk, 2);
    /// ```
    pub fn new(
        document_id: impl Into<String>,
        chunk: usize,
        span: Range<usize>,
        exact: bool,
    ) -> Self {
        Self {
            document_id: document_id.into(),
            chunk,
            span,
            exact,
        }
    }
}

impl fmt::Display for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{}-{}",
            self.document_id, self.span.start, self.span.end
        )
    }
}

/// A stored fact: a [`Triple`] plus its confidence and every place it was
/// seen (up to [`ExtractionConfig::max_provenance`](crate::ExtractionConfig::max_provenance)).
///
/// The same `(subject, relation, object)` extracted from several chunks is
/// stored once; `confidence` is the highest confidence seen and `support`
/// counts every sighting, including those past the provenance cap.
#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    /// The relationship, using the entities' canonical display names.
    pub triple: Triple,
    /// Highest confidence reported for this fact, in `[0, 1]`.
    pub confidence: f32,
    /// How many times the fact was extracted.
    pub support: u32,
    /// Where it was extracted from, oldest first, capped.
    pub provenance: Vec<Provenance>,
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (confidence {:.2})", self.triple, self.confidence)
    }
}

/// A resolved entity: one node of the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    /// Canonical display name (the first spelling seen).
    pub name: String,
    /// Normalised `snake_case` type, when the model gave one.
    pub entity_type: Option<String>,
    /// Other spellings merged into this entity, capped.
    pub aliases: Vec<String>,
    /// How many times the entity was mentioned.
    pub mentions: u32,
    /// Where it was mentioned, oldest first, capped.
    pub provenance: Vec<Provenance>,
}
