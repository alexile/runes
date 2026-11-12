use std::fmt;

/// A single extracted fact: a directed relationship between two named entities.
///
/// Triples are the atomic unit of a knowledge graph. The `subject` and `object`
/// are entity names; the `relation` is the edge label connecting them.
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
/// println!("{t}"); // Alice --[works_at]--> Acme Corp
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triple {
    subject: String,
    relation: String,
    object: String,
}

impl Triple {
    /// Create a triple. Whitespace is trimmed from all three fields.
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

    /// The entity at the tail of the relationship.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The relationship type label.
    #[must_use]
    pub fn relation(&self) -> &str {
        &self.relation
    }

    /// The entity at the head of the relationship.
    #[must_use]
    pub fn object(&self) -> &str {
        &self.object
    }

    /// Return `true` if any field is empty after trimming.
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
