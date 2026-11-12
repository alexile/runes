use rune_chain_core::TokenUsage;

use crate::extractor::Reject;
use crate::triple::Fact;

/// Counts of extracted items that were dropped, by reason.
///
/// # Example
///
/// ```rust
/// use rune_chain_knowledge_graph::Rejections;
///
/// let r = Rejections::default();
/// assert!(r.is_empty());
/// assert_eq!(r.total(), 0);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rejections {
    /// Wrong JSON type, empty name or label, a relation from an entity to
    /// itself, or a non-numeric confidence.
    pub invalid: usize,
    /// A name or label over its length limit.
    pub too_long: usize,
    /// A relation or entity type outside the configured allow-list.
    pub disallowed: usize,
    /// A relation under the configured minimum confidence.
    pub low_confidence: usize,
    /// Past the per-chunk entity or relation cap.
    pub over_limit: usize,
    /// Past the whole-graph entity or fact cap.
    pub capacity: usize,
}

impl Rejections {
    /// Sum of all counters.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.invalid
            + self.too_long
            + self.disallowed
            + self.low_confidence
            + self.over_limit
            + self.capacity
    }

    /// Whether nothing was dropped.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total() == 0
    }

    pub(crate) const fn add(&mut self, reason: Reject) {
        match reason {
            Reject::Invalid => self.invalid += 1,
            Reject::TooLong => self.too_long += 1,
            Reject::Disallowed => self.disallowed += 1,
            Reject::LowConfidence => self.low_confidence += 1,
            Reject::OverLimit => self.over_limit += 1,
        }
    }

    pub(crate) const fn merge(&mut self, other: &Self) {
        self.invalid += other.invalid;
        self.too_long += other.too_long;
        self.disallowed += other.disallowed;
        self.low_confidence += other.low_confidence;
        self.over_limit += other.over_limit;
        self.capacity += other.capacity;
    }
}

/// What one extraction call did.
///
/// # Example
///
/// ```rust
/// use rune_chain_knowledge_graph::ExtractionReport;
///
/// let r = ExtractionReport::default();
/// assert!(r.facts.is_empty());
/// assert_eq!(r.new_entities, 0);
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct ExtractionReport {
    /// Facts accepted in this call, as stored (canonical names; provenance
    /// is this call's sighting only).
    pub facts: Vec<Fact>,
    /// Entities created by this call.
    pub new_entities: usize,
    /// Mentions merged into an existing entity by embedding similarity
    /// rather than by name.
    pub merged_by_similarity: usize,
    /// Facts in this call that were already in the graph.
    pub duplicate_facts: usize,
    /// Items dropped, by reason.
    pub rejections: Rejections,
    /// Chunks sent to the model.
    pub chunks: usize,
    /// Token usage summed over the model calls, when the provider reports it.
    pub usage: Option<TokenUsage>,
}

impl ExtractionReport {
    pub(crate) fn absorb(&mut self, other: Self) {
        self.facts.extend(other.facts);
        self.new_entities += other.new_entities;
        self.merged_by_similarity += other.merged_by_similarity;
        self.duplicate_facts += other.duplicate_facts;
        self.rejections.merge(&other.rejections);
        self.chunks += other.chunks;
        TokenUsage::accumulate(&mut self.usage, other.usage.as_ref());
    }
}
