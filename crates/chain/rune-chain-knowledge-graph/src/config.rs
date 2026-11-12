use std::collections::BTreeSet;

use crate::error::KgError;
use crate::normalize;

/// Largest hop count [`RetrievalConfig::hops`] accepts.
pub const MAX_HOPS: usize = 6;

/// Limits and filters applied to extraction.
///
/// Every limit exists so that a model, or a hostile document steering it,
/// cannot flood the graph: per-chunk caps bound one LLM reply, the totals
/// bound the whole graph. Items over a limit are dropped and counted in
/// [`Rejections`](crate::Rejections); they never fail the call.
///
/// The struct is `#[non_exhaustive]`: start from [`Default`] and set fields.
///
/// # Example
///
/// ```rust
/// use rune_chain_knowledge_graph::ExtractionConfig;
///
/// let mut config = ExtractionConfig::default()
///     .with_allowed_relations(["works at", "founded", "located_in"]);
/// config.max_entities_per_chunk = 20;
/// config.min_confidence = 0.5;
/// assert!(config.allowed_relations.as_ref().unwrap().contains("works_at"));
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ExtractionConfig {
    /// Entities kept from one chunk's reply. Default 64.
    pub max_entities_per_chunk: usize,
    /// Relations kept from one chunk's reply. Default 128.
    pub max_relations_per_chunk: usize,
    /// Longest entity name kept, in characters. Default 100.
    pub max_name_chars: usize,
    /// Longest relation or type label kept, in characters. Default 48.
    pub max_label_chars: usize,
    /// Longest evidence quote kept, in characters. Default 300.
    pub max_evidence_chars: usize,
    /// Relations below this confidence are dropped. Default `0.0`.
    pub min_confidence: f32,
    /// Confidence assumed when the model leaves it out. Default `0.5`.
    pub default_confidence: f32,
    /// If set, only these relation labels (normalised to `snake_case`) are
    /// kept. Default `None` (any label).
    pub allowed_relations: Option<BTreeSet<String>>,
    /// If set, every entity must have one of these types (normalised to
    /// `snake_case`); untyped entities are dropped. Default `None`.
    pub allowed_entity_types: Option<BTreeSet<String>>,
    /// Largest chunk sent to the model, in bytes. Default 32 KiB.
    pub max_chunk_bytes: usize,
    /// Chunk size used by
    /// [`extract_document`](crate::KnowledgeGraph::extract_document), in
    /// bytes. Default 4000.
    pub chunk_bytes: usize,
    /// Overlap between consecutive chunks, in bytes. Default 200.
    pub chunk_overlap: usize,
    /// Most chunks one document may be split into. Default 1024.
    pub max_chunks_per_document: usize,
    /// Most entities the whole graph may hold. Default 100 000.
    pub max_entities: usize,
    /// Most distinct facts the whole graph may hold. Default 500 000.
    pub max_facts: usize,
    /// Provenance records kept per entity and per fact. Default 8.
    pub max_provenance: usize,
    /// Aliases kept per entity. Default 8.
    pub max_aliases: usize,
    /// With an embedder, a new name whose embedding has at least this cosine
    /// similarity to an existing entity (of a compatible type) is merged
    /// into it instead of becoming a new node. Default `0.92`.
    pub merge_similarity: f32,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            max_entities_per_chunk: 64,
            max_relations_per_chunk: 128,
            max_name_chars: 100,
            max_label_chars: 48,
            max_evidence_chars: 300,
            min_confidence: 0.0,
            default_confidence: 0.5,
            allowed_relations: None,
            allowed_entity_types: None,
            max_chunk_bytes: 32 * 1024,
            chunk_bytes: 4000,
            chunk_overlap: 200,
            max_chunks_per_document: 1024,
            max_entities: 100_000,
            max_facts: 500_000,
            max_provenance: 8,
            max_aliases: 8,
            merge_similarity: 0.92,
        }
    }
}

impl ExtractionConfig {
    /// Restrict relations to `labels`, normalised to `snake_case`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_knowledge_graph::ExtractionConfig;
    ///
    /// let c = ExtractionConfig::default().with_allowed_relations(["Works At"]);
    /// assert!(c.allowed_relations.unwrap().contains("works_at"));
    /// ```
    #[must_use]
    pub fn with_allowed_relations<I, S>(mut self, labels: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.allowed_relations = Some(normalised_set(labels));
        self
    }

    /// Restrict entity types to `types`, normalised to `snake_case`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_knowledge_graph::ExtractionConfig;
    ///
    /// let c = ExtractionConfig::default().with_allowed_entity_types(["Person", "Org"]);
    /// assert!(c.allowed_entity_types.unwrap().contains("person"));
    /// ```
    #[must_use]
    pub fn with_allowed_entity_types<I, S>(mut self, types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.allowed_entity_types = Some(normalised_set(types));
        self
    }

    pub(crate) fn validate(&self) -> Result<(), KgError> {
        let positive = [
            ("max_name_chars", self.max_name_chars),
            ("max_label_chars", self.max_label_chars),
            ("max_chunk_bytes", self.max_chunk_bytes),
            ("chunk_bytes", self.chunk_bytes),
            ("max_chunks_per_document", self.max_chunks_per_document),
        ];
        for (name, value) in positive {
            if value == 0 {
                return Err(KgError::InvalidInput(format!("{name} must be positive")));
            }
        }
        if self.chunk_overlap >= self.chunk_bytes {
            return Err(KgError::InvalidInput(
                "chunk_overlap must be smaller than chunk_bytes".into(),
            ));
        }
        if self.chunk_bytes > self.max_chunk_bytes {
            return Err(KgError::InvalidInput(
                "chunk_bytes must not exceed max_chunk_bytes".into(),
            ));
        }
        for (name, value) in [
            ("min_confidence", self.min_confidence),
            ("default_confidence", self.default_confidence),
            ("merge_similarity", self.merge_similarity),
        ] {
            if !(0.0..=1.0).contains(&value) {
                return Err(KgError::InvalidInput(format!(
                    "{name} must be within [0, 1]"
                )));
            }
        }
        Ok(())
    }
}

fn normalised_set<I, S>(items: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    items
        .into_iter()
        .map(|s| normalize::label(s.as_ref()))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Limits for [`KnowledgeGraph::retrieve`](crate::KnowledgeGraph::retrieve).
///
/// Retrieval cost is bounded by these numbers, not by the graph size, apart
/// from the seed search, which is linear in the number of entities that
/// share a word with the query (plus one cosine per entity when an embedder
/// is configured).
///
/// The struct is `#[non_exhaustive]`: start from [`Default`] and set fields.
///
/// # Example
///
/// ```rust
/// use rune_chain_knowledge_graph::RetrievalConfig;
///
/// let mut config = RetrievalConfig::default();
/// config.hops = 1;
/// config.max_context_chars = 2000;
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct RetrievalConfig {
    /// Seed entities taken from the query. Default 5.
    pub max_seeds: usize,
    /// Hops expanded from the seeds, at most [`MAX_HOPS`]. Default 2.
    pub hops: usize,
    /// Entities in the context, seeds included. Default 40.
    pub max_nodes: usize,
    /// Facts in the context. Default 80.
    pub max_facts: usize,
    /// Edges followed out of any single entity, highest confidence first,
    /// so that hubs do not swamp the context. Default 25.
    pub max_neighbors_per_node: usize,
    /// Length budget of [`GraphContext::text`](crate::GraphContext::text),
    /// in characters. Whole lines are dropped to fit. Default 6000.
    pub max_context_chars: usize,
    /// Minimum keyword score (share of an entity's words found in the query)
    /// for a seed. Default `0.5`.
    pub min_keyword_score: f32,
    /// Minimum cosine similarity between query and entity embeddings for a
    /// seed. Only used with an embedder. Default `0.75`.
    pub min_similarity: f32,
    /// Facts below this confidence are not followed. Default `0.0`.
    pub min_confidence: f32,
    /// Longest query used, in characters; the rest is ignored. Default 2000.
    pub max_query_chars: usize,
}

impl Default for RetrievalConfig {
    fn default() -> Self {
        Self {
            max_seeds: 5,
            hops: 2,
            max_nodes: 40,
            max_facts: 80,
            max_neighbors_per_node: 25,
            max_context_chars: 6000,
            min_keyword_score: 0.5,
            min_similarity: 0.75,
            min_confidence: 0.0,
            max_query_chars: 2000,
        }
    }
}

impl RetrievalConfig {
    pub(crate) fn validate(&self) -> Result<(), KgError> {
        if self.hops > MAX_HOPS {
            return Err(KgError::InvalidInput(format!(
                "hops must be at most {MAX_HOPS}"
            )));
        }
        for (name, value) in [
            ("min_keyword_score", self.min_keyword_score),
            ("min_similarity", self.min_similarity),
            ("min_confidence", self.min_confidence),
        ] {
            if !value.is_finite() || value > 1.0 {
                return Err(KgError::InvalidInput(format!("{name} must be at most 1")));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::field_reassign_with_default,
    reason = "configs are non-exhaustive, so callers set fields this way"
)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        assert!(ExtractionConfig::default().validate().is_ok());
        assert!(RetrievalConfig::default().validate().is_ok());
    }

    #[test]
    fn bad_values_are_rejected() {
        let mut c = ExtractionConfig::default();
        c.chunk_overlap = c.chunk_bytes;
        assert!(c.validate().is_err());
        let mut c = ExtractionConfig::default();
        c.min_confidence = 1.5;
        assert!(c.validate().is_err());
        let mut c = ExtractionConfig::default();
        c.chunk_bytes = c.max_chunk_bytes + 1;
        assert!(c.validate().is_err());
        let mut r = RetrievalConfig::default();
        r.hops = MAX_HOPS + 1;
        assert!(r.validate().is_err());
        let mut r = RetrievalConfig::default();
        r.min_similarity = f32::NAN;
        assert!(r.validate().is_err());
    }

    #[test]
    fn allow_lists_are_normalised() {
        let c = ExtractionConfig::default()
            .with_allowed_relations(["Works-At", "!!"])
            .with_allowed_entity_types(["Person"]);
        assert_eq!(
            c.allowed_relations.unwrap().into_iter().collect::<Vec<_>>(),
            ["works_at"]
        );
        assert!(c.allowed_entity_types.unwrap().contains("person"));
    }
}
