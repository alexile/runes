//! `GraphRAG` for the `rune-chain` LLM framework: build a knowledge graph from
//! documents with an LLM, then retrieve a bounded, cited neighbourhood for a
//! question.
//!
//! # What it does
//!
//! - **Extraction** with [`Llm::generate_structured`](rune_chain_core::Llm::generate_structured)
//!   and a JSON schema: typed entities and `(subject, relation, object)`
//!   relations, each with a confidence and a verbatim evidence quote.
//! - **Validation** of every reply ([`ExtractionConfig`]): per-chunk caps on
//!   entities and relations, name and label length limits, optional
//!   allow-lists of relation and entity types, minimum confidence, and caps
//!   on the whole graph. Document text is fenced as untrusted data in the
//!   prompt, so neither a model nor a hostile document can flood the graph.
//! - **Entity resolution**: names are matched case- and
//!   punctuation-insensitively (`"Acme Corp."` = `"acme corp"`); with an
//!   [`EntityEmbedder`], near-duplicates above
//!   [`ExtractionConfig::merge_similarity`] are merged as aliases.
//! - **Provenance** on every node and edge ([`Provenance`]): document id,
//!   chunk index and byte span of the evidence.
//! - **Retrieval** ([`KnowledgeGraph::retrieve`]): seed entities by keyword
//!   (and embedding) match, k-hop expansion with node, fact and fan-out
//!   limits, and a compact context string with numbered citations.
//! - **Communities** ([`KnowledgeGraph::communities`]): label propagation with
//!   one-line structural summaries, no model calls.
//! - The underlying [`rune_graph::Graph`] is available through
//!   [`KnowledgeGraph::graph`] for `rune_graph::algo`.
//!
//! # End-to-end example
//!
//! ```rust
//! use async_trait::async_trait;
//! use rune_chain_core::{GenerateResult, Llm, LlmError, Message};
//! use rune_chain_knowledge_graph::{ExtractionConfig, KnowledgeGraph, RetrievalConfig};
//!
//! // Stands in for any rune-chain provider (OpenAI, Anthropic, Ollama, ...).
//! struct Model;
//!
//! #[async_trait]
//! impl Llm for Model {
//!     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
//!         Ok(GenerateResult::from_text(r#"{
//!           "entities": [
//!             {"name": "Ada Lovelace", "type": "person"},
//!             {"name": "Analytical Engine", "type": "machine"},
//!             {"name": "Charles Babbage", "type": "person"}
//!           ],
//!           "relations": [
//!             {"subject": "Ada Lovelace", "relation": "wrote programs for",
//!              "object": "Analytical Engine", "confidence": 0.95,
//!              "evidence": "Ada Lovelace wrote programs for the Analytical Engine"},
//!             {"subject": "Charles Babbage", "relation": "designed",
//!              "object": "Analytical Engine", "confidence": 0.9,
//!              "evidence": "designed by Charles Babbage"}
//!           ]
//!         }"#))
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let config = ExtractionConfig::default()
//!     .with_allowed_relations(["wrote_programs_for", "designed", "worked_with"]);
//! let kg = KnowledgeGraph::new(Model).with_config(config).unwrap();
//!
//! let doc = "Ada Lovelace wrote programs for the Analytical Engine, \
//!            a machine designed by Charles Babbage.";
//! let report = kg.extract_document("history.txt", doc).await.unwrap();
//! assert_eq!(report.facts.len(), 2);
//! assert_eq!(report.new_entities, 3);
//! assert!(report.rejections.is_empty());
//!
//! // Every fact knows where it came from.
//! let fact = &kg.relations_of("ada lovelace").await[0];
//! let source = &fact.provenance[0];
//! assert_eq!(source.document_id, "history.txt");
//! assert_eq!(&doc[source.span.clone()], "Ada Lovelace wrote programs for the Analytical Engine");
//!
//! // Retrieve a cited context for a question.
//! let ctx = kg
//!     .retrieve("Who designed the machine Ada Lovelace programmed?", &RetrievalConfig::default())
//!     .await
//!     .unwrap();
//! assert_eq!(ctx.seeds[0].name, "Ada Lovelace");
//! assert!(ctx.text.contains("[2] Charles Babbage --[designed]--> Analytical Engine"));
//! assert_eq!(
//!     ctx.text,
//!     "Facts:\n\
//!      [1] Ada Lovelace --[wrote_programs_for]--> Analytical Engine \
//!      (confidence 0.95; source history.txt@0-53)\n\
//!      [2] Charles Babbage --[designed]--> Analytical Engine \
//!      (confidence 0.90; source history.txt@65-92)\n\
//!      Entities:\n\
//!      - Ada Lovelace (person)\n\
//!      - Analytical Engine (machine)\n\
//!      - Charles Babbage (person)"
//! );
//! // Put ctx.text into the answering prompt, fenced as untrusted data.
//! # });
//! ```
//!
//! # Bounded cost
//!
//! | What | Bound |
//! |---|---|
//! | Model calls per document | [`ExtractionConfig::max_chunks_per_document`] |
//! | Bytes per model call | [`ExtractionConfig::max_chunk_bytes`] |
//! | Items per reply | `max_entities_per_chunk`, `max_relations_per_chunk` |
//! | Graph size | [`ExtractionConfig::max_entities`], [`ExtractionConfig::max_facts`] |
//! | Provenance and aliases per item | `max_provenance`, `max_aliases` |
//! | Retrieval | `hops` (at most [`MAX_HOPS`]), `max_nodes`, `max_facts`, `max_neighbors_per_node`, `max_context_chars` |
//!
//! # Features
//!
//! - `embed`: [`FromEmbedder`] adapts any `rune_chain_embed::Embedder` into an
//!   [`EntityEmbedder`].

mod chain;
mod community;
mod config;
mod embedding;
mod error;
mod extractor;
mod knowledge_graph;
mod normalize;
mod report;
mod retrieval;
#[cfg(test)]
mod tests;
mod triple;

pub use community::{Community, MAX_ITERATIONS};
pub use config::{ExtractionConfig, MAX_HOPS, RetrievalConfig};
pub use embedding::EntityEmbedder;
#[cfg(feature = "embed")]
pub use embedding::FromEmbedder;
pub use error::{BoxError, KgError};
pub use extractor::SCHEMA_NAME;
pub use knowledge_graph::{DEFAULT_DOCUMENT_ID, GraphView, KnowledgeGraph};
pub use report::{ExtractionReport, Rejections};
pub use retrieval::{GraphContext, ScoredEntity, SeedMatch};
pub use triple::{Entity, Fact, Provenance, Triple};

/// The JSON schema requested from the model for one chunk, given `config`
/// (allow-lists become `enum`s). Useful for providers configured by hand or
/// for logging.
///
/// # Example
///
/// ```rust
/// use rune_chain_knowledge_graph::{ExtractionConfig, extraction_schema};
///
/// let schema = extraction_schema(&ExtractionConfig::default());
/// assert_eq!(schema["required"][1], "relations");
/// ```
#[must_use]
pub fn extraction_schema(config: &ExtractionConfig) -> serde_json::Value {
    extractor::schema(config)
}
