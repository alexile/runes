//! LLM-powered knowledge graph — extract facts from text, traverse them as a graph.
//!
//! `rune-chain-knowledge-graph` bridges two tracks of the `rune-*` ecosystem:
//!
//! - **`rune-chain-*`** (LLM orchestration) — the LLM extracts structured facts
//!   from unstructured text using a carefully engineered extraction prompt.
//! - **`rune-graph`** (graph primitive) — extracted facts are stored as a directed
//!   property graph where entities are nodes and relations are labelled edges.
//!
//! The result is a living knowledge graph that grows with every [`extract`](KnowledgeGraph::extract) call
//! and can be queried with graph traversal, shortest-path, and neighbourhood
//! expansion.
//!
//! # Features
//!
//! - [`KnowledgeGraph`] — the central struct: wraps an LLM + `rune-graph::Graph`
//! - [`Triple`] — a single `(subject, relation, object)` fact
//! - [`KgError`] — typed errors for LLM and parse failures
//! - `Chain` impl — use `KnowledgeGraph` as a pipeline step via `invoke`
//! - Entity deduplication — the same entity name always maps to the same graph node
//! - Batch extraction — process many chunks with one call
//! - Graph access — call any `rune_graph::algo` function on the underlying graph
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_core::{Chain, prompt_args};
//! use rune_chain_knowledge_graph::KnowledgeGraph;
//! # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
//! # use async_trait::async_trait;
//! # struct FakeLlm;
//! # #[async_trait] impl Llm for FakeLlm {
//! #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
//! #     Ok(GenerateResult::from_text(r#"[
//! #       {"subject":"Alice","relation":"knows","object":"Bob"},
//! #       {"subject":"Bob","relation":"works_at","object":"Acme Corp"},
//! #       {"subject":"Alice","relation":"founded","object":"Acme Corp"}
//! #     ]"#))
//! #   }
//! # }
//! # tokio_test::block_on(async {
//! // Plug in any rune-chain-* LLM (OpenAI, Anthropic, Ollama…)
//! let kg = KnowledgeGraph::new(FakeLlm);
//!
//! // Extract facts from text — LLM identifies triples automatically
//! kg.extract("Alice knows Bob. Bob works at Acme Corp. Alice founded Acme Corp.")
//!     .await
//!     .unwrap();
//!
//! // Query the graph
//! let rels = kg.relations_of("Alice").await;
//! assert!(rels.iter().any(|t| t.relation() == "knows"));
//!
//! // Find how two entities are connected
//! let path = kg.path_between("Alice", "Acme Corp").await.unwrap();
//! // → ["Alice", "Acme Corp"]  (direct edge via "founded")
//!
//! // Use as a Chain step in a pipeline
//! let result = kg
//!     .invoke(prompt_args! { "input" => "Paris is the capital of France." })
//!     .await
//!     .unwrap();
//! println!("{result}"); // Paris --[is_capital_of]--> France
//! # });
//! ```
//!
//! # Chunking large documents
//!
//! For documents that exceed the LLM context window, pre-chunk with
//! `rune-chain-splitter` and call [`extract_batch`](KnowledgeGraph::extract_batch):
//!
//! ```rust
//! # use rune_chain_knowledge_graph::KnowledgeGraph;
//! # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
//! # use async_trait::async_trait;
//! # struct FakeLlm;
//! # #[async_trait] impl Llm for FakeLlm {
//! #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
//! #     Ok(GenerateResult::from_text("[]"))
//! #   }
//! # }
//! # tokio_test::block_on(async {
//! use rune_chain_splitter::{TextSplitter, RecursiveSplitter};
//!
//! let document = "A long document with many facts…";
//! let splitter = RecursiveSplitter::new().chunk_size(500).chunk_overlap(50);
//! let chunks: Vec<String> = splitter.split(document);
//! let chunk_refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
//!
//! let kg = KnowledgeGraph::new(FakeLlm);
//! kg.extract_batch(&chunk_refs).await.unwrap();
//! # });
//! ```
//!
//! # Advanced graph queries
//!
//! The underlying `rune-graph` is exposed via [`KnowledgeGraph::graph`]:
//!
//! ```rust
//! # use rune_chain_knowledge_graph::KnowledgeGraph;
//! # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
//! # use async_trait::async_trait;
//! # struct FakeLlm;
//! # #[async_trait] impl Llm for FakeLlm {
//! #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
//! #     Ok(GenerateResult::from_text("[]"))
//! #   }
//! # }
//! # tokio_test::block_on(async {
//! use rune_graph::algo;
//!
//! let kg = KnowledgeGraph::new(FakeLlm);
//! let view = kg.graph().await;
//! let scores = algo::page_rank(&view, 0.85, 50);
//! // Find the most "important" entity in the knowledge graph
//! let top = scores.iter().max_by(|a, b| a.1.partial_cmp(b.1).unwrap());
//! # });
//! ```

mod chain;
mod extractor;
mod knowledge_graph;
#[cfg(test)]
mod tests;

/// Error type for knowledge graph operations.
pub mod error;
/// Entity-relation-entity triples.
pub mod triple;

pub use error::KgError;
pub use knowledge_graph::{GraphView, KnowledgeGraph};
pub use triple::Triple;
