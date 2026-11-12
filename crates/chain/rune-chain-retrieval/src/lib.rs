//! RAG chain for `rune-chain` — embed queries, retrieve documents, answer with an LLM.
//!
//! `rune-chain-retrieval` implements Retrieval-Augmented Generation (RAG). It
//! wires together an [`Embedder`](rune_chain_embed::Embedder), a [`VectorStore`],
//! and an [`Llm`](rune_chain_core::Llm) into a single [`Chain`](rune_chain_core::Chain)
//! call: embed the question → retrieve the most similar documents → answer from context.
//!
//! # Features
//!
//! - [`Document`] — text with optional metadata, the storage unit of the pipeline
//! - [`VectorStore`] trait — implement once for any backend (Qdrant, Pinecone, pgvector, …)
//! - [`InMemoryVectorStore`] — in-process store with cosine similarity, useful for
//!   development and small document sets
//! - [`VectorStoreBackend`] — runs the chain on any [`rune_vectorstore::VectorStore`],
//!   e.g. its in-memory flat or HNSW index, or an external database adapter
//! - [`RetrievalQaChain`] — full RAG pipeline wired into the [`Chain`](rune_chain_core::Chain) trait,
//!   on a vector store or on any [`Retriever`]
//!
//! ## Retrievers
//!
//! Everything below implements [`Retriever`] (`query, top_k → ranked
//! ScoredDocument`s; `top_k = 0` is always an empty result) and composes:
//!
//! - [`Bm25Retriever`] / [`Bm25Index`] — Okapi BM25 keyword search
//!   ([`Bm25Params`] `k1`/`b`) with a Unicode-aware [`SimpleTokenizer`]
//! - [`EmbeddingRetriever`], [`InMemoryVectorStore`] — vector search
//! - [`HybridRetriever`] — fuse several retrievers with
//!   [`reciprocal_rank_fusion`] or [`weighted_score_fusion`] ([`Normalization`])
//! - [`MmrRetriever`] / [`maximal_marginal_relevance`] — diversify results
//! - [`MultiQueryRetriever`] — an [`Llm`](rune_chain_core::Llm) writes query
//!   variants, results are fused by RRF
//! - [`RerankingRetriever`] + [`Reranker`] — second-stage reranking with
//!   [`ApiReranker`] (Cohere, Jina, Voyage) or the local [`TokenOverlapReranker`]
//! - [`ContextualCompressionRetriever`] + [`DocumentCompressor`] — post-retrieval
//!   hook; [`CompressorPipeline`] offers dedupe, score threshold and truncation
//! - [`RetrieverExt`] — `.with_min_score(..)`, `.deduplicated()`
//!
//! ## Hybrid search example
//!
//! ```rust
//! use std::sync::Arc;
//! use rune_chain_retrieval::{
//!     Bm25Retriever, Document, FusionStrategy, HybridRetriever, Normalization,
//!     RerankingRetriever, Retriever, TokenOverlapReranker,
//! };
//!
//! # tokio_test::block_on(async {
//! let docs = vec![
//!     Document::new("Rust guarantees memory safety without a garbage collector."),
//!     Document::new("Python is dynamically typed."),
//! ];
//! let keyword = Arc::new(Bm25Retriever::from_documents(docs.clone()));
//! # let vector = Arc::new(Bm25Retriever::from_documents(docs)); // stand-in for a vector retriever
//! let hybrid = HybridRetriever::new()
//!     .with_retriever(keyword, 0.4)?
//!     .with_retriever(vector, 0.6)?
//!     .with_strategy(FusionStrategy::WeightedScore { normalization: Normalization::MinMax })?;
//! let retriever = RerankingRetriever::new(Arc::new(hybrid), Arc::new(TokenOverlapReranker::new()));
//! let hits = retriever.retrieve("memory safety", 1).await?;
//! assert!(hits[0].document.content.starts_with("Rust"));
//! # Ok::<(), rune_chain_retrieval::RetrievalError>(())
//! # }).unwrap();
//! ```
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rune_chain_core::{Chain, prompt_args};
//! use rune_chain_embed::{Embedder, OpenAiEmbedder};
//! use rune_chain_retrieval::{InMemoryVectorStore, RetrievalQaChain};
//!
//! # struct FakeLlm;
//! # use async_trait::async_trait;
//! # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
//! # #[async_trait] impl Llm for FakeLlm {
//! #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
//! #         Ok(GenerateResult::from_text("Paris"))
//! #     }
//! # }
//! # tokio_test::block_on(async {
//! let embedder: Arc<dyn Embedder> = Arc::new(OpenAiEmbedder::from_env().unwrap());
//! let store = Arc::new(InMemoryVectorStore::new(Arc::clone(&embedder)));
//!
//! // Load documents into the store (embed once, query many times)
//! store.add_texts(&[
//!     "The capital of France is Paris.",
//!     "The capital of Germany is Berlin.",
//!     "The capital of Japan is Tokyo.",
//! ]).await.unwrap();
//!
//! let chain = RetrievalQaChain::new(FakeLlm, Arc::clone(&embedder), store);
//! let answer = chain
//!     .invoke(prompt_args! { "input" => "What is the capital of France?" })
//!     .await
//!     .unwrap();
//! println!("{answer}"); // "Paris"
//! # });
//! ```
//!
//! # Custom `VectorStore`
//!
//! Implement [`VectorStore`] to use a production-grade vector database:
//!
//! ```rust
//! use async_trait::async_trait;
//! use rune_chain_retrieval::{Document, StoreError, VectorStore};
//!
//! struct MyVectorDb;
//!
//! #[async_trait]
//! impl VectorStore for MyVectorDb {
//!     async fn add(&self, docs: &[(Document, Vec<f32>)]) -> Result<(), StoreError> {
//!         // insert into your DB…
//!         Ok(())
//!     }
//!     async fn search(&self, emb: &[f32], top_k: usize) -> Result<Vec<Document>, StoreError> {
//!         // nearest-neighbour query…
//!         Ok(vec![])
//!     }
//! }
//! ```

mod backend;
mod bm25;
mod chain;
mod compression;
mod document;
mod error;
mod fusion;
mod mmr;
mod multi_query;
mod rerank;
mod retriever;
mod scored;
mod store;

pub use backend::VectorStoreBackend;
pub use bm25::{Bm25Index, Bm25Params, Bm25Retriever, SimpleTokenizer, Tokenizer};
pub use chain::RetrievalQaChain;
pub use compression::{
    CompressionStep, CompressorPipeline, ContextualCompressionRetriever, DocumentCompressor,
    RerankCompressor,
};
pub use document::{Document, StoreError};
pub use error::RetrievalError;
pub use fusion::{
    DEFAULT_RRF_K, FusionStrategy, HybridRetriever, Normalization, reciprocal_rank_fusion,
    weighted_score_fusion,
};
pub use mmr::{MmrRetriever, maximal_marginal_relevance};
pub use multi_query::{MultiQueryRetriever, parse_query_variants};
pub use rerank::{
    ApiReranker, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_TIMEOUT, RerankError, RerankProvider,
    Reranker, RerankingRetriever, TokenOverlapReranker, build_request_body, parse_response,
};
pub use retriever::{
    Deduplicated, EmbeddingRetriever, Retriever, RetrieverExt, ScoreThreshold, rank_scored,
};
pub use scored::{ScoredDocument, dedupe_by_content, filter_min_score, sort_by_score};
pub use store::{InMemoryVectorStore, VectorStore};
