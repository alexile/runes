//! Provider-agnostic text embeddings for `rune-chain`: the [`Embedder`]
//! trait, hardened HTTP providers, batching, caching and vector helpers.
//!
//! `rune-chain-embed` defines the [`Embedder`] trait used across the
//! `rune-chain-*` ecosystem — `rune-chain-retrieval` uses it to embed queries
//! and documents for RAG pipelines, `rune-chain-splitter` for semantic
//! splitting.
//!
//! # Features
//!
//! - [`Embedder`] — implement once, use in any pipeline; distinguishes
//!   [`embed_query`](Embedder::embed_query) from
//!   [`embed_documents`](Embedder::embed_documents) for asymmetric models
//! - Providers: [`OpenAiEmbedder`] (`OpenAI` and any OpenAI-compatible
//!   server via `base_url`, with `dimensions` and base64
//!   [`EncodingFormat`]), [`CohereEmbedder`], [`VoyageEmbedder`],
//!   [`JinaEmbedder`]
//! - Hardened transport: HTTPS enforced (plain HTTP only to loopback or
//!   explicitly allowed hosts), per-request timeout, response-size cap,
//!   truncated error bodies, API keys redacted from `Debug` and errors,
//!   retries on 429/5xx honouring `Retry-After`
//! - Batching: large inputs split into requests of at most `max_batch_size`,
//!   `max_concurrency` in flight, results in input order; also for any
//!   embedder via [`BatchingEmbedder`]
//! - Caching: [`CacheBackedEmbedder`] over a pluggable [`EmbeddingStore`]
//!   (bounded in-memory [`LruStore`] included), embedding only cache misses
//! - Checks: one vector per input, each index once, consistent dimensions —
//!   [`EmbedError::DimensionMismatch`], never a panic
//! - Documents: [`Embed`] says which texts of a value to embed
//!   (`#[derive(Embed)]` with the `derive` feature); with the
//!   `vectorstore` feature, [`to_records`] and
//!   [`VectorStoreExt::add_documents`] embed a batch of them straight into a
//!   `rune-vectorstore` store
//! - Helpers: [`cosine_similarity`], [`try_cosine_similarity`], [`dot`],
//!   [`l2_norm`], [`normalize`], [`check_dimensions`]
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use rune_chain_embed::{Embedder, OpenAiEmbedder};
//!
//! # tokio_test::block_on(async {
//! let embedder = OpenAiEmbedder::from_env().unwrap();
//! let query = embedder.embed_query("Rust is a systems programming language").await.unwrap();
//! let docs = embedder.embed_documents(&["Rust", "Python", "Go"]).await.unwrap();
//! assert_eq!(docs.len(), 3);
//! # });
//! ```
//!
//! # Caching
//!
//! ```rust,no_run
//! use rune_chain_embed::{CacheBackedEmbedder, Embedder, LruStore, OpenAiEmbedder};
//!
//! # tokio_test::block_on(async {
//! let embedder = CacheBackedEmbedder::new(OpenAiEmbedder::from_env().unwrap(), LruStore::new(50_000))
//!     .unwrap();
//! let vectors = embedder.embed_documents(&["cached after the first call"]).await.unwrap();
//! # });
//! ```
//!
//! # Custom Embedder
//!
//! ```rust
//! use rune_chain_embed::{EmbedError, Embedder};
//! use async_trait::async_trait;
//!
//! struct ConstantEmbedder;
//!
//! #[async_trait]
//! impl Embedder for ConstantEmbedder {
//!     async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
//!         Ok(texts.iter().map(|_| vec![0.0f32; 8]).collect())
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let v = ConstantEmbedder.embed("hello").await.unwrap();
//! assert_eq!(v.len(), 8);
//! # });
//! ```

// Lets `#[derive(Embed)]` refer to `::rune_chain_embed` from inside this
// crate and its doctests.
extern crate self as rune_chain_embed;

mod batch;
mod cache;
mod cohere;
mod document;
mod embedder;
mod http;
#[cfg(feature = "vectorstore")]
mod ingest;
mod jina;
mod openai;
mod similarity;
mod voyage;

pub use batch::BatchingEmbedder;
pub use cache::{CacheBackedEmbedder, EmbeddingStore, InputKind, LruStore, cache_key};
pub use cohere::{
    COHERE_BASE_URL, CohereEmbedder, CohereInputType, DEFAULT_COHERE_BATCH_SIZE,
    DEFAULT_COHERE_MODEL,
};
pub use document::{Embed, EmbedText};
pub use embedder::{EmbedError, Embedder};
pub use http::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_CONCURRENCY, DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT, MAX_ERROR_CHARS, MAX_RETRY_AFTER,
};
#[cfg(feature = "vectorstore")]
pub use ingest::{IngestError, VectorStoreExt, to_records};
pub use jina::{DEFAULT_JINA_BATCH_SIZE, DEFAULT_JINA_MODEL, JINA_BASE_URL, JinaEmbedder};
pub use openai::{
    DEFAULT_BASE_URL, DEFAULT_OPENAI_BATCH_SIZE, DEFAULT_OPENAI_MODEL, EncodingFormat,
    OpenAiEmbedder,
};
/// Derive [`Embed`]: mark text fields `#[embed]` and, optionally, an id
/// field `#[embed_id]`.
///
/// ```
/// use rune_chain_embed::Embed;
///
/// #[derive(Embed)]
/// struct Article {
///     #[embed_id]
///     slug: String,
///     #[embed]
///     title: String,
///     #[embed]
///     paragraphs: Vec<String>,
///     year: u16,
/// }
///
/// let a = Article {
///     slug: "rust-2024".into(),
///     title: "Rust 2024".into(),
///     paragraphs: vec!["Edition.".into(), "Async closures.".into()],
///     year: 2025,
/// };
/// assert_eq!(a.texts(), ["Rust 2024", "Edition.", "Async closures."]);
/// assert_eq!(a.embed_id().as_deref(), Some("rust-2024"));
/// ```
#[cfg(feature = "derive")]
pub use rune_chain_macros::Embed;
pub use similarity::{
    check_dimensions, cosine_similarity, dot, l2_norm, normalize, try_cosine_similarity,
};
pub use voyage::{
    DEFAULT_VOYAGE_BATCH_SIZE, DEFAULT_VOYAGE_MODEL, VOYAGE_BASE_URL, VoyageEmbedder,
};
