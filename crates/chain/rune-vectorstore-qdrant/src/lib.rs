//! Qdrant backend for [`rune-vectorstore`](rune_vectorstore): a
//! [`VectorStore`](rune_vectorstore::VectorStore) on a Qdrant collection,
//! spoken over Qdrant's REST API with `reqwest` (no gRPC stack).
//!
//! - [`QdrantStore`]: upsert in bounded batches, filtered search with
//!   score thresholds, batch queries, MMR, get, delete by id or by filter,
//!   exact counts. Collections are created on first use with the configured
//!   metric, size and on-disk options, and checked when they already exist.
//! - [`QdrantConfig`]: URL, collection, optional API key (never shown by
//!   `Debug`, never sent over plain HTTP to a remote host), timeouts, retries
//!   and a response-size cap.
//! - [`qdrant_filter`]: the translation of a
//!   [`Filter`](rune_vectorstore::Filter) into a Qdrant filter. Anything
//!   Qdrant cannot express is an error, never dropped.
//! - [`PointId`]: the deterministic mapping from record ids to point ids
//!   (integers and UUIDs pass through, anything else becomes a `UUIDv5`).
//!
//! Because it implements `VectorStore`, the store plugs into everything that
//! takes one: `EmbeddingIndex` and `dynamic_context` in `rune-chain`, and
//! `VectorStoreExt::add_documents` for `#[derive(Embed)]` documents.
//!
//! # Example
//!
//! ```no_run
//! use rune_vectorstore::{Filter, Metric, Query, Record, VectorStore};
//! use rune_vectorstore_qdrant::{QdrantConfig, QdrantStore};
//!
//! # async fn run() -> Result<(), rune_vectorstore::StoreError> {
//! let store = QdrantStore::new(
//!     QdrantConfig::from_env("articles")
//!         .metric(Metric::Cosine)
//!         .dimension(3),
//! )?;
//! store.upsert(vec![
//!     Record::new("rust", vec![0.9, 0.1, 0.0]).with_content("Rust").with_meta("kind", "lang"),
//!     Record::new("paris", vec![0.0, 0.2, 0.9]).with_content("Paris").with_meta("kind", "city"),
//! ]).await?;
//!
//! let q = Query::new(vec![1.0, 0.0, 0.0], 5)
//!     .with_filter(Filter::eq("kind", "city"))
//!     .with_min_score(0.0);
//! for hit in store.query(&q).await? {
//!     println!("{} {:.3}", hit.record.content, hit.score);
//! }
//! store.delete_where(&Filter::eq("kind", "city")).await?;
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod filter;
mod http;
mod id;
mod store;

pub use config::{
    DEFAULT_BATCH_SIZE, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_BATCH_BYTES,
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT, QdrantConfig,
};
pub use filter::{QdrantFilter, qdrant_filter};
pub use id::{ID_NAMESPACE, PointId};
pub use store::QdrantStore;
