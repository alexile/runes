//! Vector stores for RAG pipelines: an async store trait, exact and HNSW
//! in-memory indexes, JSON metadata filters, MMR and checksummed snapshots.
//!
//! - [`VectorStore`] — async upsert / query / delete / get, plus batch
//!   queries and MMR; the seam that retrieval pipelines program against and
//!   external databases implement.
//! - [`InMemoryVectorStore`] — the default backend: `Send + Sync`,
//!   read-parallel, runtime-agnostic, with atomic [snapshots](InMemoryVectorStore::save).
//! - [`VectorIndex`] — the synchronous, sans-I/O core, implemented by
//!   [`FlatIndex`] (exact brute force, the default and the reference) and
//!   [`HnswIndex`] (approximate, [HNSW]).
//! - [`Metric`] — cosine, dot product or Euclidean (L2); scores are always
//!   "higher is more similar".
//! - [`Filter`] — equality, `in`, range and existence tests on JSON metadata,
//!   combined with and / or / not. HNSW applies filters during the search
//!   and never loses matches (see [`HnswIndex`]).
//! - [`mmr`] — maximal marginal relevance on stored vectors.
//!
//! Bad input is an error, never a panic: wrong dimensions, empty vectors,
//! NaN or infinite components, zero vectors under cosine, NaN thresholds
//! and malformed filters all return a [`StoreError`].
//!
//! [HNSW]: https://arxiv.org/abs/1603.09320
//!
//! # Example
//!
//! ```
//! use rune_vectorstore::{
//!     Filter, HnswParams, IndexKind, InMemoryVectorStore, Options, Query, Record, VectorStore,
//! };
//!
//! # tokio_test::block_on(async {
//! let store = InMemoryVectorStore::new(
//!     Options::default().with_index(IndexKind::Hnsw(HnswParams::default())),
//! );
//! store.upsert(vec![
//!     Record::new("1", vec![0.9, 0.1, 0.0]).with_content("Rust").with_meta("kind", "lang").with_meta("year", 2015),
//!     Record::new("2", vec![0.8, 0.3, 0.1]).with_content("Go").with_meta("kind", "lang").with_meta("year", 2012),
//!     Record::new("3", vec![0.0, 0.2, 0.9]).with_content("Paris").with_meta("kind", "city"),
//! ]).await?;
//!
//! let hits = store.query(&Query::new(vec![1.0, 0.0, 0.0], 2)).await?;
//! assert_eq!(hits[0].record.content, "Rust");
//!
//! let cities = Query::new(vec![1.0, 0.0, 0.0], 2).with_filter(Filter::eq("kind", "city"));
//! assert_eq!(store.query(&cities).await?[0].record.content, "Paris");
//!
//! let old = Query::new(vec![1.0, 0.0, 0.0], 2).with_filter(Filter::lt("year", 2014));
//! assert_eq!(store.query(&old).await?[0].record.content, "Go");
//!
//! store.delete(&["1"]).await?;
//! assert_eq!(store.len().await?, 2);
//! # Ok::<(), rune_vectorstore::StoreError>(())
//! # }).unwrap();
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod filter;
mod flat;
mod hnsw;
mod index;
mod metric;
mod mmr;
mod record;
mod snapshot;
mod store;

pub use error::StoreError;
pub use filter::{Filter, MAX_FILTER_DEPTH};
pub use flat::FlatIndex;
pub use hnsw::{HnswIndex, HnswParams};
pub use index::VectorIndex;
pub use metric::{Metric, cosine, dot, euclidean, norm};
pub use mmr::mmr;
pub use record::{Hit, Query, Record};
pub use serde_json::Value;
pub use snapshot::LoadLimits;
pub use store::{InMemoryVectorStore, IndexKind, Options, VectorStore};
