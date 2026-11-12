//! Vector-store trait with in-memory flat and HNSW indexes for RAG pipelines.
//!
//! - [`VectorStore`] — async upsert / query / delete / get, the seam that
//!   retrieval pipelines program against and external databases implement.
//! - [`InMemoryVectorStore`] — the default backend, thread-safe and
//!   runtime-agnostic, over either index below.
//! - [`VectorIndex`] — the synchronous, sans-I/O core, implemented by
//!   [`FlatIndex`] (exact) and [`HnswIndex`] (approximate, [HNSW]).
//! - [`Metric`] — cosine, dot product or Euclidean; scores are always
//!   "higher is more similar".
//!
//! Records carry an id, a vector, content text and string metadata;
//! queries can filter on metadata equality and a minimum score.
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
//!     Record::new("1", vec![0.9, 0.1, 0.0]).with_content("Rust").with_meta("kind", "lang"),
//!     Record::new("2", vec![0.8, 0.3, 0.1]).with_content("Go").with_meta("kind", "lang"),
//!     Record::new("3", vec![0.0, 0.2, 0.9]).with_content("Paris").with_meta("kind", "city"),
//! ]).await?;
//!
//! let hits = store.query(&Query::new(vec![1.0, 0.0, 0.0], 2)).await?;
//! assert_eq!(hits[0].record.content, "Rust");
//!
//! let cities = Query::new(vec![1.0, 0.0, 0.0], 2)
//!     .with_filter(Filter::default().must_equal("kind", "city"));
//! assert_eq!(store.query(&cities).await?[0].record.content, "Paris");
//!
//! store.delete(&["1"]).await?;
//! assert_eq!(store.len().await?, 2);
//! # Ok::<(), rune_vectorstore::StoreError>(())
//! # }).unwrap();
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod flat;
mod hnsw;
mod index;
mod metric;
mod record;
mod store;

pub use error::StoreError;
pub use flat::FlatIndex;
pub use hnsw::{HnswIndex, HnswParams};
pub use index::VectorIndex;
pub use metric::{Metric, cosine, dot, euclidean, norm};
pub use record::{Filter, Hit, Query, Record};
pub use store::{InMemoryVectorStore, IndexKind, Options, VectorStore};
