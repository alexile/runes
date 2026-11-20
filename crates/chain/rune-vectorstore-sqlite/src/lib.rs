//! An embedded, single-file vector store on SQLite for `rune-vectorstore`.
//!
//! [`SqliteVectorStore`] implements the async
//! [`VectorStore`](rune_vectorstore::VectorStore) trait with exact search:
//! vectors are stored as little-endian `f32` BLOBs and scored in Rust while
//! a streaming scan keeps the best `top_k` in a bounded heap. Scores,
//! ordering (ties by id) and [`Filter`](rune_vectorstore::Filter) semantics
//! are the same as the in-memory flat index, so the two are
//! interchangeable; the test suite checks that on random data.
//!
//! - **Durable and simple**: one file, WAL mode, atomic upsert batches,
//!   parallel readers. `open_in_memory` for tests.
//! - **Filters pushed down safely**: metadata filters compile to
//!   `json_each` / `json_type` conditions on bound JSON paths, so keys and
//!   values never touch the SQL text. Candidates are then re-checked
//!   exactly in Rust.
//! - **Validated input**: NaN or infinite components, empty vectors, zero
//!   vectors under cosine, dimension mismatches, empty or duplicate ids and
//!   malformed filters are errors, as in the in-memory store.
//! - **Honest about scale**: search is a linear scan. Fine up to a few
//!   hundred thousand vectors; past that use an approximate index.
//!
//! # Example
//!
//! ```
//! use rune_vectorstore::{Filter, Metric, Query, Record, VectorStore};
//! use rune_vectorstore_sqlite::{SqliteConfig, SqliteVectorStore};
//!
//! # tokio_test::block_on(async {
//! let dir = tempfile::tempdir().unwrap();
//! let store = SqliteVectorStore::open(
//!     dir.path().join("vectors.db"),
//!     SqliteConfig::new("docs").with_metric(Metric::Cosine),
//! )?;
//! store.upsert(vec![
//!     Record::new("1", vec![0.9, 0.1]).with_content("Rust").with_meta("year", 2015),
//!     Record::new("2", vec![0.8, 0.3]).with_content("Go").with_meta("year", 2012),
//! ]).await?;
//!
//! let old = Query::new(vec![1.0, 0.0], 1).with_filter(Filter::lt("year", 2014));
//! assert_eq!(store.query(&old).await?[0].record.content, "Go");
//! assert_eq!(store.len().await?, 2);
//! # Ok::<(), rune_vectorstore::StoreError>(())
//! # }).unwrap();
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod check;
mod filter;
mod store;

pub use store::{SqliteConfig, SqliteVectorStore, check_identifier};
