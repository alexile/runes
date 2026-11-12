//! The async store trait and its in-memory implementation.

use std::path::Path;
use std::sync::RwLock;

use async_trait::async_trait;

use crate::snapshot::{self, LoadLimits};
use crate::{
    Filter, FlatIndex, Hit, HnswIndex, HnswParams, Metric, Query, Record, StoreError, VectorIndex,
    mmr,
};

/// An async vector store: the seam between RAG pipelines and a backend.
///
/// [`InMemoryVectorStore`] is the default backend. External databases
/// (Qdrant, pgvector, …) implement this trait in their own adapter crates;
/// their transport failures map to [`StoreError::Backend`].
///
/// Scores follow the store's [`Metric`]: higher is always more similar.
///
/// # Implementing
///
/// ```
/// use async_trait::async_trait;
/// use rune_vectorstore::{Hit, Query, Record, StoreError, VectorStore};
///
/// struct Remote;
///
/// #[async_trait]
/// impl VectorStore for Remote {
///     async fn upsert(&self, _records: Vec<Record>) -> Result<(), StoreError> {
///         Err(StoreError::Backend("not connected".into()))
///     }
///     async fn query(&self, _query: &Query) -> Result<Vec<Hit>, StoreError> {
///         Ok(Vec::new())
///     }
///     async fn delete(&self, _ids: &[&str]) -> Result<usize, StoreError> {
///         Ok(0)
///     }
///     async fn get(&self, _id: &str) -> Result<Option<Record>, StoreError> {
///         Ok(None)
///     }
///     async fn len(&self) -> Result<usize, StoreError> {
///         Ok(0)
///     }
/// }
/// ```
#[async_trait]
pub trait VectorStore: Send + Sync {
    /// Insert records, replacing any existing record with the same id.
    async fn upsert(&self, records: Vec<Record>) -> Result<(), StoreError>;

    /// Return up to `query.top_k` hits, best first.
    async fn query(&self, query: &Query) -> Result<Vec<Hit>, StoreError>;

    /// Remove records by id. Returns how many existed.
    async fn delete(&self, ids: &[&str]) -> Result<usize, StoreError>;

    /// Look up a record by id.
    async fn get(&self, id: &str) -> Result<Option<Record>, StoreError>;

    /// Number of stored records.
    async fn len(&self) -> Result<usize, StoreError>;

    /// `true` if the store holds no records.
    async fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len().await? == 0)
    }

    /// Run several queries; results come back in the same order.
    ///
    /// The default runs them one after another. Backends with a native batch
    /// API (or, like [`InMemoryVectorStore`], a lock to take once) override it.
    async fn query_batch(&self, queries: &[Query]) -> Result<Vec<Vec<Hit>>, StoreError> {
        let mut out = Vec::with_capacity(queries.len());
        for q in queries {
            out.push(self.query(q).await?);
        }
        Ok(out)
    }

    /// Diversified search: fetch `fetch_k` candidates for `query` (at least
    /// `query.top_k`), then keep `query.top_k` of them chosen by [`mmr`]
    /// with the given `lambda`, under `metric`.
    ///
    /// Hits keep their original similarity scores and come back in MMR pick
    /// order. Vectors are always fetched, whatever
    /// [`Query::include_vectors`] says.
    ///
    /// # Errors
    ///
    /// Anything [`VectorStore::query`] returns, plus
    /// [`StoreError::InvalidQuery`] for a `lambda` outside `[0, 1]`.
    ///
    /// # Example
    ///
    /// ```
    /// use rune_vectorstore::{InMemoryVectorStore, Metric, Query, Record, VectorStore};
    ///
    /// # tokio_test::block_on(async {
    /// let store = InMemoryVectorStore::default();
    /// store.upsert(vec![
    ///     Record::new("a", vec![1.0, 0.0]),
    ///     Record::new("a2", vec![0.99, 0.02]),
    ///     Record::new("b", vec![0.7, 0.7]),
    /// ]).await?;
    /// let hits = store.query_mmr(&Query::new(vec![1.0, 0.0], 2), 10, 0.3, Metric::Cosine).await?;
    /// let ids: Vec<_> = hits.iter().map(|h| h.record.id.as_str()).collect();
    /// assert_eq!(ids, ["a", "b"]);
    /// # Ok::<(), rune_vectorstore::StoreError>(())
    /// # }).unwrap();
    /// ```
    async fn query_mmr(
        &self,
        query: &Query,
        fetch_k: usize,
        lambda: f32,
        metric: Metric,
    ) -> Result<Vec<Hit>, StoreError> {
        if !(0.0..=1.0).contains(&lambda) {
            return Err(StoreError::InvalidQuery("MMR lambda must be within [0, 1]"));
        }
        let mut wide = query.clone().with_vectors(true);
        wide.top_k = fetch_k.max(query.top_k);
        let candidates = self.query(&wide).await?;
        let order = mmr(metric, &query.vector, &candidates, query.top_k, lambda)?;
        let mut slots: Vec<Option<Hit>> = candidates.into_iter().map(Some).collect();
        Ok(order
            .into_iter()
            .filter_map(|i| slots.get_mut(i).and_then(Option::take))
            .map(|mut h| {
                if !query.include_vectors {
                    h.record.vector = Vec::new();
                }
                h
            })
            .collect())
    }
}

/// Which in-memory index [`InMemoryVectorStore`] uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexKind {
    /// Exact brute-force search ([`FlatIndex`]).
    #[default]
    Flat,
    /// Approximate graph search ([`HnswIndex`]).
    Hnsw(HnswParams),
}

/// Configuration for [`InMemoryVectorStore`].
///
/// # Example
///
/// ```
/// use rune_vectorstore::{HnswParams, IndexKind, Metric, Options};
///
/// let opts = Options::default()
///     .with_metric(Metric::DotProduct)
///     .with_dimension(384)
///     .with_index(IndexKind::Hnsw(HnswParams::default()));
/// assert_eq!(opts.dimension, Some(384));
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Similarity metric. Default [`Metric::Cosine`].
    pub metric: Metric,
    /// Required vector dimension; `None` fixes it on the first insert.
    pub dimension: Option<usize>,
    /// Index structure. Default [`IndexKind::Flat`].
    pub index: IndexKind,
}

impl Options {
    /// Set the metric.
    #[must_use]
    pub const fn with_metric(mut self, metric: Metric) -> Self {
        self.metric = metric;
        self
    }

    /// Require vectors of this dimension.
    #[must_use]
    pub const fn with_dimension(mut self, dimension: usize) -> Self {
        self.dimension = Some(dimension);
        self
    }

    /// Choose the index structure.
    #[must_use]
    pub const fn with_index(mut self, index: IndexKind) -> Self {
        self.index = index;
        self
    }

    /// Build the configured index.
    #[must_use]
    pub fn build_index(&self) -> Box<dyn VectorIndex> {
        match (self.index, self.dimension) {
            (IndexKind::Flat, None) => Box::new(FlatIndex::new(self.metric)),
            (IndexKind::Flat, Some(d)) => Box::new(FlatIndex::with_dimension(self.metric, d)),
            (IndexKind::Hnsw(p), None) => Box::new(HnswIndex::new(self.metric, p)),
            (IndexKind::Hnsw(p), Some(d)) => Box::new(HnswIndex::with_dimension(self.metric, p, d)),
        }
    }
}

/// Thread-safe in-memory [`VectorStore`] over any [`VectorIndex`].
///
/// The store is `Send + Sync`. Queries, gets and snapshots share a read
/// lock, so they run in parallel; upserts and deletes take the write lock.
/// The lock is a synchronous `std` one held only inside each call, never
/// across an `.await`, so the store works under any async runtime. Large
/// HNSW upserts hold the write lock while they build, so split very large
/// loads into batches if query latency matters meanwhile.
///
/// # Persistence
///
/// [`save`](Self::save) writes a versioned, checksummed snapshot atomically
/// (temp file, fsync, rename); [`load`](Self::load) reads it back under
/// [`LoadLimits`]. Both do blocking file I/O: in async code, call them
/// from `spawn_blocking` or your runtime's equivalent.
///
/// # Example
///
/// ```
/// use rune_vectorstore::{InMemoryVectorStore, Options, Query, Record, VectorStore};
///
/// # tokio_test::block_on(async {
/// let store = InMemoryVectorStore::new(Options::default());
/// store.upsert(vec![
///     Record::new("fr", vec![1.0, 0.0]).with_content("Paris"),
///     Record::new("de", vec![0.0, 1.0]).with_content("Berlin"),
/// ]).await?;
///
/// let hits = store.query(&Query::new(vec![0.9, 0.2], 1)).await?;
/// assert_eq!(hits[0].record.content, "Paris");
///
/// assert_eq!(store.delete(&["fr"]).await?, 1);
/// assert_eq!(store.len().await?, 1);
/// # Ok::<(), rune_vectorstore::StoreError>(())
/// # }).unwrap();
/// ```
pub struct InMemoryVectorStore {
    index: RwLock<Box<dyn VectorIndex>>,
}

impl std::fmt::Debug for InMemoryVectorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryVectorStore")
            .finish_non_exhaustive()
    }
}

impl Default for InMemoryVectorStore {
    fn default() -> Self {
        Self::new(Options::default())
    }
}

impl InMemoryVectorStore {
    /// Create an empty store from options.
    #[must_use]
    pub fn new(options: Options) -> Self {
        Self {
            index: RwLock::new(options.build_index()),
        }
    }

    /// Wrap an existing index, e.g. one built synchronously or a custom
    /// [`VectorIndex`] implementation.
    #[must_use]
    pub fn from_index(index: impl VectorIndex + 'static) -> Self {
        Self {
            index: RwLock::new(Box::new(index)),
        }
    }

    /// The store's metric.
    pub fn metric(&self) -> Result<Metric, StoreError> {
        self.read(|i| i.metric())
    }

    /// Remove every record.
    pub fn clear(&self) -> Result<(), StoreError> {
        self.write(|i| i.clear())
    }

    /// Remove every record matching `filter`; returns how many were removed.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidFilter`] for a malformed filter.
    pub fn delete_where(&self, filter: &Filter) -> Result<usize, StoreError> {
        self.write(|i| i.delete_where(filter))?
    }

    /// Encode the store as a snapshot (see [`save`](Self::save)).
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidSnapshot`] if a field is too large for the
    /// format (over 4 GiB).
    pub fn to_bytes(&self) -> Result<Vec<u8>, StoreError> {
        self.read(|i| snapshot::encode(i))?
    }

    /// Decode a snapshot produced by [`to_bytes`](Self::to_bytes) or
    /// [`save`](Self::save).
    ///
    /// The metric, dimension and index kind come from the snapshot. HNSW
    /// graphs are rebuilt from the records with the saved parameters.
    ///
    /// # Errors
    ///
    /// [`StoreError::LimitExceeded`] when the input breaks `limits`, and
    /// [`StoreError::InvalidSnapshot`] when it is truncated, fails its
    /// checksum, has an unknown version, or holds invalid records.
    ///
    /// # Example
    ///
    /// ```
    /// use rune_vectorstore::{InMemoryVectorStore, LoadLimits, Record, VectorStore};
    ///
    /// # tokio_test::block_on(async {
    /// let store = InMemoryVectorStore::default();
    /// store.upsert(vec![Record::new("a", vec![1.0, 0.0]).with_meta("n", 1)]).await?;
    /// let copy = InMemoryVectorStore::from_bytes(&store.to_bytes()?, &LoadLimits::default())?;
    /// assert_eq!(copy.get("a").await?, store.get("a").await?);
    /// # Ok::<(), rune_vectorstore::StoreError>(())
    /// # }).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8], limits: &LoadLimits) -> Result<Self, StoreError> {
        Ok(Self {
            index: RwLock::new(snapshot::decode(bytes, limits)?),
        })
    }

    /// Write a snapshot to `path` atomically.
    ///
    /// The snapshot is encoded under the read lock, which is released before
    /// any file I/O. The bytes go to a temporary file next to `path`, are
    /// flushed to disk, and the file is renamed over `path`, so a crash
    /// leaves either the old snapshot or the new one, never a torn file.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on file-system failures; see also
    /// [`to_bytes`](Self::to_bytes).
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), StoreError> {
        let bytes = self.to_bytes()?;
        snapshot::write_atomic(path.as_ref(), &bytes)
    }

    /// Load a snapshot written by [`save`](Self::save).
    ///
    /// The file size is checked against [`LoadLimits::max_bytes`] before
    /// reading, and never more than that many bytes are read.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] on file-system failures; see also
    /// [`from_bytes`](Self::from_bytes).
    pub fn load(path: impl AsRef<Path>, limits: &LoadLimits) -> Result<Self, StoreError> {
        let bytes = snapshot::read_limited(path.as_ref(), limits)?;
        Self::from_bytes(&bytes, limits)
    }

    fn read<T>(&self, f: impl FnOnce(&dyn VectorIndex) -> T) -> Result<T, StoreError> {
        let guard = self.index.read().map_err(|_| StoreError::Poisoned)?;
        Ok(f(guard.as_ref()))
    }

    fn write<T>(&self, f: impl FnOnce(&mut dyn VectorIndex) -> T) -> Result<T, StoreError> {
        let mut guard = self.index.write().map_err(|_| StoreError::Poisoned)?;
        Ok(f(guard.as_mut()))
    }
}

#[async_trait]
impl VectorStore for InMemoryVectorStore {
    async fn upsert(&self, records: Vec<Record>) -> Result<(), StoreError> {
        self.write(|i| i.upsert(records))?
    }

    async fn query(&self, query: &Query) -> Result<Vec<Hit>, StoreError> {
        self.read(|i| i.query(query))?
    }

    async fn delete(&self, ids: &[&str]) -> Result<usize, StoreError> {
        self.write(|i| i.delete(ids))
    }

    async fn get(&self, id: &str) -> Result<Option<Record>, StoreError> {
        self.read(|i| i.get(id).cloned())
    }

    async fn len(&self) -> Result<usize, StoreError> {
        self.read(|i| i.len())
    }

    async fn query_batch(&self, queries: &[Query]) -> Result<Vec<Vec<Hit>>, StoreError> {
        self.read(|i| queries.iter().map(|q| i.query(q)).collect())?
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn both_backends_agree_on_small_sets() {
        let records: Vec<Record> = (0..50u8)
            .map(|i| {
                Record::new(
                    format!("r{i}"),
                    vec![f32::from(i).cos(), f32::from(i).sin()],
                )
            })
            .collect();
        for kind in [IndexKind::Flat, IndexKind::Hnsw(HnswParams::default())] {
            let store = InMemoryVectorStore::new(Options::default().with_index(kind));
            store.upsert(records.clone()).await.unwrap();
            let hits = store.query(&Query::new(vec![1.0, 0.0], 3)).await.unwrap();
            assert_eq!(hits[0].record.id, "r0", "{kind:?}");
            assert_eq!(store.get("r7").await.unwrap().unwrap().id, "r7");
            assert!(store.get("nope").await.unwrap().is_none());
            assert!(!store.is_empty().await.unwrap());
            store.clear().unwrap();
            assert!(store.is_empty().await.unwrap());
        }
    }

    #[tokio::test]
    async fn dimension_option_is_enforced() {
        let store = InMemoryVectorStore::new(Options::default().with_dimension(3));
        let err = store
            .upsert(vec![Record::new("a", vec![1.0, 2.0])])
            .await
            .unwrap_err();
        assert_eq!(
            err,
            StoreError::DimensionMismatch {
                expected: 3,
                actual: 2
            }
        );
    }

    #[tokio::test]
    async fn usable_as_trait_object_across_tasks() {
        let store: Arc<dyn VectorStore> = Arc::new(InMemoryVectorStore::default());
        let mut tasks = Vec::new();
        for i in 0..8u8 {
            let s = Arc::clone(&store);
            tasks.push(tokio::spawn(async move {
                s.upsert(vec![Record::new(i.to_string(), vec![1.0, f32::from(i)])])
                    .await
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        assert_eq!(store.len().await.unwrap(), 8);
    }

    #[test]
    fn debug_and_metric() {
        let store = InMemoryVectorStore::from_index(FlatIndex::new(Metric::Euclidean));
        assert_eq!(store.metric().unwrap(), Metric::Euclidean);
        assert!(format!("{store:?}").contains("InMemoryVectorStore"));
    }
}
