//! The synchronous, sans-I/O index trait and the shared validation logic.

use std::collections::HashSet;

use crate::{Filter, Hit, IndexKind, Metric, Query, Record, StoreError};

/// A synchronous in-memory vector index.
///
/// This is the sans-I/O core: no locks, no runtime, no I/O. [`FlatIndex`]
/// (exact) and [`HnswIndex`] (approximate) implement it, and
/// [`InMemoryVectorStore`] wraps any implementation behind the async
/// [`VectorStore`] trait.
///
/// [`FlatIndex`]: crate::FlatIndex
/// [`HnswIndex`]: crate::HnswIndex
/// [`InMemoryVectorStore`]: crate::InMemoryVectorStore
/// [`VectorStore`]: crate::VectorStore
pub trait VectorIndex: Send + Sync {
    /// The metric this index scores with.
    fn metric(&self) -> Metric;

    /// The vector dimension, once fixed by options or the first insert.
    fn dimension(&self) -> Option<usize>;

    /// Number of live records.
    fn len(&self) -> usize;

    /// `true` if the index holds no live records.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert `records`, replacing any existing record with the same id.
    ///
    /// The batch is atomic: every record is validated first, and on error
    /// nothing is changed.
    fn upsert(&mut self, records: Vec<Record>) -> Result<(), StoreError>;

    /// Remove the records with these ids. Returns how many existed.
    fn delete(&mut self, ids: &[&str]) -> usize;

    /// Remove every record whose metadata matches `filter`. Returns how many
    /// were removed.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidFilter`] if the filter is malformed.
    fn delete_where(&mut self, filter: &Filter) -> Result<usize, StoreError> {
        filter.validate()?;
        let ids: Vec<String> = self
            .records()
            .filter(|r| filter.matches(r))
            .map(|r| r.id.clone())
            .collect();
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        Ok(self.delete(&ids))
    }

    /// Look up a record by id.
    fn get(&self, id: &str) -> Option<&Record>;

    /// Every live record, in no particular order.
    fn records(&self) -> Box<dyn Iterator<Item = &Record> + '_>;

    /// Return up to `query.top_k` hits, best first.
    ///
    /// # Errors
    ///
    /// [`StoreError::DimensionMismatch`] or [`StoreError::InvalidVector`] for
    /// a bad query vector, [`StoreError::InvalidQuery`] for a NaN
    /// `min_score`, [`StoreError::InvalidFilter`] for a malformed filter.
    fn query(&self, query: &Query) -> Result<Vec<Hit>, StoreError>;

    /// Remove every record. The dimension stays fixed.
    fn clear(&mut self);

    /// Which built-in index this is, so snapshots can rebuild it. Custom
    /// indexes return `None` and are restored as [`IndexKind::Flat`].
    fn kind(&self) -> Option<IndexKind> {
        None
    }
}

/// Dimension and metric checks shared by every index.
#[derive(Debug, Clone, Copy)]
pub struct Schema {
    pub metric: Metric,
    pub dimension: Option<usize>,
}

impl Schema {
    /// Validate a batch and return each record's norm. Fixes the dimension on
    /// success if it was still open.
    pub fn check_batch(&mut self, records: &[Record]) -> Result<Vec<f32>, StoreError> {
        let mut dim = self.dimension;
        let mut seen = HashSet::with_capacity(records.len());
        let mut norms = Vec::with_capacity(records.len());
        for r in records {
            if r.id.is_empty() {
                return Err(StoreError::EmptyId);
            }
            if !seen.insert(r.id.as_str()) {
                return Err(StoreError::DuplicateId(r.id.clone()));
            }
            let expected = *dim.get_or_insert(r.vector.len());
            if r.vector.len() != expected {
                return Err(StoreError::DimensionMismatch {
                    expected,
                    actual: r.vector.len(),
                });
            }
            norms.push(self.metric.validate(&r.vector)?);
        }
        self.dimension = dim;
        Ok(norms)
    }

    /// Validate a query and return the norm of its vector.
    pub fn check_query(&self, query: &Query) -> Result<f32, StoreError> {
        query.validate()?;
        let v = &query.vector;
        if let Some(expected) = self.dimension
            && v.len() != expected
        {
            return Err(StoreError::DimensionMismatch {
                expected,
                actual: v.len(),
            });
        }
        self.metric.validate(v)
    }
}
