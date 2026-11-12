//! Records, queries and hits.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{Filter, StoreError};

/// One stored item: a unique id, its embedding, and the payload returned on a hit.
///
/// # Example
///
/// ```
/// use rune_vectorstore::Record;
///
/// let r = Record::new("doc-1", vec![0.1, 0.2, 0.3])
///     .with_content("Paris is the capital of France.")
///     .with_meta("source", "geo.md")
///     .with_meta("page", 3);
/// assert_eq!(r.metadata["source"], "geo.md");
/// assert_eq!(r.metadata["page"], 3);
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Record {
    /// Unique, non-empty id. Upserting an existing id replaces that record.
    pub id: String,
    /// The embedding vector.
    pub vector: Vec<f32>,
    /// Text the vector was computed from (or any payload text).
    pub content: String,
    /// Arbitrary JSON metadata, usable in [`Filter`]s.
    pub metadata: BTreeMap<String, Value>,
}

impl Record {
    /// Create a record with empty content and no metadata.
    #[must_use]
    pub fn new(id: impl Into<String>, vector: Vec<f32>) -> Self {
        Self {
            id: id.into(),
            vector,
            content: String::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Set the record's content.
    #[must_use]
    pub fn with_content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Add one metadata entry. Anything convertible to a JSON value works:
    /// strings, numbers, booleans, or a `serde_json::json!` literal.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// A nearest-neighbour query.
///
/// # Example
///
/// ```
/// use rune_vectorstore::{Filter, Query};
///
/// let q = Query::new(vec![0.1, 0.9], 5)
///     .with_filter(Filter::eq("lang", "en").and(Filter::gte("year", 2020)))
///     .with_min_score(0.5)
///     .with_ef_search(128);
/// assert_eq!(q.top_k, 5);
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Query {
    /// Query embedding.
    pub vector: Vec<f32>,
    /// Maximum number of hits to return. `0` returns nothing.
    pub top_k: usize,
    /// Metadata filter applied to candidates.
    pub filter: Filter,
    /// Drop hits whose score is below this value. NaN is rejected.
    pub min_score: Option<f32>,
    /// Per-query override of the HNSW search breadth (ignored by exact
    /// indexes). `None` uses the index default.
    pub ef_search: Option<usize>,
    /// Return each hit's vector. Default `true`; turn it off to skip copying
    /// vectors when only ids, content and metadata are needed. MMR needs them.
    pub include_vectors: bool,
}

impl Query {
    /// Query for the `top_k` records nearest to `vector`.
    #[must_use]
    pub fn new(vector: Vec<f32>, top_k: usize) -> Self {
        Self {
            vector,
            top_k,
            filter: Filter::default(),
            min_score: None,
            ef_search: None,
            include_vectors: true,
        }
    }

    /// Restrict results to records matching `filter`.
    #[must_use]
    pub fn with_filter(mut self, filter: Filter) -> Self {
        self.filter = filter;
        self
    }

    /// Drop hits scoring below `min_score`.
    #[must_use]
    pub const fn with_min_score(mut self, min_score: f32) -> Self {
        self.min_score = Some(min_score);
        self
    }

    /// Override the HNSW search breadth for this query.
    #[must_use]
    pub const fn with_ef_search(mut self, ef_search: usize) -> Self {
        self.ef_search = Some(ef_search);
        self
    }

    /// Choose whether hits carry their vectors (default `true`).
    #[must_use]
    pub const fn with_vectors(mut self, include: bool) -> Self {
        self.include_vectors = include;
        self
    }

    /// Check the parts of the query that do not depend on the store.
    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        if self.min_score.is_some_and(f32::is_nan) {
            return Err(StoreError::InvalidQuery("min_score is NaN"));
        }
        self.filter.validate()
    }

    /// `true` if `score` passes the minimum-score threshold.
    pub(crate) fn passes_threshold(&self, score: f32) -> bool {
        self.min_score.is_none_or(|m| score >= m)
    }

    /// Build the hit for `record`, honouring [`Query::include_vectors`].
    pub(crate) fn hit(&self, score: f32, record: &Record) -> Hit {
        let record = if self.include_vectors {
            record.clone()
        } else {
            Record {
                id: record.id.clone(),
                vector: Vec::new(),
                content: record.content.clone(),
                metadata: record.metadata.clone(),
            }
        };
        Hit::new(score, record)
    }
}

/// A query result: the matched record and its similarity score (higher is closer).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Hit {
    /// Similarity score under the store's [`Metric`](crate::Metric).
    pub score: f32,
    /// The matched record.
    pub record: Record,
}

impl Hit {
    /// Pair a record with its score.
    #[must_use]
    pub const fn new(score: f32, record: Record) -> Self {
        Self { score, record }
    }
}

/// Sort hits best-first, breaking ties by id so output is deterministic.
pub fn sort_hits(hits: &mut [Hit]) {
    hits.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.record.id.cmp(&b.record.id))
    });
}
