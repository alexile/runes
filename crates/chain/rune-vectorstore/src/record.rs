//! Records, queries, filters and hits.

use std::collections::BTreeMap;

/// One stored item: a unique id, its embedding, and the payload returned on a hit.
///
/// # Example
///
/// ```
/// use rune_vectorstore::Record;
///
/// let r = Record::new("doc-1", vec![0.1, 0.2, 0.3])
///     .with_content("Paris is the capital of France.")
///     .with_meta("source", "geo.md");
/// assert_eq!(r.metadata["source"], "geo.md");
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
    /// Arbitrary string metadata, usable in [`Filter`]s.
    pub metadata: BTreeMap<String, String>,
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

    /// Add one metadata entry.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Metadata filter: a record matches when every listed key has exactly the
/// listed value. The empty filter matches everything.
///
/// # Example
///
/// ```
/// use rune_vectorstore::{Filter, Record};
///
/// let f = Filter::default().must_equal("lang", "en");
/// assert!(f.matches(&Record::new("a", vec![1.0]).with_meta("lang", "en")));
/// assert!(!f.matches(&Record::new("b", vec![1.0]).with_meta("lang", "de")));
/// assert!(!f.matches(&Record::new("c", vec![1.0])));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Filter {
    /// Required `key == value` pairs.
    pub equals: BTreeMap<String, String>,
}

impl Filter {
    /// Require `metadata[key] == value`.
    #[must_use]
    pub fn must_equal(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.equals.insert(key.into(), value.into());
        self
    }

    /// `true` if the filter has no conditions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.equals.is_empty()
    }

    /// `true` if `record` satisfies every condition.
    #[must_use]
    pub fn matches(&self, record: &Record) -> bool {
        self.equals
            .iter()
            .all(|(k, v)| record.metadata.get(k) == Some(v))
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
///     .with_filter(Filter::default().must_equal("lang", "en"))
///     .with_min_score(0.5);
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
    /// Drop hits whose score is below this value.
    pub min_score: Option<f32>,
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

    /// `true` if a hit with `score` on `record` passes the filter and threshold.
    pub(crate) fn accepts(&self, score: f32, record: &Record) -> bool {
        self.min_score.is_none_or(|m| score >= m) && self.filter.matches(record)
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
