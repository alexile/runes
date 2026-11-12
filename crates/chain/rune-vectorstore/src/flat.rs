//! Exact brute-force index.

use std::collections::HashMap;

use crate::index::Schema;
use crate::record::sort_hits;
use crate::{Hit, IndexKind, Metric, Query, Record, StoreError, VectorIndex};

/// Exact nearest-neighbour index that scores every record on each query.
///
/// Query cost is `O(n · d)`. That is fast enough for tens of thousands of
/// records and gives perfect recall, so it is the default backend and the
/// reference the approximate [`HnswIndex`](crate::HnswIndex) is tested
/// against. Metadata filters are applied before scoring, so a filtered
/// query only scores the matching records.
///
/// # Example
///
/// ```
/// use rune_vectorstore::{FlatIndex, Metric, Query, Record, VectorIndex};
///
/// let mut index = FlatIndex::new(Metric::Cosine);
/// index.upsert(vec![
///     Record::new("x", vec![1.0, 0.0]),
///     Record::new("y", vec![0.0, 1.0]),
/// ])?;
/// let hits = index.query(&Query::new(vec![0.9, 0.1], 1))?;
/// assert_eq!(hits[0].record.id, "x");
/// # Ok::<(), rune_vectorstore::StoreError>(())
/// ```
#[derive(Debug, Clone)]
pub struct FlatIndex {
    schema: Schema,
    entries: Vec<(Record, f32)>,
    positions: HashMap<String, usize>,
}

impl FlatIndex {
    /// Create an empty index; the dimension is fixed by the first insert.
    #[must_use]
    pub fn new(metric: Metric) -> Self {
        Self {
            schema: Schema {
                metric,
                dimension: None,
            },
            entries: Vec::new(),
            positions: HashMap::new(),
        }
    }

    /// Create an empty index that only accepts `dimension`-sized vectors.
    #[must_use]
    pub fn with_dimension(metric: Metric, dimension: usize) -> Self {
        let mut index = Self::new(metric);
        index.schema.dimension = Some(dimension);
        index
    }

    fn remove(&mut self, id: &str) -> bool {
        let Some(pos) = self.positions.remove(id) else {
            return false;
        };
        self.entries.swap_remove(pos);
        if let Some((moved, _)) = self.entries.get(pos) {
            self.positions.insert(moved.id.clone(), pos);
        }
        true
    }
}

impl VectorIndex for FlatIndex {
    fn metric(&self) -> Metric {
        self.schema.metric
    }

    fn dimension(&self) -> Option<usize> {
        self.schema.dimension
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn upsert(&mut self, records: Vec<Record>) -> Result<(), StoreError> {
        let norms = self.schema.check_batch(&records)?;
        for (record, norm) in records.into_iter().zip(norms) {
            if let Some(&pos) = self.positions.get(&record.id) {
                if let Some(slot) = self.entries.get_mut(pos) {
                    *slot = (record, norm);
                }
            } else {
                self.positions.insert(record.id.clone(), self.entries.len());
                self.entries.push((record, norm));
            }
        }
        Ok(())
    }

    fn delete(&mut self, ids: &[&str]) -> usize {
        ids.iter().filter(|id| self.remove(id)).count()
    }

    fn get(&self, id: &str) -> Option<&Record> {
        self.positions
            .get(id)
            .and_then(|&p| self.entries.get(p))
            .map(|(r, _)| r)
    }

    fn query(&self, query: &Query) -> Result<Vec<Hit>, StoreError> {
        let qn = self.schema.check_query(query)?;
        if query.top_k == 0 {
            return Ok(Vec::new());
        }
        let metric = self.schema.metric;
        let filtered = !query.filter.is_empty();
        let mut scored: Vec<(f32, &Record)> = self
            .entries
            .iter()
            .filter(|(r, _)| !filtered || query.filter.matches(r))
            .filter_map(|(r, n)| {
                let s = metric.score_with_norms(&query.vector, qn, &r.vector, *n);
                query.passes_threshold(s).then_some((s, r))
            })
            .collect();
        let by_score = |a: &(f32, &Record), b: &(f32, &Record)| {
            b.0.total_cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id))
        };
        if scored.len() > query.top_k {
            scored.select_nth_unstable_by(query.top_k - 1, by_score);
            scored.truncate(query.top_k);
        }
        let mut hits: Vec<Hit> = scored.into_iter().map(|(s, r)| query.hit(s, r)).collect();
        sort_hits(&mut hits);
        Ok(hits)
    }

    fn records(&self) -> Box<dyn Iterator<Item = &Record> + '_> {
        Box::new(self.entries.iter().map(|(r, _)| r))
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.positions.clear();
    }

    fn kind(&self) -> Option<IndexKind> {
        Some(IndexKind::Flat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Filter;

    fn sample() -> FlatIndex {
        let mut idx = FlatIndex::new(Metric::Cosine);
        idx.upsert(vec![
            Record::new("a", vec![1.0, 0.0]).with_meta("k", "1"),
            Record::new("b", vec![0.7, 0.7]).with_meta("k", "2"),
            Record::new("c", vec![0.0, 1.0]).with_meta("k", "1"),
        ])
        .unwrap();
        idx
    }

    fn ids(hits: &[Hit]) -> Vec<&str> {
        hits.iter().map(|h| h.record.id.as_str()).collect()
    }

    #[test]
    fn ranks_by_score() {
        let hits = sample().query(&Query::new(vec![1.0, 0.1], 3)).unwrap();
        assert_eq!(ids(&hits), ["a", "b", "c"]);
        assert!(hits[0].score >= hits[1].score && hits[1].score >= hits[2].score);
    }

    #[test]
    fn top_k_zero_and_larger_than_len() {
        let idx = sample();
        assert_eq!(idx.query(&Query::new(vec![1.0, 0.0], 0)).unwrap(), []);
        assert_eq!(idx.query(&Query::new(vec![1.0, 0.0], 10)).unwrap().len(), 3);
    }

    #[test]
    fn filter_and_min_score() {
        let idx = sample();
        let q = Query::new(vec![0.7, 0.7], 3).with_filter(Filter::eq("k", "1"));
        assert_eq!(ids(&idx.query(&q).unwrap()), ["a", "c"]);
        let q = Query::new(vec![0.7, 0.7], 3).with_filter(Filter::gt("k", "1"));
        assert_eq!(ids(&idx.query(&q).unwrap()), ["b"]);
        let q = Query::new(vec![1.0, 0.0], 3).with_min_score(0.5);
        assert_eq!(ids(&idx.query(&q).unwrap()), ["a", "b"]);
    }

    #[test]
    fn upsert_replaces_and_delete_removes() {
        let mut idx = sample();
        idx.upsert(vec![Record::new("a", vec![0.0, 1.0]).with_content("moved")])
            .unwrap();
        assert_eq!(idx.len(), 3);
        assert_eq!(idx.get("a").unwrap().content, "moved");
        assert_eq!(idx.delete(&["a", "zzz", "a"]), 1);
        assert_eq!(idx.len(), 2);
        assert!(idx.get("a").is_none());
        assert_eq!(idx.get("c").unwrap().id, "c");
        assert_eq!(idx.get("b").unwrap().id, "b");
        assert_eq!(idx.delete_where(&Filter::eq("k", "2")).unwrap(), 1);
        assert_eq!(idx.records().count(), 1);
        idx.clear();
        assert!(idx.is_empty());
        assert_eq!(idx.dimension(), Some(2));
    }

    #[test]
    fn batches_are_atomic() {
        let mut idx = sample();
        let err = idx
            .upsert(vec![
                Record::new("d", vec![1.0, 1.0]),
                Record::new("e", vec![1.0, 1.0, 1.0]),
            ])
            .unwrap_err();
        assert_eq!(
            err,
            StoreError::DimensionMismatch {
                expected: 2,
                actual: 3
            }
        );
        assert_eq!(idx.len(), 3);
        assert!(matches!(
            idx.upsert(vec![
                Record::new("d", vec![1.0, 0.0]),
                Record::new("d", vec![0.0, 1.0])
            ]),
            Err(StoreError::DuplicateId(_))
        ));
        assert_eq!(
            idx.upsert(vec![Record::new("", vec![1.0, 0.0])]),
            Err(StoreError::EmptyId)
        );
        assert_eq!(idx.len(), 3);
    }

    #[test]
    fn hits_without_vectors() {
        let hits = sample()
            .query(&Query::new(vec![1.0, 0.0], 1).with_vectors(false))
            .unwrap();
        assert_eq!(hits[0].record.vector, Vec::<f32>::new());
        assert_eq!(hits[0].record.metadata["k"], "1");
    }

    #[test]
    fn query_validation() {
        let idx = sample();
        assert!(matches!(
            idx.query(&Query::new(vec![1.0], 1)),
            Err(StoreError::DimensionMismatch { .. })
        ));
        assert!(matches!(
            idx.query(&Query::new(vec![0.0, 0.0], 1)),
            Err(StoreError::InvalidVector(_))
        ));
        assert_eq!(
            idx.query(&Query::new(vec![1.0, 0.0], 1).with_min_score(f32::NAN)),
            Err(StoreError::InvalidQuery("min_score is NaN"))
        );
        assert!(matches!(
            idx.query(&Query::new(vec![1.0, 0.0], 1).with_filter(Filter::gt("k", true))),
            Err(StoreError::InvalidFilter(_))
        ));
        assert!(matches!(
            idx.query(&Query::new(vec![f32::NAN, 0.0], 1)),
            Err(StoreError::InvalidVector(_))
        ));
        let empty = FlatIndex::with_dimension(Metric::DotProduct, 3);
        assert_eq!(
            empty.query(&Query::new(vec![1.0, 2.0, 3.0], 1)).unwrap(),
            []
        );
        assert!(empty.query(&Query::new(vec![1.0], 1)).is_err());
    }
}
