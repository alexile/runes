//! Approximate nearest-neighbour index: Hierarchical Navigable Small World graphs.
//!
//! Follows Malkov & Yashunin, "Efficient and robust approximate nearest
//! neighbor search using Hierarchical Navigable Small World graphs"
//! (<https://arxiv.org/abs/1603.09320>), with the neighbour-selection
//! heuristic (Algorithm 4, keeping pruned connections).

use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, HashMap, HashSet};

use crate::index::Schema;
use crate::record::sort_hits;
use crate::{Hit, Metric, Query, Record, StoreError, VectorIndex};

/// Highest layer a node may be assigned to.
const MAX_LEVEL: usize = 16;
/// Rebuild the graph once tombstones outnumber live nodes and reach this count.
const COMPACT_MIN_TOMBSTONES: usize = 64;

/// Tuning parameters for [`HnswIndex`].
///
/// # Example
///
/// ```
/// use rune_vectorstore::HnswParams;
///
/// let p = HnswParams::default().with_m(32).with_ef_search(128);
/// assert_eq!(p.m, 32);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HnswParams {
    /// Links per node on upper layers (layer 0 keeps `2 * m`). Default `16`.
    pub m: usize,
    /// Candidate list size while building. Default `200`.
    pub ef_construction: usize,
    /// Candidate list size while querying (at least `top_k` is used). Default `64`.
    pub ef_search: usize,
    /// Seed for level assignment, so builds are reproducible.
    pub seed: u64,
}

impl Default for HnswParams {
    fn default() -> Self {
        Self {
            m: 16,
            ef_construction: 200,
            ef_search: 64,
            seed: 0x5EED_CAFE_F00D_D00D,
        }
    }
}

impl HnswParams {
    /// Set `m` (clamped to at least 2).
    #[must_use]
    pub fn with_m(mut self, m: usize) -> Self {
        self.m = m.max(2);
        self
    }

    /// Set `ef_construction` (clamped to at least 1).
    #[must_use]
    pub fn with_ef_construction(mut self, ef: usize) -> Self {
        self.ef_construction = ef.max(1);
        self
    }

    /// Set `ef_search` (clamped to at least 1).
    #[must_use]
    pub fn with_ef_search(mut self, ef: usize) -> Self {
        self.ef_search = ef.max(1);
        self
    }

    /// Set the level-assignment seed.
    #[must_use]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }
}

#[derive(Debug, Clone)]
struct Node {
    record: Record,
    norm: f32,
    /// `links[layer]` = neighbour node indexes on that layer.
    links: Vec<Vec<usize>>,
    deleted: bool,
}

/// A scored node, ordered by score then index.
#[derive(Debug, Clone, Copy)]
struct Cand {
    score: f32,
    idx: usize,
}

impl PartialEq for Cand {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Cand {}
impl PartialOrd for Cand {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Cand {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .total_cmp(&other.score)
            .then_with(|| other.idx.cmp(&self.idx))
    }
}

/// Approximate nearest-neighbour index (HNSW).
///
/// Queries visit `O(log n)` nodes instead of all of them, at the price of
/// approximate results; raise [`HnswParams::ef_search`] for better recall.
/// Deletes and replacing upserts leave tombstones that still route searches
/// but never appear in results; the graph is rebuilt once tombstones
/// outnumber live records. If a filtered or thresholded query cannot fill
/// `top_k` from the graph walk, it falls back to an exact scan, so filters
/// never lose matches.
///
/// # Example
///
/// ```
/// use rune_vectorstore::{HnswIndex, HnswParams, Metric, Query, Record, VectorIndex};
///
/// let mut index = HnswIndex::new(Metric::Euclidean, HnswParams::default());
/// let records = (0..100u8)
///     .map(|i| Record::new(i.to_string(), vec![f32::from(i), 0.0]))
///     .collect();
/// index.upsert(records)?;
/// let hits = index.query(&Query::new(vec![41.8, 0.0], 2))?;
/// assert_eq!(hits[0].record.id, "42");
/// assert_eq!(hits[1].record.id, "41");
/// # Ok::<(), rune_vectorstore::StoreError>(())
/// ```
#[derive(Debug, Clone)]
pub struct HnswIndex {
    schema: Schema,
    params: HnswParams,
    nodes: Vec<Node>,
    ids: HashMap<String, usize>,
    entry: Option<usize>,
    rng: u64,
}

impl HnswIndex {
    /// Create an empty index; the dimension is fixed by the first insert.
    #[must_use]
    pub fn new(metric: Metric, params: HnswParams) -> Self {
        let params = HnswParams {
            m: params.m.max(2),
            ef_construction: params.ef_construction.max(1),
            ef_search: params.ef_search.max(1),
            seed: params.seed,
        };
        Self {
            schema: Schema {
                metric,
                dimension: None,
            },
            params,
            nodes: Vec::new(),
            ids: HashMap::new(),
            entry: None,
            rng: params.seed,
        }
    }

    /// Create an empty index that only accepts `dimension`-sized vectors.
    #[must_use]
    pub fn with_dimension(metric: Metric, params: HnswParams, dimension: usize) -> Self {
        let mut index = Self::new(metric, params);
        index.schema.dimension = Some(dimension);
        index
    }

    /// The parameters this index was built with.
    #[must_use]
    pub const fn params(&self) -> HnswParams {
        self.params
    }

    /// splitmix64.
    const fn next_u64(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Geometric level: `P(level >= l) = m^-l`, as in the paper's `mL = 1/ln(m)`.
    fn random_level(&mut self) -> usize {
        let threshold = u64::MAX / u64::try_from(self.params.m).unwrap_or(u64::MAX);
        let mut level = 0;
        while level < MAX_LEVEL && self.next_u64() < threshold {
            level += 1;
        }
        level
    }

    fn score_to(&self, q: &[f32], qn: f32, idx: usize) -> f32 {
        let n = &self.nodes[idx];
        self.schema
            .metric
            .score_with_norms(q, qn, &n.record.vector, n.norm)
    }

    fn node_score(&self, a: usize, b: usize) -> f32 {
        let na = &self.nodes[a];
        self.score_to(&na.record.vector, na.norm, b)
    }

    /// Greedy beam search on one layer; returns up to `ef` candidates, best first.
    fn search_layer(
        &self,
        q: &[f32],
        qn: f32,
        entry: &[Cand],
        ef: usize,
        layer: usize,
    ) -> Vec<Cand> {
        let mut visited: HashSet<usize> = entry.iter().map(|c| c.idx).collect();
        let mut candidates: BinaryHeap<Cand> = entry.iter().copied().collect();
        let mut results: BinaryHeap<Reverse<Cand>> = entry.iter().copied().map(Reverse).collect();
        while results.len() > ef {
            results.pop();
        }
        while let Some(c) = candidates.pop() {
            let worst = results.peek().map_or(f32::NEG_INFINITY, |r| r.0.score);
            if c.score < worst && results.len() >= ef {
                break;
            }
            let Some(links) = self.nodes[c.idx].links.get(layer) else {
                continue;
            };
            for &nb in links {
                if !visited.insert(nb) {
                    continue;
                }
                let worst = results.peek().map_or(f32::NEG_INFINITY, |r| r.0.score);
                let s = self.score_to(q, qn, nb);
                if results.len() < ef || s > worst {
                    let cand = Cand { score: s, idx: nb };
                    candidates.push(cand);
                    results.push(Reverse(cand));
                    if results.len() > ef {
                        results.pop();
                    }
                }
            }
        }
        let mut out: Vec<Cand> = results.into_iter().map(|r| r.0).collect();
        out.sort_unstable_by(|a, b| b.cmp(a));
        out
    }

    /// Neighbour-selection heuristic with pruned-connection back-fill.
    /// `found` must be sorted best first.
    fn select_neighbors(&self, found: &[Cand], m: usize) -> Vec<usize> {
        let mut selected: Vec<usize> = Vec::with_capacity(m);
        let mut pruned: Vec<usize> = Vec::new();
        for c in found {
            if selected.len() >= m {
                break;
            }
            if selected
                .iter()
                .all(|&s| self.node_score(c.idx, s) < c.score)
            {
                selected.push(c.idx);
            } else {
                pruned.push(c.idx);
            }
        }
        let room = m.saturating_sub(selected.len());
        selected.extend(pruned.into_iter().take(room));
        selected
    }

    /// Shrink `node`'s links on `layer` to `max` using the selection heuristic.
    ///
    /// Links to live nodes win over links to tombstones, so deleted nodes
    /// cannot crowd live ones out and leave them unreachable.
    fn prune_links(&mut self, node: usize, layer: usize, max: usize) {
        let (mut live, mut dead): (Vec<Cand>, Vec<Cand>) = self.nodes[node].links[layer]
            .iter()
            .map(|&nb| Cand {
                score: self.node_score(node, nb),
                idx: nb,
            })
            .partition(|c| !self.nodes[c.idx].deleted);
        live.sort_unstable_by(|a, b| b.cmp(a));
        dead.sort_unstable_by(|a, b| b.cmp(a));
        let mut kept = self.select_neighbors(&live, max);
        let room = max.saturating_sub(kept.len());
        kept.extend(dead.into_iter().take(room).map(|c| c.idx));
        self.nodes[node].links[layer] = kept;
    }

    /// Walk from the entry point down to `stop_layer + 1` with `ef = 1`.
    fn descend(&self, q: &[f32], qn: f32, entry: usize, stop_layer: usize) -> Vec<Cand> {
        let top = self.nodes[entry].links.len().saturating_sub(1);
        let mut eps = vec![Cand {
            score: self.score_to(q, qn, entry),
            idx: entry,
        }];
        for layer in (stop_layer + 1..=top).rev() {
            eps = self.search_layer(q, qn, &eps, 1, layer);
        }
        eps
    }

    fn insert(&mut self, record: Record, norm: f32) {
        let idx = self.nodes.len();
        let level = self.random_level();
        let q = record.vector.clone();
        self.ids.insert(record.id.clone(), idx);
        self.nodes.push(Node {
            record,
            norm,
            links: vec![Vec::new(); level + 1],
            deleted: false,
        });
        let Some(entry) = self.entry else {
            self.entry = Some(idx);
            return;
        };
        let top = self.nodes[entry].links.len() - 1;
        let mut eps = self.descend(&q, norm, entry, level);
        for layer in (0..=level.min(top)).rev() {
            let found = self.search_layer(&q, norm, &eps, self.params.ef_construction, layer);
            let live: Vec<Cand> = found
                .iter()
                .copied()
                .filter(|c| !self.nodes[c.idx].deleted)
                .collect();
            let pool = if live.is_empty() { &found } else { &live };
            let neighbors = self.select_neighbors(pool, self.params.m);
            let max = if layer == 0 {
                self.params.m * 2
            } else {
                self.params.m
            };
            for &nb in &neighbors {
                self.nodes[nb].links[layer].push(idx);
                if self.nodes[nb].links[layer].len() > max {
                    self.prune_links(nb, layer, max);
                }
            }
            self.nodes[idx].links[layer] = neighbors;
            eps = found;
        }
        if level > top {
            self.entry = Some(idx);
        }
    }

    /// Tombstone `id`; returns whether it was live.
    fn tombstone(&mut self, id: &str) -> bool {
        let Some(idx) = self.ids.remove(id) else {
            return false;
        };
        let node = &mut self.nodes[idx];
        node.deleted = true;
        node.record.content = String::new();
        node.record.metadata.clear();
        true
    }

    fn maybe_compact(&mut self) {
        let live = self.ids.len();
        let dead = self.nodes.len() - live;
        if live == 0 {
            self.reset();
        } else if dead >= COMPACT_MIN_TOMBSTONES && dead > live {
            self.rebuild();
        }
    }

    fn reset(&mut self) {
        self.nodes.clear();
        self.ids.clear();
        self.entry = None;
    }

    /// Re-insert every live record into a fresh graph.
    fn rebuild(&mut self) {
        let old = std::mem::take(&mut self.nodes);
        self.reset();
        for node in old.into_iter().filter(|n| !n.deleted) {
            self.insert(node.record, node.norm);
        }
    }

    fn exact_scan(&self, query: &Query, qn: f32) -> Vec<Hit> {
        let mut hits: Vec<Hit> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| !n.deleted)
            .filter_map(|(i, n)| {
                let s = self.score_to(&query.vector, qn, i);
                query
                    .accepts(s, &n.record)
                    .then(|| Hit::new(s, n.record.clone()))
            })
            .collect();
        sort_hits(&mut hits);
        hits.truncate(query.top_k);
        hits
    }
}

impl VectorIndex for HnswIndex {
    fn metric(&self) -> Metric {
        self.schema.metric
    }

    fn dimension(&self) -> Option<usize> {
        self.schema.dimension
    }

    fn len(&self) -> usize {
        self.ids.len()
    }

    fn upsert(&mut self, records: Vec<Record>) -> Result<(), StoreError> {
        let norms = self.schema.check_batch(&records)?;
        for (record, norm) in records.into_iter().zip(norms) {
            self.tombstone(&record.id);
            self.insert(record, norm);
        }
        self.maybe_compact();
        Ok(())
    }

    fn delete(&mut self, ids: &[&str]) -> usize {
        let removed = ids.iter().filter(|id| self.tombstone(id)).count();
        if removed > 0 {
            self.maybe_compact();
        }
        removed
    }

    fn get(&self, id: &str) -> Option<&Record> {
        self.ids.get(id).map(|&i| &self.nodes[i].record)
    }

    fn query(&self, query: &Query) -> Result<Vec<Hit>, StoreError> {
        let qn = self.schema.check_query(&query.vector)?;
        let (Some(entry), true) = (self.entry, query.top_k > 0) else {
            return Ok(Vec::new());
        };
        let eps = self.descend(&query.vector, qn, entry, 0);
        let ef = self.params.ef_search.max(query.top_k);
        let mut hits: Vec<Hit> = self
            .search_layer(&query.vector, qn, &eps, ef, 0)
            .into_iter()
            .filter_map(|c| {
                let n = &self.nodes[c.idx];
                (!n.deleted && query.accepts(c.score, &n.record))
                    .then(|| Hit::new(c.score, n.record.clone()))
            })
            .collect();
        if hits.len() < query.top_k.min(self.len()) {
            return Ok(self.exact_scan(query, qn));
        }
        sort_hits(&mut hits);
        hits.truncate(query.top_k);
        Ok(hits)
    }

    fn clear(&mut self) {
        self.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Filter, FlatIndex};

    fn grid(n: u16) -> Vec<Record> {
        (0..n)
            .map(|i| {
                Record::new(i.to_string(), vec![f32::from(i % 37), f32::from(i / 37)])
                    .with_meta("parity", (i % 2).to_string())
            })
            .collect()
    }

    #[test]
    fn levels_are_geometric_and_seeded() {
        let mut a = HnswIndex::new(Metric::Cosine, HnswParams::default());
        let mut b = HnswIndex::new(Metric::Cosine, HnswParams::default());
        let la: Vec<usize> = (0..2000).map(|_| a.random_level()).collect();
        let lb: Vec<usize> = (0..2000).map(|_| b.random_level()).collect();
        assert_eq!(la, lb);
        let zeros = la.iter().filter(|&&l| l == 0).count();
        // P(level 0) = 1 - 1/16 ≈ 0.94.
        assert!((1800..1950).contains(&zeros), "{zeros}");
    }

    #[test]
    fn exact_on_small_grid() {
        let mut h = HnswIndex::new(Metric::Euclidean, HnswParams::default());
        let mut f = FlatIndex::new(Metric::Euclidean);
        h.upsert(grid(500)).unwrap();
        f.upsert(grid(500)).unwrap();
        for q in [[3.2, 4.1], [30.0, 12.9], [-5.0, -5.0], [18.5, 6.5]] {
            let q = Query::new(q.to_vec(), 5);
            let hh: Vec<_> = h.query(&q).unwrap().into_iter().map(|x| x.score).collect();
            let ff: Vec<_> = f.query(&q).unwrap().into_iter().map(|x| x.score).collect();
            assert_eq!(hh, ff);
        }
    }

    #[test]
    fn filtered_query_falls_back_to_exact() {
        let mut h = HnswIndex::new(Metric::Euclidean, HnswParams::default().with_ef_search(1));
        h.upsert(grid(300)).unwrap();
        h.upsert(vec![
            Record::new("odd-one", vec![0.0, 0.0]).with_meta("rare", "yes"),
        ])
        .unwrap();
        let q =
            Query::new(vec![36.0, 7.0], 3).with_filter(Filter::default().must_equal("rare", "yes"));
        let hits = h.query(&q).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record.id, "odd-one");
    }

    #[test]
    fn deletes_upserts_and_compaction() {
        let mut h = HnswIndex::new(Metric::Euclidean, HnswParams::default());
        h.upsert(grid(400)).unwrap();
        let doomed: Vec<String> = (0..300u16).map(|i| i.to_string()).collect();
        let doomed: Vec<&str> = doomed.iter().map(String::as_str).collect();
        assert_eq!(h.delete(&doomed), 300);
        assert_eq!(h.len(), 100);
        // Compaction ran: no tombstones remain.
        assert_eq!(h.nodes.len(), 100);
        let hits = h.query(&Query::new(vec![0.0, 0.0], 400)).unwrap();
        assert_eq!(hits.len(), 100);
        assert!(
            hits.iter()
                .all(|x| x.record.id.parse::<u16>().unwrap() >= 300)
        );

        h.upsert(vec![
            Record::new("399", vec![100.0, 100.0]).with_content("moved"),
        ])
        .unwrap();
        assert_eq!(h.len(), 100);
        let top = h.query(&Query::new(vec![99.0, 99.0], 1)).unwrap();
        assert_eq!(top[0].record.content, "moved");
        assert_eq!(h.get("399").unwrap().content, "moved");

        let rest: Vec<String> = (300..400u16).map(|i| i.to_string()).collect();
        let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
        assert_eq!(h.delete(&rest), 100);
        assert!(h.is_empty());
        assert_eq!(h.query(&Query::new(vec![0.0, 0.0], 3)).unwrap(), []);
        assert_eq!(h.dimension(), Some(2));
    }

    #[test]
    fn params_are_clamped() {
        let h = HnswIndex::new(
            Metric::Cosine,
            HnswParams {
                m: 0,
                ef_construction: 0,
                ef_search: 0,
                seed: 1,
            },
        );
        assert_eq!(h.params().m, 2);
        assert_eq!(h.params().ef_search, 1);
    }
}
