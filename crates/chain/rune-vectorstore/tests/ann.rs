//! HNSW against the exact index on seeded random data: plain and filtered
//! recall, plus the selectivity paths of filtered search.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use rune_vectorstore::{
    Filter, FlatIndex, HnswIndex, HnswParams, Metric, Query, Record, VectorIndex,
};

/// Deterministic splitmix64 → uniform floats in [-1, 1).
struct Rng(u64);

impl Rng {
    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_f32(&mut self) -> f32 {
        #[allow(clippy::cast_precision_loss, reason = "24 random bits fit f32 exactly")]
        let unit = (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32;
        unit.mul_add(2.0, -1.0)
    }

    fn vector(&mut self, dim: usize) -> Vec<f32> {
        (0..dim).map(|_| self.next_f32()).collect()
    }
}

const N: usize = 3000;
const DIM: usize = 24;
const QUERIES: usize = 100;
const K: usize = 10;

/// Records with a `bucket` in 0..100 and a `group` in 0..3.
fn dataset(seed: u64) -> (Vec<Record>, Vec<Vec<f32>>) {
    let mut rng = Rng(seed);
    let records = (0..N)
        .map(|i| {
            Record::new(i.to_string(), rng.vector(DIM))
                .with_meta("bucket", rng.next_u64() % 100)
                .with_meta("group", ["a", "b", "c"][i % 3])
        })
        .collect();
    let queries = (0..QUERIES).map(|_| rng.vector(DIM)).collect();
    (records, queries)
}

fn build(metric: Metric, params: HnswParams, records: &[Record]) -> (FlatIndex, HnswIndex) {
    let mut flat = FlatIndex::new(metric);
    let mut hnsw = HnswIndex::new(metric, params);
    flat.upsert(records.to_vec()).unwrap();
    hnsw.upsert(records.to_vec()).unwrap();
    (flat, hnsw)
}

/// Mean recall@K of `hnsw` against `flat` over `queries` with `filter`.
fn recall(flat: &FlatIndex, hnsw: &HnswIndex, queries: &[Vec<f32>], filter: &Filter) -> f64 {
    let (mut found, mut wanted) = (0usize, 0usize);
    for q in queries {
        let q = Query::new(q.clone(), K).with_filter(filter.clone());
        let truth: Vec<String> = flat
            .query(&q)
            .unwrap()
            .into_iter()
            .map(|h| h.record.id)
            .collect();
        let approx = hnsw.query(&q).unwrap();
        assert_eq!(approx.len(), truth.len());
        assert!(approx.iter().all(|h| filter.matches(&h.record)));
        assert!(approx.windows(2).all(|w| w[0].score >= w[1].score));
        wanted += truth.len();
        found += approx
            .iter()
            .filter(|h| truth.contains(&h.record.id))
            .count();
    }
    #[allow(clippy::cast_precision_loss, reason = "small counts")]
    let r = found as f64 / wanted as f64;
    r
}

#[test]
fn default_params_reach_95_percent_recall() {
    let (records, queries) = dataset(1);
    for metric in [Metric::Cosine, Metric::Euclidean, Metric::DotProduct] {
        let (flat, hnsw) = build(metric, HnswParams::default(), &records);
        let r = recall(&flat, &hnsw, &queries, &Filter::default());
        eprintln!("{metric:?}: recall@10 = {r}");
        assert!(r >= 0.95, "{metric:?}: recall@10 = {r}");
    }
}

#[test]
fn filtered_recall_across_selectivities() {
    let (records, queries) = dataset(2);
    let (flat, hnsw) = build(Metric::Cosine, HnswParams::default(), &records);
    // ~80 %: above the exact cutoff, so the filtered graph walk runs.
    let wide = Filter::lt("bucket", 80);
    // ~33 % and ~2 %: few enough matches to be scanned exactly.
    let group = Filter::eq("group", "a");
    let rare = Filter::between("bucket", 10, 11);
    for (name, f, min) in [
        ("wide", &wide, 0.95),
        ("group", &group, 1.0),
        ("rare", &rare, 1.0),
    ] {
        let r = recall(&flat, &hnsw, &queries, f);
        eprintln!("{name}: filtered recall@10 = {r}");
        assert!(r >= min, "{name}: filtered recall@10 = {r}");
    }
}

#[test]
fn filtered_graph_walk_keeps_recall_when_forced() {
    let (records, queries) = dataset(3);
    // A small ef lowers the exact cutoff (ef * 2m = 512) below the ~1000
    // matches of the group filter, so this exercises the filtered walk.
    let params = HnswParams::default().with_ef_search(16);
    let (flat, hnsw) = build(Metric::Euclidean, params, &records);
    let r = recall(&flat, &hnsw, &queries, &Filter::eq("group", "b"));
    eprintln!("forced walk: filtered recall@10 = {r}");
    assert!(r >= 0.9, "filtered recall@10 = {r}");
    let r = recall(
        &flat,
        &hnsw,
        &queries,
        &Filter::eq("group", "b").or(Filter::eq("group", "c")),
    );
    assert!(r >= 0.9, "filtered recall@10 = {r}");
}

#[test]
fn per_query_ef_search_raises_recall() {
    let (records, queries) = dataset(4);
    let (flat, hnsw) = build(
        Metric::Cosine,
        HnswParams::default().with_m(4).with_ef_search(10),
        &records,
    );
    let mut low = 0;
    let mut high = 0;
    for q in &queries {
        let base = Query::new(q.clone(), K);
        let truth: Vec<String> = flat
            .query(&base)
            .unwrap()
            .into_iter()
            .map(|h| h.record.id)
            .collect();
        let count = |q: &Query| {
            hnsw.query(q)
                .unwrap()
                .iter()
                .filter(|h| truth.contains(&h.record.id))
                .count()
        };
        low += count(&base);
        high += count(&base.clone().with_ef_search(400));
    }
    assert!(high >= low, "{high} < {low}");
    assert!(high >= QUERIES * K * 95 / 100, "{high}");
}

#[test]
fn min_score_never_returns_hits_below_threshold() {
    let (records, queries) = dataset(5);
    let (flat, hnsw) = build(Metric::Cosine, HnswParams::default(), &records);
    for q in queries.iter().take(20) {
        let q = Query::new(q.clone(), K).with_min_score(0.3);
        let exact = flat.query(&q).unwrap();
        let approx = hnsw.query(&q).unwrap();
        assert!(approx.iter().all(|h| h.score >= 0.3));
        assert!(approx.len() <= exact.len());
    }
}
