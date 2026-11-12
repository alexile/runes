//! Recall@k of the HNSW index against exact search on a seeded toy set.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use rune_vectorstore::{FlatIndex, HnswIndex, HnswParams, Metric, Query, Record, VectorIndex};

/// Deterministic splitmix64 → uniform floats in [-1, 1).
struct Rng(u64);

impl Rng {
    fn next_f32(&mut self) -> f32 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        #[allow(clippy::cast_precision_loss, reason = "24 random bits fit f32 exactly")]
        let unit = (z >> 40) as f32 / (1u64 << 24) as f32;
        unit.mul_add(2.0, -1.0)
    }

    fn vector(&mut self, dim: usize) -> Vec<f32> {
        (0..dim).map(|_| self.next_f32()).collect()
    }
}

/// `n` points around 20 cluster centres in `dim` dimensions.
fn clustered(rng: &mut Rng, n: usize, dim: usize) -> Vec<Vec<f32>> {
    let centres: Vec<Vec<f32>> = (0..20).map(|_| rng.vector(dim)).collect();
    (0..n)
        .map(|i| {
            centres[i % centres.len()]
                .iter()
                .map(|c| c + 0.25 * rng.next_f32())
                .collect()
        })
        .collect()
}

fn recall_at_k(metric: Metric, params: HnswParams, k: usize) -> f64 {
    let mut rng = Rng(7);
    let (n, dim, queries) = (2000, 16, 50);
    let data = clustered(&mut rng, n, dim);
    let records: Vec<Record> = data
        .iter()
        .enumerate()
        .map(|(i, v)| Record::new(i.to_string(), v.clone()))
        .collect();
    let mut flat = FlatIndex::new(metric);
    let mut hnsw = HnswIndex::new(metric, params);
    flat.upsert(records.clone()).unwrap();
    hnsw.upsert(records).unwrap();

    let mut found = 0usize;
    for q in clustered(&mut rng, queries, dim) {
        let q = Query::new(q, k);
        let truth: Vec<String> = flat
            .query(&q)
            .unwrap()
            .into_iter()
            .map(|h| h.record.id)
            .collect();
        let approx = hnsw.query(&q).unwrap();
        assert_eq!(approx.len(), k);
        found += approx
            .iter()
            .filter(|h| truth.contains(&h.record.id))
            .count();
    }
    #[allow(clippy::cast_precision_loss, reason = "small counts")]
    let recall = found as f64 / (queries * k) as f64;
    recall
}

// The toy set is deliberately hard: points within a cluster are nearly
// equidistant, so the true top-10 is full of near-ties.

#[test]
fn hnsw_recall_at_10_cosine() {
    let r = recall_at_k(Metric::Cosine, HnswParams::default(), 10);
    assert!(r >= 0.9, "recall@10 = {r}");
    let r = recall_at_k(
        Metric::Cosine,
        HnswParams::default().with_ef_search(256),
        10,
    );
    assert!(r >= 0.99, "recall@10 = {r}");
}

#[test]
fn hnsw_recall_at_10_euclidean() {
    let r = recall_at_k(Metric::Euclidean, HnswParams::default(), 10);
    assert!(r >= 0.9, "recall@10 = {r}");
    let r = recall_at_k(
        Metric::Euclidean,
        HnswParams::default().with_ef_search(256),
        10,
    );
    assert!(r >= 0.99, "recall@10 = {r}");
}

#[test]
fn hnsw_recall_at_1_dot_product() {
    let r = recall_at_k(Metric::DotProduct, HnswParams::default(), 1);
    assert!(r >= 0.9, "recall@1 = {r}");
}

#[test]
fn recall_improves_with_ef_search() {
    let low = recall_at_k(
        Metric::Cosine,
        HnswParams::default().with_m(4).with_ef_search(10),
        10,
    );
    let high = recall_at_k(
        Metric::Cosine,
        HnswParams::default().with_m(4).with_ef_search(200),
        10,
    );
    assert!(high >= low, "{high} < {low}");
    assert!(high >= 0.9, "recall@10 = {high}");
}

#[test]
fn hnsw_recall_survives_churn() {
    let mut rng = Rng(11);
    let data = clustered(&mut rng, 1500, 16);
    let mut flat = FlatIndex::new(Metric::Cosine);
    let mut hnsw = HnswIndex::new(Metric::Cosine, HnswParams::default());
    let records: Vec<Record> = data
        .iter()
        .enumerate()
        .map(|(i, v)| Record::new(i.to_string(), v.clone()))
        .collect();
    flat.upsert(records.clone()).unwrap();
    hnsw.upsert(records).unwrap();
    // Delete a third, re-upsert another third with new vectors.
    let ids: Vec<String> = (0..500).map(|i| (i * 3).to_string()).collect();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    assert_eq!(flat.delete(&ids), 500);
    assert_eq!(hnsw.delete(&ids), 500);
    let moved: Vec<Record> = (0..500)
        .map(|i| Record::new((i * 3 + 1).to_string(), rng.vector(16)))
        .collect();
    flat.upsert(moved.clone()).unwrap();
    hnsw.upsert(moved).unwrap();
    assert_eq!(flat.len(), hnsw.len());

    let mut found = 0;
    for q in clustered(&mut rng, 50, 16) {
        let q = Query::new(q, 10);
        let truth: Vec<String> = flat
            .query(&q)
            .unwrap()
            .into_iter()
            .map(|h| h.record.id)
            .collect();
        found += hnsw
            .query(&q)
            .unwrap()
            .iter()
            .filter(|h| truth.contains(&h.record.id))
            .count();
    }
    assert!(found >= 450, "recall@10 = {found}/500");
}
