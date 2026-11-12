//! Property tests: indexes agree with a brute-force model and never panic.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::collections::HashMap;

use proptest::prelude::*;
use rune_vectorstore::{
    Filter, FlatIndex, HnswIndex, HnswParams, Metric, Query, Record, VectorIndex,
};

const DIM: usize = 4;

fn vector() -> impl Strategy<Value = Vec<f32>> {
    prop::collection::vec(-10.0f32..10.0, DIM)
        .prop_filter("non-zero for cosine", |v| v.iter().any(|x| x.abs() > 1e-3))
}

fn metric() -> impl Strategy<Value = Metric> {
    prop_oneof![
        Just(Metric::Cosine),
        Just(Metric::DotProduct),
        Just(Metric::Euclidean)
    ]
}

#[derive(Debug, Clone)]
enum Op {
    Upsert(u8, Vec<f32>),
    Delete(u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u8..40, vector()).prop_map(|(i, v)| Op::Upsert(i, v)),
        1 => (0u8..40).prop_map(Op::Delete),
    ]
}

fn brute_force(model: &HashMap<String, Vec<f32>>, metric: Metric, q: &[f32], k: usize) -> Vec<f32> {
    let mut scores: Vec<f32> = model.values().map(|v| metric.score(q, v)).collect();
    scores.sort_by(|a, b| b.total_cmp(a));
    scores.truncate(k);
    scores
}

fn apply(index: &mut dyn VectorIndex, model: &mut HashMap<String, Vec<f32>>, ops: &[Op]) {
    for op in ops {
        match op {
            Op::Upsert(i, v) => {
                index
                    .upsert(vec![Record::new(i.to_string(), v.clone())])
                    .unwrap();
                model.insert(i.to_string(), v.clone());
            }
            Op::Delete(i) => {
                let id = i.to_string();
                let existed = usize::from(model.remove(&id).is_some());
                assert_eq!(index.delete(&[&id]), existed);
            }
        }
    }
}

proptest! {
    #[test]
    fn flat_matches_brute_force(
        metric in metric(),
        ops in prop::collection::vec(op(), 0..80),
        q in vector(),
        k in 0usize..12,
    ) {
        let mut index = FlatIndex::new(metric);
        let mut model = HashMap::new();
        apply(&mut index, &mut model, &ops);
        prop_assert_eq!(index.len(), model.len());
        for (id, v) in &model {
            prop_assert_eq!(&index.get(id).unwrap().vector, v);
        }
        if model.is_empty() {
            return Ok(());
        }
        let got: Vec<f32> = index.query(&Query::new(q.clone(), k)).unwrap()
            .into_iter().map(|h| h.score).collect();
        let want = brute_force(&model, metric, &q, k);
        prop_assert_eq!(got.len(), want.len());
        for (g, w) in got.iter().zip(&want) {
            prop_assert!((g - w).abs() <= 1e-3 * w.abs().max(1.0), "{} vs {}", g, w);
        }
    }

    #[test]
    fn hnsw_tracks_model_and_finds_stored_vectors(
        ops in prop::collection::vec(op(), 1..120),
        k in 1usize..8,
    ) {
        let mut index = HnswIndex::new(Metric::Euclidean, HnswParams::default().with_m(4));
        let mut model = HashMap::new();
        apply(&mut index, &mut model, &ops);
        prop_assert_eq!(index.len(), model.len());
        for (id, v) in &model {
            prop_assert_eq!(&index.get(id).unwrap().vector, v);
            let hits = index.query(&Query::new(v.clone(), k)).unwrap();
            prop_assert_eq!(hits.len(), k.min(model.len()));
            // An exact match scores 0 under negated L2 and must come first.
            prop_assert!(hits[0].score.abs() < 1e-4);
            prop_assert!(hits.iter().all(|h| model.contains_key(&h.record.id)));
            prop_assert!(hits.windows(2).all(|w| w[0].score >= w[1].score));
        }
    }

    #[test]
    fn arbitrary_vectors_never_panic(
        metric in metric(),
        stored in prop::collection::vec(prop::collection::vec(any::<f32>(), 0..6), 0..20),
        q in prop::collection::vec(any::<f32>(), 0..6),
        k in 0usize..5,
    ) {
        let mut flat = FlatIndex::new(metric);
        let mut hnsw = HnswIndex::new(metric, HnswParams::default());
        for (i, v) in stored.into_iter().enumerate() {
            let r = Record::new(i.to_string(), v);
            let a = flat.upsert(vec![r.clone()]);
            let b = hnsw.upsert(vec![r]);
            prop_assert_eq!(a.is_ok(), b.is_ok());
        }
        let q = Query::new(q, k);
        let a = flat.query(&q);
        let b = hnsw.query(&q);
        prop_assert_eq!(a.is_ok(), b.is_ok());
        if let (Ok(a), Ok(b)) = (a, b) {
            prop_assert_eq!(a.len(), b.len());
            prop_assert!(a.iter().chain(&b).all(|h| h.score.is_finite()));
        }
    }

    #[test]
    fn filtered_hnsw_returns_every_match_it_should(
        vectors in prop::collection::vec(vector(), 1..150),
        buckets in prop::collection::vec(0u8..10, 150),
        q in vector(),
        k in 1usize..10,
        cut in 0u8..11,
        ef in 1usize..40,
    ) {
        let records: Vec<Record> = vectors
            .iter()
            .enumerate()
            .map(|(i, v)| Record::new(i.to_string(), v.clone()).with_meta("b", buckets[i]))
            .collect();
        let mut flat = FlatIndex::new(Metric::Euclidean);
        let mut hnsw = HnswIndex::new(
            Metric::Euclidean,
            HnswParams::default().with_m(4).with_ef_search(ef),
        );
        flat.upsert(records.clone()).unwrap();
        hnsw.upsert(records).unwrap();
        let filter = Filter::lt("b", cut);
        let query = Query::new(q, k).with_filter(filter.clone());
        let exact = flat.query(&query).unwrap();
        let approx = hnsw.query(&query).unwrap();
        prop_assert_eq!(approx.len(), exact.len());
        prop_assert!(approx.iter().all(|h| filter.matches(&h.record)));
        prop_assert!(approx.windows(2).all(|w| w[0].score >= w[1].score));
    }
}
