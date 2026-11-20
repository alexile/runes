//! The SQLite store against `InMemoryVectorStore` on seeded random data:
//! same ids, same order, same scores, with and without filters.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::ops::Bound;

use rune_vectorstore::{
    Filter, InMemoryVectorStore, Metric, Options, Query, Record, StoreError, Value, VectorStore,
};
use rune_vectorstore_sqlite::{SqliteConfig, SqliteVectorStore};
use serde_json::json;

/// Deterministic splitmix64.
struct Rng(u64);

impl Rng {
    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    const fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    #[allow(clippy::cast_precision_loss)]
    fn unit(&mut self) -> f32 {
        ((self.next_u64() >> 40) as f32 / (1u64 << 24) as f32).mul_add(2.0, -1.0)
    }

    fn vector(&mut self, dim: usize) -> Vec<f32> {
        (0..dim).map(|_| self.unit()).collect()
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[usize::try_from(self.below(items.len() as u64)).unwrap()]
    }
}

const KEYS: [&str; 6] = ["n", "f", "s", "tags", "flag", "odd key.with \"quotes\""];

fn value(rng: &mut Rng) -> Value {
    match rng.below(9) {
        0 => json!(rng.below(10)),
        1 => json!(f64::from(u32::try_from(rng.below(20)).unwrap()) / 4.0),
        2 => json!(rng.pick(&["a", "b", "c", "é", "a\"b", ""])),
        3 => json!([rng.below(5), rng.pick(&["a", "b"])]),
        4 => json!(rng.below(2) == 0),
        5 => Value::Null,
        6 => json!(-i64::try_from(rng.below(5)).unwrap()),
        7 => json!({"x": rng.below(2)}),
        _ => json!(u64::MAX - rng.below(2)),
    }
}

fn record(rng: &mut Rng, i: usize, dim: usize) -> Record {
    let mut r = Record::new(format!("r{i:04}"), rng.vector(dim)).with_content(format!("doc {i}"));
    for key in KEYS {
        if rng.below(3) > 0 {
            r = r.with_meta(key, value(rng));
        }
    }
    r
}

fn leaf(rng: &mut Rng) -> Filter {
    let key = *rng.pick(&KEYS);
    match rng.below(7) {
        0 | 1 => Filter::eq(key, value(rng)),
        2 => Filter::is_in(key, [value(rng), value(rng), value(rng)]),
        3 => {
            let a = rng.below(10);
            Filter::range(
                key,
                Bound::Included(json!(a)),
                Bound::Excluded(json!(a + 4)),
            )
        }
        4 => Filter::gt(
            key,
            f64::from(u32::try_from(rng.below(16)).unwrap()) / 4.0 - 1.0,
        ),
        5 => Filter::between(key, *rng.pick(&["", "a", "b"]), *rng.pick(&["b", "c", "z"])),
        _ => Filter::exists(key),
    }
}

fn filter(rng: &mut Rng, depth: u32) -> Filter {
    if depth == 0 {
        return leaf(rng);
    }
    match rng.below(5) {
        0 => Filter::And((0..rng.below(4)).map(|_| filter(rng, depth - 1)).collect()),
        1 => Filter::Or((0..rng.below(4)).map(|_| filter(rng, depth - 1)).collect()),
        2 => !filter(rng, depth - 1),
        _ => leaf(rng),
    }
}

async fn pair(metric: Metric, records: &[Record]) -> (InMemoryVectorStore, SqliteVectorStore) {
    let mem = InMemoryVectorStore::new(Options::default().with_metric(metric));
    let sql = SqliteVectorStore::open_in_memory(
        SqliteConfig::new("parity")
            .with_metric(metric)
            .with_scan_chunk_rows(97),
    )
    .unwrap();
    for chunk in records.chunks(150) {
        mem.upsert(chunk.to_vec()).await.unwrap();
        sql.upsert(chunk.to_vec()).await.unwrap();
    }
    (mem, sql)
}

fn summary(hits: &[rune_vectorstore::Hit]) -> Vec<(String, u32)> {
    hits.iter()
        .map(|h| (h.record.id.clone(), h.score.to_bits()))
        .collect()
}

#[tokio::test]
async fn random_queries_match_in_memory() {
    for (seed, metric) in [
        (1, Metric::Cosine),
        (2, Metric::DotProduct),
        (3, Metric::Euclidean),
    ] {
        let mut rng = Rng(seed);
        let dim = 12;
        let records: Vec<Record> = (0..600).map(|i| record(&mut rng, i, dim)).collect();
        let (mem, sql) = pair(metric, &records).await;
        assert_eq!(sql.len().await.unwrap(), 600);
        let mut nonempty = 0;
        for i in 0..150 {
            let k = [1, 5, 10, 50, 1000][i % 5];
            let mut q = Query::new(rng.vector(dim), k).with_filter(filter(&mut rng, 3));
            if i % 7 == 0 {
                q = q.with_min_score(0.0);
            }
            let want = mem.query(&q).await.unwrap();
            let got = sql.query(&q).await.unwrap();
            assert_eq!(summary(&got), summary(&want), "{metric:?} {:?}", q.filter);
            assert_eq!(got, want);
            nonempty += usize::from(!got.is_empty());
        }
        assert!(nonempty > 100, "filters should mostly match something");
    }
}

#[tokio::test]
async fn every_leaf_alone_and_negated_matches_in_memory() {
    let mut rng = Rng(7);
    let records: Vec<Record> = (0..300).map(|i| record(&mut rng, i, 4)).collect();
    let (mem, sql) = pair(Metric::Euclidean, &records).await;
    for _ in 0..400 {
        let f = leaf(&mut rng);
        for f in [f.clone(), !f] {
            let q = Query::new(vec![0.0; 4], 1000).with_filter(f);
            let want = mem.query(&q).await.unwrap();
            let got = sql.query(&q).await.unwrap();
            if got != want {
                let g: Vec<_> = got
                    .iter()
                    .map(|h| (&h.record.id, &h.record.metadata))
                    .collect();
                let w: Vec<_> = want
                    .iter()
                    .map(|h| (&h.record.id, &h.record.metadata))
                    .collect();
                let extra: Vec<_> = g.iter().filter(|x| !w.contains(x)).collect();
                let missing: Vec<_> = w.iter().filter(|x| !g.contains(x)).collect();
                panic!("{:?}\nextra {extra:?}\nmissing {missing:?}", q.filter);
            }
        }
    }
}

#[tokio::test]
async fn delete_where_matches_in_memory() {
    let mut rng = Rng(11);
    let records: Vec<Record> = (0..300).map(|i| record(&mut rng, i, 3)).collect();
    for _ in 0..10 {
        let (mem, sql) = pair(Metric::Cosine, &records).await;
        let f = filter(&mut rng, 2);
        assert_eq!(
            sql.delete_where(&f).await.unwrap(),
            mem.delete_where(&f).unwrap(),
            "{f:?}"
        );
        assert_eq!(sql.len().await.unwrap(), mem.len().await.unwrap());
        let q = Query::new(vec![1.0, 0.0, 0.0], 1000);
        assert_eq!(sql.query(&q).await.unwrap(), mem.query(&q).await.unwrap());
    }
}

#[tokio::test]
async fn mmr_and_batch_match_in_memory() {
    let mut rng = Rng(5);
    let records: Vec<Record> = (0..200).map(|i| record(&mut rng, i, 6)).collect();
    let (mem, sql) = pair(Metric::Cosine, &records).await;
    let queries: Vec<Query> = (0..5).map(|_| Query::new(rng.vector(6), 4)).collect();
    assert_eq!(
        sql.query_batch(&queries).await.unwrap(),
        mem.query_batch(&queries).await.unwrap()
    );
    let q = &queries[0];
    assert_eq!(
        sql.query_mmr(q, 20, 0.5, Metric::Cosine).await.unwrap(),
        mem.query_mmr(q, 20, 0.5, Metric::Cosine).await.unwrap()
    );
}

#[tokio::test]
async fn same_errors_as_in_memory() {
    let (mem, sql) = pair(Metric::Cosine, &[Record::new("a", vec![1.0, 0.0])]).await;
    let bad_batches = [
        vec![Record::new("", vec![1.0, 0.0])],
        vec![
            Record::new("x", vec![1.0, 0.0]),
            Record::new("x", vec![0.0, 1.0]),
        ],
        vec![Record::new("x", vec![1.0, 0.0, 0.0])],
        vec![Record::new("x", vec![f32::NAN, 0.0])],
        vec![Record::new("x", vec![f32::INFINITY, 0.0])],
        vec![Record::new("x", vec![0.0, 0.0])],
        vec![Record::new("ok", vec![1.0, 0.0]), Record::new("x", vec![])],
    ];
    for batch in bad_batches {
        let want = mem.upsert(batch.clone()).await.unwrap_err();
        assert_eq!(sql.upsert(batch).await.unwrap_err(), want);
    }
    // Failed batches are atomic.
    assert_eq!(sql.len().await.unwrap(), 1);
    let bad_queries = [
        Query::new(vec![1.0], 1),
        Query::new(vec![f32::NAN, 1.0], 1),
        Query::new(vec![0.0, 0.0], 1),
        Query::new(vec![1.0, 0.0], 1).with_min_score(f32::NAN),
        Query::new(vec![1.0, 0.0], 1).with_filter(Filter::gt("x", true)),
    ];
    for q in bad_queries {
        let want: StoreError = mem.query(&q).await.unwrap_err();
        assert_eq!(sql.query(&q).await.unwrap_err(), want);
    }
}
