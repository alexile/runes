//! Integration tests against a live Postgres with pgvector. They run only
//! when `DATABASE_URL` is set, e.g.
//! `DATABASE_URL=postgres://postgres:pw@127.0.0.1:5432/postgres`, and are
//! skipped otherwise. Each test works in its own table and drops it.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::ops::Bound;
use std::sync::atomic::{AtomicU32, Ordering};

use rune_vectorstore::{
    Filter, Hit, InMemoryVectorStore, Metric, Options, Query, Record, StoreError, Value,
    VectorStore,
};
use rune_vectorstore_pgvector::{PgIndex, PgVectorConfig, PgVectorStore};
use serde_json::json;

fn database_url() -> Option<String> {
    let url = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty());
    if url.is_none() {
        eprintln!("DATABASE_URL not set; skipping");
    }
    url
}

/// A table name unique to this process and call.
fn table(prefix: &str) -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        "rvs_{prefix}_{}_{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

async fn open(url: &str, config: PgVectorConfig) -> PgVectorStore {
    PgVectorStore::connect(url, config).await.unwrap()
}

async fn drop_table(store: &PgVectorStore) {
    let client = store.pool().get().await.unwrap();
    client
        .batch_execute(&format!("DROP TABLE IF EXISTS {}", store.table()))
        .await
        .unwrap();
}

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

const KEYS: [&str; 5] = ["n", "f", "s", "tags", "odd key.with \"quotes\""];

fn value(rng: &mut Rng) -> Value {
    match rng.below(8) {
        0 => json!(rng.below(10)),
        1 => json!(f64::from(u32::try_from(rng.below(20)).unwrap()) / 4.0),
        2 => json!(rng.pick(&["a", "b", "c", "é", "a\"b", "", "B"])),
        3 => json!([rng.below(5), rng.pick(&["a", "b"])]),
        4 => json!(rng.below(2) == 0),
        5 => Value::Null,
        6 => json!({"x": rng.below(2)}),
        _ => json!(-i64::try_from(rng.below(5)).unwrap()),
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
        5 => Filter::between(key, *rng.pick(&["", "a", "B"]), *rng.pick(&["b", "c", "z"])),
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

fn assert_same(got: &[Hit], want: &[Hit], what: &dyn std::fmt::Debug) {
    let ids = |h: &[Hit]| h.iter().map(|h| h.record.id.clone()).collect::<Vec<_>>();
    assert_eq!(ids(got), ids(want), "{what:?}");
    for (g, w) in got.iter().zip(want) {
        assert!(
            (g.score - w.score).abs() < 1e-4,
            "{} vs {}",
            g.score,
            w.score
        );
        assert_eq!(g.record, w.record);
    }
}

#[tokio::test]
async fn exact_scan_matches_in_memory() {
    let Some(url) = database_url() else { return };
    for (seed, metric) in [
        (1, Metric::Cosine),
        (2, Metric::DotProduct),
        (3, Metric::Euclidean),
    ] {
        let mut rng = Rng(seed);
        let dim = 8;
        let config = PgVectorConfig::new(table("exact"), dim)
            .with_metric(metric)
            .with_index(PgIndex::None)
            .with_upsert_batch_rows(77);
        let pg = open(&url, config).await;
        let mem = InMemoryVectorStore::new(Options::default().with_metric(metric));
        let records: Vec<Record> = (0..400).map(|i| record(&mut rng, i, dim)).collect();
        pg.upsert(records.clone()).await.unwrap();
        mem.upsert(records).await.unwrap();
        assert_eq!(pg.len().await.unwrap(), 400);
        for i in 0..120 {
            let k = [1, 5, 10, 50, 1000][i % 5];
            let q = Query::new(rng.vector(dim), k).with_filter(filter(&mut rng, 3));
            let got = pg.query(&q).await.unwrap();
            let want = mem.query(&q).await.unwrap();
            assert_same(&got, &want, &q.filter);
        }
        for _ in 0..200 {
            let f = leaf(&mut rng);
            for f in [f.clone(), !f] {
                let q = Query::new(rng.vector(dim), 1000).with_filter(f);
                assert_same(
                    &pg.query(&q).await.unwrap(),
                    &mem.query(&q).await.unwrap(),
                    &q.filter,
                );
            }
        }
        let f = filter(&mut rng, 2);
        assert_eq!(
            pg.delete_where(&f).await.unwrap(),
            mem.delete_where(&f).unwrap()
        );
        assert_eq!(pg.len().await.unwrap(), mem.len().await.unwrap());
        drop_table(&pg).await;
    }
}

#[tokio::test]
async fn crud_and_options() {
    let Some(url) = database_url() else { return };
    let pg = open(&url, PgVectorConfig::new(table("crud"), 3)).await;
    let a = Record::new("a", vec![0.25, -1.5, 3.0])
        .with_content("alpha")
        .with_meta("n", 1)
        .with_meta("big", u64::MAX)
        .with_meta("nested", json!({"deep": [1.5, null, "z"]}));
    pg.upsert(vec![a.clone(), Record::new("b", vec![1.0, 0.0, 0.0])])
        .await
        .unwrap();
    assert_eq!(pg.get("a").await.unwrap(), Some(a));
    assert_eq!(pg.get("nope").await.unwrap(), None);
    assert_eq!(pg.get("nul\0").await.unwrap(), None);
    pg.upsert(vec![
        Record::new("a", vec![0.0, 1.0, 0.0]).with_content("new"),
    ])
    .await
    .unwrap();
    assert_eq!(pg.get("a").await.unwrap().unwrap().content, "new");
    assert_eq!(pg.len().await.unwrap(), 2);

    let q = Query::new(vec![0.0, 1.0, 0.0], 10);
    let hits = pg.query(&q).await.unwrap();
    assert_eq!(hits[0].record.id, "a");
    assert!((hits[0].score - 1.0).abs() < 1e-6);
    let hits = pg.query(&q.clone().with_vectors(false)).await.unwrap();
    assert!(hits.iter().all(|h| h.record.vector.is_empty()));
    assert_eq!(
        pg.query(&q.clone().with_min_score(0.5))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        pg.query(&Query::new(vec![1.0, 0.0, 0.0], 0)).await.unwrap(),
        []
    );
    let wide = Query::new(vec![1.0, 0.0, 0.0], usize::MAX).with_ef_search(5000);
    assert_eq!(pg.query(&wide).await.unwrap().len(), 2);

    assert_eq!(pg.delete(&["a", "a", "zz", "\0"]).await.unwrap(), 1);
    pg.clear().await.unwrap();
    assert!(pg.is_empty().await.unwrap());
    drop_table(&pg).await;
}

#[tokio::test]
async fn invalid_input_is_rejected() {
    let Some(url) = database_url() else { return };
    let pg = open(&url, PgVectorConfig::new(table("bad"), 2)).await;
    let mem = InMemoryVectorStore::new(Options::default().with_dimension(2));
    for batch in [
        vec![Record::new("", vec![1.0, 0.0])],
        vec![
            Record::new("x", vec![1.0, 0.0]),
            Record::new("x", vec![0.0, 1.0]),
        ],
        vec![Record::new("x", vec![1.0, 0.0, 0.0])],
        vec![Record::new("x", vec![f32::NAN, 0.0])],
        vec![Record::new("x", vec![f32::NEG_INFINITY, 0.0])],
        vec![Record::new("x", vec![0.0, 0.0])],
    ] {
        let want = mem.upsert(batch.clone()).await.unwrap_err();
        assert_eq!(pg.upsert(batch).await.unwrap_err(), want);
    }
    assert!(matches!(
        pg.upsert(vec![Record::new("x", vec![1.0, 0.0]).with_meta("k", "\0")])
            .await,
        Err(StoreError::Backend(_))
    ));
    for q in [
        Query::new(vec![1.0], 1),
        Query::new(vec![f32::NAN, 1.0], 1),
        Query::new(vec![0.0, 0.0], 1),
        Query::new(vec![1.0, 0.0], 1).with_min_score(f32::NAN),
        Query::new(vec![1.0, 0.0], 1).with_filter(Filter::gt("x", true)),
    ] {
        assert_eq!(
            pg.query(&q).await.unwrap_err(),
            mem.query(&q).await.unwrap_err()
        );
    }
    assert!(pg.is_empty().await.unwrap());
    drop_table(&pg).await;
}

#[tokio::test]
async fn hnsw_and_ivfflat_with_filters() {
    let Some(url) = database_url() else { return };
    for index in [
        PgIndex::Hnsw {
            m: 16,
            ef_construction: 64,
        },
        PgIndex::IvfFlat { lists: 4 },
    ] {
        let mut rng = Rng(9);
        let dim = 16;
        let config = PgVectorConfig::new(table("ann"), dim)
            .with_index(index)
            .with_ef_search(100)
            .with_probes(4);
        let pg = open(&url, config).await;
        let mem = InMemoryVectorStore::default();
        let records: Vec<Record> = (0..2000)
            .map(|i| {
                Record::new(i.to_string(), rng.vector(dim)).with_meta("bucket", rng.below(100))
            })
            .collect();
        pg.upsert(records.clone()).await.unwrap();
        mem.upsert(records).await.unwrap();
        let (mut found, mut total) = (0, 0);
        for _ in 0..20 {
            // A 2 % filter: without iterative scans HNSW would return
            // almost nothing.
            let q = Query::new(rng.vector(dim), 10).with_filter(Filter::lt("bucket", 2));
            let want = mem.query(&q).await.unwrap();
            let got = pg.query(&q).await.unwrap();
            assert!(got.iter().all(|h| q.filter.matches(&h.record)));
            total += want.len();
            found += got
                .iter()
                .filter(|h| want.iter().any(|w| w.record.id == h.record.id))
                .count();
        }
        let recall =
            f64::from(u32::try_from(found).unwrap()) / f64::from(u32::try_from(total).unwrap());
        assert!(recall > 0.8, "{index:?}: recall {recall}");
        drop_table(&pg).await;
    }
}

#[tokio::test]
async fn schema_is_idempotent_and_dimension_checked() {
    let Some(url) = database_url() else { return };
    let name = table("schema");
    let pg = open(&url, PgVectorConfig::new(&name, 4)).await;
    pg.ensure_schema().await.unwrap();
    let again = open(&url, PgVectorConfig::new(&name, 4)).await;
    again.ensure_schema().await.unwrap();
    let wrong = PgVectorStore::connect(&url, PgVectorConfig::new(&name, 5)).await;
    assert!(matches!(
        wrong,
        Err(StoreError::DimensionMismatch {
            expected: 4,
            actual: 5
        })
    ));
    drop_table(&pg).await;
}

#[tokio::test]
async fn hostile_metadata_is_inert() {
    let Some(url) = database_url() else { return };
    let pg = open(&url, PgVectorConfig::new(table("evil"), 2)).await;
    let keys = [
        "'; DROP TABLE evil; --",
        "\") OR 1=1 --",
        "$1",
        "a\\\"b",
        "",
        "metadata",
        "}'::jsonb OR TRUE --",
    ];
    let values = [
        json!("'; DELETE FROM evil; --"),
        json!("x' OR '1'='1"),
        json!({"$1": "?"}),
        json!(["' || pg_sleep(5) || '"]),
    ];
    let mut records = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        for (j, value) in values.iter().enumerate() {
            records.push(
                Record::new(format!("{key}/{i}/{j}"), vec![1.0, 0.5])
                    .with_meta(*key, value.clone()),
            );
        }
    }
    pg.upsert(records.clone()).await.unwrap();
    for r in &records {
        assert_eq!(pg.get(&r.id).await.unwrap().as_ref(), Some(r));
    }
    for key in keys {
        for value in &values {
            for f in [
                Filter::eq(key, value.clone()),
                !Filter::eq(key, value.clone()),
                Filter::exists(key),
                Filter::between(key, "'", "z'; --"),
                Filter::eq(key, "\0"),
            ] {
                let q = Query::new(vec![1.0, 0.0], 1000).with_filter(f.clone());
                let hits = pg.query(&q).await.unwrap();
                let want = records.iter().filter(|r| f.matches(r)).count();
                assert_eq!(hits.len(), want, "{f:?}");
            }
        }
    }
    assert_eq!(pg.len().await.unwrap(), records.len());
    drop_table(&pg).await;
}

/// Runs without a database: the connection fails, and neither the error
/// nor `Debug` may show the password or the URL.
#[tokio::test]
async fn errors_never_leak_credentials() {
    let url = "postgres://scanner:Sup3rS3cretPw@127.0.0.1:1/vectors?connect_timeout=2";
    let err = PgVectorStore::connect(url, PgVectorConfig::new("docs", 3))
        .await
        .unwrap_err()
        .to_string();
    assert!(!err.contains("Sup3rS3cretPw"), "{err}");
    assert!(!err.contains(url), "{err}");

    let err = PgVectorStore::connect(
        "postgres://u:Sup3rS3cretPw@[bad",
        PgVectorConfig::new("docs", 3),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(!err.contains("Sup3rS3cretPw"), "{err}");

    let mut cfg = deadpool_postgres::Config::new();
    cfg.url = Some(url.into());
    let pool = cfg
        .create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .unwrap();
    let store = PgVectorStore::new(pool, PgVectorConfig::new("docs", 3)).unwrap();
    assert!(!format!("{store:?}").contains("Sup3rS3cretPw"));
    let err = store.len().await.unwrap_err().to_string();
    assert!(!err.contains("Sup3rS3cretPw"), "{err}");
}
