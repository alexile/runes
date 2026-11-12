//! The async store: concurrency, batch and MMR queries, snapshots on disk.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::sync::Arc;

use rune_vectorstore::{
    Filter, HnswParams, InMemoryVectorStore, IndexKind, LoadLimits, Metric, Options, Query, Record,
    StoreError, VectorStore,
};

const fn assert_send_sync<T: Send + Sync>() {}
const _: () = assert_send_sync::<InMemoryVectorStore>();

fn records(n: u16) -> Vec<Record> {
    (0..n)
        .map(|i| {
            let a = f32::from(i) * 0.1;
            Record::new(format!("r{i}"), vec![a.cos(), a.sin(), 0.5])
                .with_content(format!("item {i}"))
                .with_meta("even", i % 2 == 0)
                .with_meta("i", i)
        })
        .collect()
}

fn kinds() -> [IndexKind; 2] {
    [IndexKind::Flat, IndexKind::Hnsw(HnswParams::default())]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_readers_and_writers() {
    for kind in kinds() {
        let store = Arc::new(InMemoryVectorStore::new(
            Options::default().with_index(kind),
        ));
        store.upsert(records(200)).await.unwrap();
        let mut tasks = Vec::new();
        for t in 0..8u16 {
            let s = Arc::clone(&store);
            tasks.push(tokio::spawn(async move {
                for j in 0..50u16 {
                    if t % 4 == 0 {
                        let id = format!("w{t}-{j}");
                        s.upsert(vec![Record::new(id, vec![1.0, f32::from(j), 0.0])])
                            .await
                            .unwrap();
                    } else {
                        let hits = s.query(&Query::new(vec![1.0, 0.0, 0.5], 5)).await.unwrap();
                        assert_eq!(hits.len(), 5);
                    }
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(store.len().await.unwrap(), 200 + 2 * 50);
    }
}

#[tokio::test]
async fn batch_queries_match_single_queries() {
    for kind in kinds() {
        let store = InMemoryVectorStore::new(Options::default().with_index(kind));
        store.upsert(records(100)).await.unwrap();
        let queries: Vec<Query> = (0..10u8)
            .map(|i| {
                Query::new(vec![1.0, f32::from(i) * 0.2, 0.5], 3)
                    .with_filter(Filter::eq("even", i % 2 == 0))
            })
            .collect();
        let batch = store.query_batch(&queries).await.unwrap();
        assert_eq!(batch.len(), queries.len());
        for (q, hits) in queries.iter().zip(&batch) {
            assert_eq!(&store.query(q).await.unwrap(), hits);
        }
        let bad = [Query::new(vec![1.0], 1)];
        assert!(matches!(
            store.query_batch(&bad).await,
            Err(StoreError::DimensionMismatch { .. })
        ));
    }
}

#[tokio::test]
async fn mmr_diversifies_and_respects_options() {
    let store = InMemoryVectorStore::default();
    store
        .upsert(vec![
            Record::new("a", vec![1.0, 0.0]),
            Record::new("a2", vec![0.999, 0.01]),
            Record::new("a3", vec![0.998, 0.02]),
            Record::new("b", vec![0.6, 0.8]),
        ])
        .await
        .unwrap();
    let q = Query::new(vec![1.0, 0.0], 2);
    let plain: Vec<String> = store
        .query(&q)
        .await
        .unwrap()
        .into_iter()
        .map(|h| h.record.id)
        .collect();
    assert_eq!(plain, ["a", "a2"]);
    let diverse = store.query_mmr(&q, 10, 0.3, Metric::Cosine).await.unwrap();
    let ids: Vec<&str> = diverse.iter().map(|h| h.record.id.as_str()).collect();
    assert_eq!(ids, ["a", "b"]);
    assert_eq!(diverse[0].record.vector, [1.0, 0.0]);
    let slim = store
        .query_mmr(&q.clone().with_vectors(false), 10, 0.3, Metric::Cosine)
        .await
        .unwrap();
    assert!(slim.iter().all(|h| h.record.vector.is_empty()));
    assert!(store.query_mmr(&q, 10, -0.1, Metric::Cosine).await.is_err());
}

#[tokio::test]
async fn upsert_replaces_and_delete_where() {
    for kind in kinds() {
        let store = InMemoryVectorStore::new(Options::default().with_index(kind));
        store.upsert(records(40)).await.unwrap();
        store
            .upsert(vec![
                Record::new("r3", vec![0.0, 0.0, 1.0]).with_meta("i", 999),
            ])
            .await
            .unwrap();
        assert_eq!(store.len().await.unwrap(), 40);
        let r3 = store.get("r3").await.unwrap().unwrap();
        assert_eq!(r3.metadata["i"], 999);
        assert!(!r3.metadata.contains_key("even"));

        assert_eq!(store.delete_where(&Filter::eq("even", true)).unwrap(), 20);
        assert_eq!(store.len().await.unwrap(), 20);
        let all = store
            .query(&Query::new(vec![1.0, 0.0, 0.5], 100))
            .await
            .unwrap();
        assert_eq!(all.len(), 20);
        assert!(
            all.iter()
                .all(|h| h.record.metadata.get("even") != Some(&true.into()))
        );
        assert!(store.delete_where(&Filter::gt("i", false)).is_err());
    }
}

#[tokio::test]
async fn snapshots_round_trip_through_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.bin");
    for (n, kind) in kinds().into_iter().enumerate() {
        let store = InMemoryVectorStore::new(
            Options::default()
                .with_metric(Metric::Euclidean)
                .with_index(kind),
        );
        store.upsert(records(300)).await.unwrap();
        store.delete(&["r5", "r6"]).await.unwrap();
        store.save(&path).unwrap();
        // Saving again replaces the file atomically.
        store.save(&path).unwrap();

        let loaded = InMemoryVectorStore::load(&path, &LoadLimits::default()).unwrap();
        assert_eq!(loaded.metric().unwrap(), Metric::Euclidean);
        assert_eq!(loaded.len().await.unwrap(), 298, "{n}");
        assert!(loaded.get("r5").await.unwrap().is_none());
        assert_eq!(
            loaded.get("r7").await.unwrap(),
            store.get("r7").await.unwrap()
        );
        let q = Query::new(vec![0.9, 0.1, 0.5], 5).with_filter(Filter::eq("even", false));
        assert_eq!(
            loaded.query(&q).await.unwrap(),
            store.query(&q).await.unwrap()
        );
    }
    // No temporary files are left behind.
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["store.bin"]);
}

#[test]
fn load_enforces_limits_and_reports_io_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.bin");
    let store = InMemoryVectorStore::default();
    tokio_test::block_on(store.upsert(records(10))).unwrap();
    store.save(&path).unwrap();

    let err =
        InMemoryVectorStore::load(&path, &LoadLimits::default().with_max_bytes(64)).unwrap_err();
    assert!(matches!(err, StoreError::LimitExceeded { .. }), "{err}");
    let err =
        InMemoryVectorStore::load(&path, &LoadLimits::default().with_max_records(5)).unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::LimitExceeded {
                what: "record count",
                ..
            }
        ),
        "{err}"
    );

    std::fs::write(&path, b"definitely not a snapshot").unwrap();
    assert!(matches!(
        InMemoryVectorStore::load(&path, &LoadLimits::default()),
        Err(StoreError::InvalidSnapshot(_))
    ));
    let err =
        InMemoryVectorStore::load(dir.path().join("missing"), &LoadLimits::default()).unwrap_err();
    assert!(matches!(
        err,
        StoreError::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        }
    ));
    let err = store
        .save(dir.path().join("no/such/dir/x.bin"))
        .unwrap_err();
    assert!(matches!(err, StoreError::Io { .. }));
}
