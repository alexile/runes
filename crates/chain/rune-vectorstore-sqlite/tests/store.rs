//! Behaviour of the SQLite store: persistence, configuration checks,
//! concurrency and hostile input.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::sync::Arc;

use rune_vectorstore::{Filter, Metric, Options, Query, Record, StoreError, VectorStore};
use rune_vectorstore_sqlite::{SqliteConfig, SqliteVectorStore, check_identifier};
use serde_json::json;

fn mem(table: &str) -> SqliteVectorStore {
    SqliteVectorStore::open_in_memory(SqliteConfig::new(table)).unwrap()
}

#[tokio::test]
async fn crud_round_trip() {
    let store = mem("docs");
    assert!(store.is_empty().await.unwrap());
    let rec = Record::new("a", vec![0.25, -1.5, 3.0])
        .with_content("alpha")
        .with_meta("n", 1)
        .with_meta("tags", json!(["x", "y"]))
        .with_meta("nested", json!({"deep": [1.5, null, "z"]}))
        .with_meta("big", u64::MAX);
    store
        .upsert(vec![rec.clone(), Record::new("b", vec![1.0, 0.0, 0.0])])
        .await
        .unwrap();
    assert_eq!(store.get("a").await.unwrap(), Some(rec));
    assert_eq!(store.get("zzz").await.unwrap(), None);
    assert_eq!(store.len().await.unwrap(), 2);
    assert_eq!(store.dimension(), Some(3));

    // Upsert replaces in place.
    store
        .upsert(vec![
            Record::new("a", vec![0.0, 1.0, 0.0]).with_content("new"),
        ])
        .await
        .unwrap();
    let a = store.get("a").await.unwrap().unwrap();
    assert_eq!((a.content.as_str(), a.metadata.len()), ("new", 0));
    assert_eq!(store.len().await.unwrap(), 2);

    assert_eq!(store.delete(&["a", "a", "nope"]).await.unwrap(), 1);
    assert_eq!(store.delete(&[]).await.unwrap(), 0);
    store.clear().await.unwrap();
    assert!(store.is_empty().await.unwrap());
    // The dimension survives clear.
    assert!(matches!(
        store.upsert(vec![Record::new("c", vec![1.0])]).await,
        Err(StoreError::DimensionMismatch {
            expected: 3,
            actual: 1
        })
    ));
}

#[tokio::test]
async fn query_options() {
    let store = mem("q");
    store
        .upsert(vec![
            Record::new("x", vec![1.0, 0.0]).with_content("x"),
            Record::new("y", vec![0.0, 1.0]).with_content("y"),
            Record::new("z", vec![-1.0, 0.0]).with_content("z"),
        ])
        .await
        .unwrap();
    let q = Query::new(vec![1.0, 0.1], 10);
    let ids: Vec<_> = store
        .query(&q)
        .await
        .unwrap()
        .into_iter()
        .map(|h| h.record.id)
        .collect();
    assert_eq!(ids, ["x", "y", "z"]);
    assert_eq!(
        store
            .query(&Query::new(vec![1.0, 0.0], 0))
            .await
            .unwrap()
            .len(),
        0
    );
    let hits = store.query(&q.clone().with_min_score(0.5)).await.unwrap();
    assert_eq!(hits.len(), 1);
    let hits = store.query(&q.clone().with_vectors(false)).await.unwrap();
    assert!(
        hits.iter()
            .all(|h| h.record.vector.is_empty() && !h.record.content.is_empty())
    );
    let hits = store
        .query(&Query::new(vec![1.0, 0.0], usize::MAX))
        .await
        .unwrap();
    assert_eq!(hits.len(), 3);
}

#[tokio::test]
async fn empty_store_queries_return_nothing() {
    let store = mem("empty");
    assert_eq!(
        store.query(&Query::new(vec![1.0], 5)).await.unwrap().len(),
        0
    );
    assert_eq!(store.dimension(), None);
}

#[tokio::test]
async fn file_store_persists_and_checks_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.db");
    {
        let store = SqliteVectorStore::open(
            &path,
            SqliteConfig::new("docs").with_metric(Metric::DotProduct),
        )
        .unwrap();
        store
            .upsert(vec![Record::new("a", vec![1.0, 2.0]).with_meta("k", "v")])
            .await
            .unwrap();
    }
    let reopened = SqliteVectorStore::open(
        &path,
        SqliteConfig::new("docs").with_metric(Metric::DotProduct),
    )
    .unwrap();
    assert_eq!(reopened.dimension(), Some(2));
    assert_eq!(reopened.get("a").await.unwrap().unwrap().metadata["k"], "v");

    // WAL mode is on.
    assert_eq!(journal_mode(&path), "wal");

    let wrong_metric = SqliteVectorStore::open(&path, SqliteConfig::new("docs"));
    assert!(matches!(wrong_metric, Err(StoreError::Backend(_))));
    let wrong_dim = SqliteVectorStore::open(
        &path,
        SqliteConfig::new("docs")
            .with_metric(Metric::DotProduct)
            .with_dimension(3),
    );
    assert!(matches!(
        wrong_dim,
        Err(StoreError::DimensionMismatch {
            expected: 2,
            actual: 3
        })
    ));

    // A second collection in the same file is independent.
    let other = SqliteVectorStore::open(
        &path,
        SqliteConfig::new("other").with_options(&Options::default().with_dimension(4)),
    )
    .unwrap();
    assert_eq!(other.dimension(), Some(4));
    assert!(other.is_empty().await.unwrap());
}

/// Read the journal mode through a separate connection.
fn journal_mode(path: &std::path::Path) -> String {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn parallel_readers_and_writers() {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(SqliteVectorStore::open(dir.path().join("p.db"), SqliteConfig::new("p")).unwrap());
    let mut tasks = Vec::new();
    for i in 0..16u16 {
        let s = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            let v = vec![1.0, f32::from(i)];
            s.upsert(vec![Record::new(i.to_string(), v.clone())])
                .await?;
            s.query(&Query::new(v, 3)).await.map(drop)
        }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    assert_eq!(store.len().await.unwrap(), 16);
}

#[test]
fn works_without_a_runtime() {
    let store = mem("sync");
    let fut = store.upsert(vec![Record::new("a", vec![1.0])]);
    tokio_test::block_on(fut).unwrap();
    assert_eq!(tokio_test::block_on(store.len()).unwrap(), 1);
}

#[test]
fn table_names_are_identifiers_only() {
    for ok in ["docs", "_x", "Docs_2", "a".repeat(63).as_str()] {
        assert!(check_identifier(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "1docs",
        "docs; DROP TABLE x",
        "do\"cs",
        "sqlite_master",
        "SQLITE_x",
        "rune_vectorstore_collections",
        "a b",
        "é",
        "a".repeat(64).as_str(),
    ] {
        assert!(check_identifier(bad).is_err(), "{bad}");
        assert!(SqliteVectorStore::open_in_memory(SqliteConfig::new(bad)).is_err());
    }
}

#[tokio::test]
async fn hostile_metadata_keys_and_values_are_inert() {
    let store = mem("evil");
    let keys = [
        "'; DROP TABLE evil; --",
        "\") OR 1=1 --",
        "$.x[0]",
        "a\\\"b",
        "",
        "nul\0key",
        "line\nbreak",
        "rune_vectorstore_collections",
    ];
    let values = [
        json!("'; DELETE FROM evil; --"),
        json!("\0"),
        json!("x' OR '1'='1"),
        json!({"$": "?1"}),
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
    store.upsert(records.clone()).await.unwrap();
    for r in &records {
        assert_eq!(store.get(&r.id).await.unwrap().as_ref(), Some(r));
    }
    for key in keys {
        for value in &values {
            for f in [
                Filter::eq(key, value.clone()),
                !Filter::eq(key, value.clone()),
                Filter::exists(key),
                Filter::between(key, "'", "z'; --"),
            ] {
                let q = Query::new(vec![1.0, 0.0], 1000).with_filter(f.clone());
                let hits = store.query(&q).await.unwrap();
                let want = records.iter().filter(|r| f.matches(r)).count();
                assert_eq!(hits.len(), want, "{f:?}");
            }
        }
    }
    assert_eq!(store.len().await.unwrap(), records.len());
    let n = store
        .delete_where(&Filter::eq(keys[0], values[0].clone()))
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(store.len().await.unwrap(), records.len() - 1);
}

#[tokio::test]
async fn large_scan_streams_in_chunks() {
    let store = SqliteVectorStore::open_in_memory(SqliteConfig::new("big").with_scan_chunk_rows(1))
        .unwrap();
    let records: Vec<Record> = (0..500u16)
        .map(|i| Record::new(format!("{i:03}"), vec![1.0, f32::from(i)]).with_meta("i", i))
        .collect();
    store.upsert(records).await.unwrap();
    let q = Query::new(vec![1.0, 0.0], 2).with_filter(Filter::lt("i", 3));
    let ids: Vec<_> = store
        .query(&q)
        .await
        .unwrap()
        .into_iter()
        .map(|h| h.record.id)
        .collect();
    assert_eq!(ids, ["000", "001"]);
}

#[test]
fn debug_hides_connections() {
    let s = format!("{:?}", mem("dbg"));
    assert!(s.contains("dbg") && s.contains("Cosine"));
}
