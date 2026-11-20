//! Tests against a real Qdrant server. They run only when `QDRANT_URL` is
//! set (plus `QDRANT_API_KEY` if the server needs one), e.g.
//!
//! ```sh
//! docker run -p 6333:6333 qdrant/qdrant
//! QDRANT_URL=http://localhost:6333 cargo test -p rune-vectorstore-qdrant --test live
//! ```
//!
//! Each test uses its own throwaway collection and drops it at the end.

#![allow(clippy::unwrap_used, clippy::assert_is_empty, reason = "test helpers")]

use rune_vectorstore::{Filter, Metric, Query, Record, VectorStore};
use rune_vectorstore_qdrant::{QdrantConfig, QdrantStore};
use serde_json::json;

fn live(name: &str, metric: Metric) -> Option<QdrantStore> {
    if std::env::var("QDRANT_URL").map_or(true, |u| u.trim().is_empty()) {
        eprintln!("QDRANT_URL is not set; skipping");
        return None;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let collection = format!("rune_test_{name}_{}_{nanos}", std::process::id());
    Some(
        QdrantStore::new(
            QdrantConfig::from_env(collection)
                .metric(metric)
                .batch_size(3),
        )
        .unwrap(),
    )
}

fn corpus() -> Vec<Record> {
    vec![
        Record::new("rust", vec![0.9, 0.1, 0.0])
            .with_content("Rust")
            .with_meta("kind", "lang")
            .with_meta("year", 2015)
            .with_meta("tags", json!(["systems", "safe"]))
            .with_meta("released", "2015-05-15"),
        Record::new("go", vec![0.8, 0.3, 0.1])
            .with_content("Go")
            .with_meta("kind", "lang")
            .with_meta("year", 2012)
            .with_meta("tags", json!(["systems"]))
            .with_meta("released", "2012-03-28"),
        Record::new("python", vec![0.5, 0.5, 0.2])
            .with_content("Python")
            .with_meta("kind", "lang")
            .with_meta("year", 1991)
            .with_meta("score", 9.5)
            .with_meta("major", 3.0),
        Record::new("paris", vec![0.0, 0.2, 0.9])
            .with_content("Paris")
            .with_meta("kind", "city")
            .with_meta("note", serde_json::Value::Null),
        Record::new("7", vec![0.1, 0.9, 0.1]).with_content("Seven"),
    ]
}

fn ids(hits: &[rune_vectorstore::Hit]) -> Vec<&str> {
    hits.iter().map(|h| h.record.id.as_str()).collect()
}

#[tokio::test]
async fn crud_and_filters() {
    let Some(s) = live("crud", Metric::Cosine) else {
        return;
    };
    assert_eq!(s.len().await.unwrap(), 0);
    assert!(
        s.query(&Query::new(vec![1.0, 0.0, 0.0], 3))
            .await
            .unwrap()
            .is_empty()
    );

    s.upsert(corpus()).await.unwrap();
    assert_eq!(s.len().await.unwrap(), 5);

    let hits = s.query(&Query::new(vec![1.0, 0.0, 0.0], 2)).await.unwrap();
    assert_eq!(ids(&hits), ["rust", "go"]);
    assert!(hits[0].score > hits[1].score && hits[0].score <= 1.0);
    // Cosine vectors come back unit length.
    let n: f32 = hits[0].record.vector.iter().map(|x| x * x).sum();
    assert!((n - 1.0).abs() < 1e-4);
    assert_eq!(hits[0].record.metadata["year"], 2015);

    let q = |f: Filter| Query::new(vec![1.0, 0.0, 0.0], 10).with_filter(f);
    let cases = [
        (Filter::eq("kind", "city"), vec!["paris"]),
        (Filter::lt("year", 2014), vec!["go", "python"]),
        (Filter::between("year", 2012, 2015), vec!["rust", "go"]),
        (Filter::eq("tags", "safe"), vec!["rust"]),
        (
            Filter::is_in("tags", ["safe", "systems"]),
            vec!["rust", "go"],
        ),
        (Filter::is_in("year", [1991, 2015]), vec!["rust", "python"]),
        (Filter::eq("score", 9.5), vec!["python"]),
        // An integer finds a float of the same value, like the in-memory store.
        (Filter::eq("major", 3), vec!["python"]),
        (
            Filter::eq("kind", "lang").and(!Filter::eq("year", 2015)),
            vec!["go", "python"],
        ),
        (
            Filter::eq("kind", "city").or(Filter::eq("year", 1991)),
            vec!["python", "paris"],
        ),
        (Filter::exists("tags"), vec!["rust", "go"]),
        (Filter::eq("note", serde_json::Value::Null), vec!["paris"]),
        (Filter::gte("released", "2013-01-01"), vec!["rust"]),
        (Filter::Or(vec![]), vec![]),
    ];
    for (f, want) in cases {
        let hits = s.query(&q(f.clone())).await.unwrap();
        let mut got = ids(&hits);
        let mut want = want;
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(got, want, "{f:?}");
    }
    let hits = s
        .query(&Query::new(vec![1.0, 0.0, 0.0], 10).with_min_score(0.9))
        .await
        .unwrap();
    assert!(hits.iter().all(|h| h.score >= 0.9) && !hits.is_empty());

    let batch = s
        .query_batch(&[
            Query::new(vec![0.0, 0.0, 1.0], 1),
            Query::new(vec![0.0, 1.0, 0.0], 1),
        ])
        .await
        .unwrap();
    assert_eq!(batch[0][0].record.id, "paris");
    assert_eq!(batch[1][0].record.id, "7");

    let mmr = s
        .query_mmr(&Query::new(vec![1.0, 0.0, 0.0], 2), 5, 0.3, Metric::Cosine)
        .await
        .unwrap();
    assert_eq!(mmr.len(), 2);

    let got = s.get("python").await.unwrap().unwrap();
    assert_eq!(got.content, "Python");
    assert_eq!(s.get("7").await.unwrap().unwrap().content, "Seven");
    assert_eq!(s.get("nope").await.unwrap(), None);

    // Upsert replaces.
    s.upsert(vec![
        Record::new("go", vec![0.8, 0.3, 0.1]).with_content("Golang"),
    ])
    .await
    .unwrap();
    assert_eq!(s.get("go").await.unwrap().unwrap().content, "Golang");
    assert_eq!(s.len().await.unwrap(), 5);

    assert_eq!(s.delete(&["rust", "missing", "rust"]).await.unwrap(), 1);
    assert_eq!(s.count(&Filter::eq("kind", "lang")).await.unwrap(), 1);
    assert_eq!(
        s.delete_where(&Filter::eq("kind", "lang")).await.unwrap(),
        1
    );
    assert_eq!(s.len().await.unwrap(), 3);
    assert_eq!(s.delete_where(&Filter::default()).await.unwrap(), 3);
    assert!(s.is_empty().await.unwrap());

    let err = s
        .upsert(vec![Record::new("x", vec![1.0, 2.0])])
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        rune_vectorstore::StoreError::DimensionMismatch { .. }
    ));

    assert!(s.drop_collection().await.unwrap());
    assert!(!s.drop_collection().await.unwrap());
}

#[tokio::test]
async fn euclidean_and_dot() {
    for (name, metric) in [("l2", Metric::Euclidean), ("dot", Metric::DotProduct)] {
        let Some(s) = live(name, metric) else {
            return;
        };
        s.upsert(vec![
            Record::new("a", vec![0.0, 0.0]),
            Record::new("b", vec![3.0, 4.0]),
        ])
        .await
        .unwrap();
        let hits = s.query(&Query::new(vec![0.0, 0.0], 2)).await.unwrap();
        if metric == Metric::Euclidean {
            assert_eq!(ids(&hits), ["a", "b"]);
            assert!((hits[1].score + 5.0).abs() < 1e-4, "{}", hits[1].score);
            let near = Query::new(vec![0.0, 0.0], 2).with_min_score(-1.0);
            assert_eq!(ids(&s.query(&near).await.unwrap()), ["a"]);
        } else {
            let hits = s.query(&Query::new(vec![1.0, 1.0], 2)).await.unwrap();
            assert_eq!(ids(&hits), ["b", "a"]);
            assert!((hits[0].score - 7.0).abs() < 1e-4);
        }
        // Reopening with another metric is refused.
        let other = if metric == Metric::Euclidean {
            Metric::DotProduct
        } else {
            Metric::Euclidean
        };
        let reopened =
            QdrantStore::new(QdrantConfig::from_env(s.collection().to_owned()).metric(other))
                .unwrap();
        assert!(reopened.len().await.is_err());
        assert!(s.drop_collection().await.unwrap());
    }
}
