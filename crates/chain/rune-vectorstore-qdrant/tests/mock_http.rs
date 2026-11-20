//! End-to-end tests against a loopback mock of Qdrant's REST API: the store
//! builds real HTTP requests and decodes recorded responses. No test touches
//! the network.

#![allow(clippy::unwrap_used, clippy::assert_is_empty, reason = "test helpers")]

use std::time::Duration;

use rune_chain_core::testing::http::{MockResponse, MockServer, RecordedRequest};
use rune_vectorstore::{Filter, Metric, Query, Record, StoreError, VectorStore};
use rune_vectorstore_qdrant::{PointId, QdrantConfig, QdrantStore};
use serde_json::{Value, json};

const KEY: &str = "qdrant-test-key-0123";

fn config(server: &MockServer) -> QdrantConfig {
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    QdrantConfig::new(server.base_url(), "docs")
        .api_key(KEY)
        .http_client(http)
}

fn store(server: &MockServer) -> QdrantStore {
    QdrantStore::new(config(server)).unwrap()
}

fn ok(result: &Value) -> MockResponse {
    MockResponse::json(
        200,
        json!({ "result": result, "status": "ok", "time": 0.001 }).to_string(),
    )
}

fn missing() -> MockResponse {
    MockResponse::json(
        404,
        r#"{"status":{"error":"Not found: Collection `docs` doesn't exist!"},"time":0.0}"#,
    )
}

fn info(size: usize, distance: &str) -> MockResponse {
    ok(&json!({
        "status": "green",
        "points_count": 0,
        "config": { "params": { "vectors": { "size": size, "distance": distance } } }
    }))
}

fn uuid(id: &str) -> String {
    PointId::from_record_id(id).to_string()
}

fn assert_auth(req: &RecordedRequest) {
    assert_eq!(req.header("api-key"), Some(KEY));
    assert!(!req.path.contains(KEY));
}

fn point(id: &str, score: f64, content: &str, meta: &Value, vector: Option<&[f32]>) -> Value {
    let mut p = json!({
        "id": uuid(id),
        "version": 1,
        "score": score,
        "payload": { "page_content": content, "metadata": meta, "doc_id": id },
    });
    if let Some(v) = vector {
        p["vector"] = json!(v);
    }
    p
}

#[tokio::test]
async fn upsert_creates_the_collection_and_writes_points() {
    let server = MockServer::start([
        missing(),
        ok(&json!(true)),
        ok(&json!({"status": "completed"})),
    ])
    .unwrap();
    let s = QdrantStore::new(
        config(&server)
            .on_disk_payload(true)
            .metric(Metric::DotProduct),
    )
    .unwrap();
    s.upsert(vec![
        Record::new("doc-1", vec![1.0, 0.0, 0.5])
            .with_content("Rust")
            .with_meta("year", 2015)
            .with_meta("tags", json!(["lang"])),
        Record::new("42", vec![0.0, 1.0, 0.0]),
    ])
    .await
    .unwrap();

    let reqs = server.finish().unwrap();
    assert_eq!(reqs.len(), 3);
    for r in &reqs {
        assert_auth(r);
    }
    assert_eq!(
        (reqs[0].method.as_str(), reqs[0].path.as_str()),
        ("GET", "/collections/docs")
    );
    assert_eq!(
        (reqs[1].method.as_str(), reqs[1].path.as_str()),
        ("PUT", "/collections/docs")
    );
    assert_eq!(
        reqs[1].json().unwrap(),
        json!({ "vectors": { "size": 3, "distance": "Dot" }, "on_disk_payload": true })
    );
    assert_eq!(
        (reqs[2].method.as_str(), reqs[2].path.as_str()),
        ("PUT", "/collections/docs/points?wait=true")
    );
    assert_eq!(reqs[2].header("content-type"), Some("application/json"));
    assert_eq!(
        reqs[2].json().unwrap(),
        json!({ "points": [
            {
                "id": "b078ced4-e7d0-548d-a825-d9133395950e",
                "vector": [1.0, 0.0, 0.5],
                "payload": {
                    "page_content": "Rust",
                    "metadata": { "tags": ["lang"], "year": 2015 },
                    "doc_id": "doc-1"
                }
            },
            {
                "id": 42,
                "vector": [0.0, 1.0, 0.0],
                "payload": { "page_content": "", "metadata": {}, "doc_id": "42" }
            }
        ]})
    );
}

#[tokio::test]
async fn upserts_are_batched_by_count_and_by_size() {
    let records: Vec<Record> = (0..5)
        .map(|i| {
            Record::new(
                format!("r{i}"),
                vec![1.0, f32::from(u8::try_from(i).unwrap())],
            )
        })
        .collect();

    // By count: 2 + 2 + 1.
    let server = MockServer::start([
        info(2, "Cosine"),
        ok(&json!({})),
        ok(&json!({})),
        ok(&json!({})),
    ])
    .unwrap();
    let s = QdrantStore::new(config(&server).batch_size(2)).unwrap();
    s.upsert(records.clone()).await.unwrap();
    let reqs = server.finish().unwrap();
    let sizes: Vec<usize> = reqs[1..]
        .iter()
        .map(|r| r.json().unwrap()["points"].as_array().unwrap().len())
        .collect();
    assert_eq!(sizes, [2, 2, 1]);
    let ids: Vec<Value> = reqs[1..]
        .iter()
        .flat_map(|r| r.json().unwrap()["points"].as_array().unwrap().clone())
        .map(|p| p["payload"]["doc_id"].clone())
        .collect();
    assert_eq!(ids, ["r0", "r1", "r2", "r3", "r4"]);

    // By size: each point is about 120 bytes, so a 300-byte cap fits two.
    let server = MockServer::start([
        info(2, "Cosine"),
        ok(&json!({})),
        ok(&json!({})),
        ok(&json!({})),
    ])
    .unwrap();
    let s = QdrantStore::new(config(&server).max_batch_bytes(300)).unwrap();
    s.upsert(records.clone()).await.unwrap();
    let reqs = server.finish().unwrap();
    for r in &reqs[1..] {
        assert!(r.body.len() <= 300, "{}", r.body.len());
        assert!(r.json().is_ok());
    }
    let total: usize = reqs[1..]
        .iter()
        .map(|r| r.json().unwrap()["points"].as_array().unwrap().len())
        .sum();
    assert_eq!(total, 5);

    // A single point above the cap is refused before anything is written.
    let server = MockServer::start([info(2, "Cosine")]).unwrap();
    let s = QdrantStore::new(config(&server).max_batch_bytes(40)).unwrap();
    let err = s.upsert(records).await.unwrap_err();
    assert!(
        matches!(err, StoreError::LimitExceeded { limit: 40, .. }),
        "{err:?}"
    );
    assert_eq!(server.finish().unwrap().len(), 1);
}

#[tokio::test]
async fn bad_records_fail_before_any_request() {
    let server = MockServer::start([]).unwrap();
    let s = store(&server);
    let cases = [
        (vec![Record::new("", vec![1.0])], StoreError::EmptyId),
        (
            vec![Record::new("a", vec![1.0]), Record::new("a", vec![2.0])],
            StoreError::DuplicateId("a".into()),
        ),
        (
            vec![
                Record::new("a", vec![1.0, 2.0]),
                Record::new("b", vec![1.0]),
            ],
            StoreError::DimensionMismatch {
                expected: 2,
                actual: 1,
            },
        ),
        (
            vec![Record::new("a", vec![f32::NAN])],
            StoreError::InvalidVector("vector contains NaN or infinity"),
        ),
        (
            vec![Record::new("a", vec![0.0, 0.0])],
            StoreError::InvalidVector("zero vector has no direction under the cosine metric"),
        ),
        (
            vec![Record::new("a", vec![])],
            StoreError::InvalidVector("vector is empty"),
        ),
    ];
    for (records, want) in cases {
        assert_eq!(s.upsert(records).await.unwrap_err(), want);
    }
    assert!(server.finish().unwrap().is_empty());
}

#[tokio::test]
async fn query_translates_the_filter_and_decodes_hits() {
    let meta = json!({ "lang": "en", "year": 2021 });
    let server = MockServer::start([
        info(2, "Cosine"),
        ok(&json!({ "points": [
            point("b", 0.8, "Bee", &meta, Some(&[0.6, 0.8])),
            point("a", 0.9, "Ay", &meta, Some(&[1.0, 0.0])),
            point("low", 0.1, "Low", &meta, None),
        ]})),
    ])
    .unwrap();
    let s = store(&server);
    let q = Query::new(vec![1.0, 0.0], 3)
        .with_filter(Filter::eq("lang", "en").and(!Filter::lt("year", 2020)))
        .with_min_score(0.5)
        .with_ef_search(128);
    let hits = s.query(&q).await.unwrap();
    // Sorted best first; the hit under min_score is dropped even if the
    // server returned it.
    let ids: Vec<&str> = hits.iter().map(|h| h.record.id.as_str()).collect();
    assert_eq!(ids, ["a", "b"]);
    assert!((hits[0].score - 0.9).abs() < 1e-6);
    assert_eq!(hits[0].record.content, "Ay");
    assert_eq!(hits[0].record.vector, [1.0, 0.0]);
    assert_eq!(hits[0].record.metadata["year"], 2021);

    let reqs = server.finish().unwrap();
    assert_eq!(reqs[1].path, "/collections/docs/points/query");
    assert_eq!(
        reqs[1].json().unwrap(),
        json!({
            "query": [1.0, 0.0],
            "limit": 3,
            "with_payload": true,
            "with_vector": true,
            "score_threshold": 0.5,
            "params": { "hnsw_ef": 128 },
            "filter": { "must": [
                { "key": "metadata.lang", "match": { "value": "en" } },
                { "must_not": [{ "key": "metadata.year", "range": { "lt": 2020 } }] },
            ]}
        })
    );
}

#[tokio::test]
async fn euclidean_scores_are_negated_distances() {
    let server = MockServer::start([
        info(2, "Euclid"),
        ok(&json!({ "points": [
            point("near", 1.0, "", &json!({}), None),
            point("far", 3.0, "", &json!({}), None),
        ]})),
    ])
    .unwrap();
    let s = QdrantStore::new(config(&server).metric(Metric::Euclidean)).unwrap();
    let q = Query::new(vec![0.0, 0.0], 5)
        .with_min_score(-2.0)
        .with_vectors(false);
    let hits = s.query(&q).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].record.id, "near");
    assert!((hits[0].score + 1.0).abs() < 1e-6);
    assert!(hits[0].record.vector.is_empty());
    // A positive min_score can never pass: no request is sent.
    assert!(
        s.query(&q.clone().with_min_score(0.5))
            .await
            .unwrap()
            .is_empty()
    );

    let reqs = server.finish().unwrap();
    assert_eq!(reqs.len(), 2);
    let body = reqs[1].json().unwrap();
    assert_eq!(body["score_threshold"], 2.0);
    assert_eq!(body["with_vector"], false);
}

#[tokio::test]
async fn named_vectors() {
    let server = MockServer::start([
        ok(&json!({ "config": { "params": { "vectors": {
            "dense": { "size": 2, "distance": "Cosine" }
        }}}})),
        ok(&json!({})),
        ok(&json!({ "points": [{
            "id": uuid("a"), "score": 1.0,
            "payload": { "page_content": "A", "metadata": {}, "doc_id": "a" },
            "vector": { "dense": [1.0, 0.0] }
        }]})),
    ])
    .unwrap();
    let s = QdrantStore::new(config(&server).vector_name("dense")).unwrap();
    s.upsert(vec![Record::new("a", vec![1.0, 0.0])])
        .await
        .unwrap();
    let hits = s.query(&Query::new(vec![1.0, 0.0], 1)).await.unwrap();
    assert_eq!(hits[0].record.vector, [1.0, 0.0]);
    let reqs = server.finish().unwrap();
    assert_eq!(
        reqs[1].json().unwrap()["points"][0]["vector"],
        json!({ "dense": [1.0, 0.0] })
    );
    assert_eq!(reqs[2].json().unwrap()["using"], "dense");
}

#[tokio::test]
async fn existing_collection_must_match_the_config() {
    let server = MockServer::start([info(3, "Euclid")]).unwrap();
    let err = store(&server)
        .upsert(vec![Record::new("a", vec![1.0, 0.0, 0.0])])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Euclid distance"), "{err}");
    server.finish().unwrap();

    let server = MockServer::start([info(3, "Cosine")]).unwrap();
    let err = store(&server)
        .upsert(vec![Record::new("a", vec![1.0, 0.0])])
        .await
        .unwrap_err();
    assert_eq!(
        err,
        StoreError::DimensionMismatch {
            expected: 3,
            actual: 2
        }
    );
    server.finish().unwrap();

    let server = MockServer::start([ok(&json!({ "config": { "params": { "vectors": {
        "dense": { "size": 3, "distance": "Cosine" }
    }}}}))])
    .unwrap();
    let err = store(&server).ensure_collection().await.unwrap_err();
    assert!(err.to_string().contains("vector_name"), "{err}");
    server.finish().unwrap();
}

#[tokio::test]
async fn reads_on_a_missing_collection_are_empty() {
    let server =
        MockServer::start([missing(), missing(), missing(), missing(), missing()]).unwrap();
    let s = store(&server);
    assert!(s.query(&Query::new(vec![1.0], 3)).await.unwrap().is_empty());
    assert_eq!(s.len().await.unwrap(), 0);
    assert_eq!(s.get("a").await.unwrap(), None);
    assert_eq!(s.delete(&["a"]).await.unwrap(), 0);
    // Malformed queries are still rejected.
    assert!(
        s.query(&Query::new(vec![1.0], 3).with_min_score(f32::NAN))
            .await
            .is_err()
    );
    // Without a known size the collection cannot be created.
    let err = s.ensure_collection().await.unwrap_err();
    assert!(err.to_string().contains("dimension"), "{err}");
    server.finish().unwrap();
}

#[tokio::test]
async fn get_delete_count() {
    let server = MockServer::start([
        info(2, "Cosine"),
        // get
        ok(&json!([{
            "id": uuid("a"),
            "payload": { "page_content": "A", "metadata": { "k": 1 }, "doc_id": "a" },
            "vector": [0.6, 0.8]
        }])),
        // delete: one of the two ids exists
        ok(&json!([{ "id": uuid("a") }])),
        ok(&json!({ "status": "completed" })),
        // delete_where: count, then delete
        ok(&json!({ "count": 7 })),
        ok(&json!({ "status": "completed" })),
        // len
        ok(&json!({ "count": 3 })),
    ])
    .unwrap();
    let s = store(&server);
    let rec = s.get("a").await.unwrap().unwrap();
    assert_eq!(rec.content, "A");
    assert_eq!(rec.vector, [0.6, 0.8]);
    assert_eq!(rec.metadata["k"], 1);

    assert_eq!(s.delete(&["a", "zz", "a", ""]).await.unwrap(), 1);
    assert_eq!(s.delete_where(&Filter::eq("k", 1)).await.unwrap(), 7);
    assert_eq!(s.len().await.unwrap(), 3);
    // Nothing can match: answered without a request.
    assert_eq!(s.delete_where(&Filter::Or(vec![])).await.unwrap(), 0);

    let reqs = server.finish().unwrap();
    assert_eq!(reqs[1].path, "/collections/docs/points");
    assert_eq!(
        reqs[1].json().unwrap(),
        json!({ "ids": [uuid("a")], "with_payload": true, "with_vector": true })
    );
    assert_eq!(
        reqs[2].json().unwrap(),
        json!({ "ids": [uuid("a"), uuid("zz")], "with_payload": false, "with_vector": false })
    );
    assert_eq!(reqs[3].path, "/collections/docs/points/delete?wait=true");
    assert_eq!(reqs[3].json().unwrap(), json!({ "points": [uuid("a")] }));
    assert_eq!(reqs[4].path, "/collections/docs/points/count");
    assert_eq!(
        reqs[4].json().unwrap(),
        json!({ "exact": true, "filter": { "must": [
            { "key": "metadata.k", "range": { "gte": 1, "lte": 1 } }
        ]}})
    );
    assert_eq!(
        reqs[5].json().unwrap(),
        json!({ "filter": { "must": [{ "key": "metadata.k", "range": { "gte": 1, "lte": 1 } }] } })
    );
    assert_eq!(reqs[6].json().unwrap(), json!({ "exact": true }));
}

#[tokio::test]
async fn get_ignores_a_foreign_point_with_the_same_id() {
    let server = MockServer::start([
        info(1, "Cosine"),
        ok(&json!([{ "id": 7, "payload": { "doc_id": "seven" }, "vector": [1.0] }])),
    ])
    .unwrap();
    assert_eq!(store(&server).get("7").await.unwrap(), None);
    server.finish().unwrap();
}

#[tokio::test]
async fn query_batch_skips_queries_that_cannot_match() {
    let server = MockServer::start([
        info(2, "Cosine"),
        ok(&json!([
            { "points": [point("a", 0.9, "", &json!({}), None)] },
            { "points": [] },
        ])),
    ])
    .unwrap();
    let s = store(&server);
    let queries = [
        Query::new(vec![1.0, 0.0], 1),
        Query::new(vec![1.0, 0.0], 0),
        Query::new(vec![0.0, 1.0], 2),
    ];
    let out = s.query_batch(&queries).await.unwrap();
    assert_eq!(out.len(), 3);
    assert_eq!(out[0][0].record.id, "a");
    assert!(out[1].is_empty() && out[2].is_empty());
    let reqs = server.finish().unwrap();
    assert_eq!(reqs[1].path, "/collections/docs/points/query/batch");
    let searches = &reqs[1].json().unwrap()["searches"];
    assert_eq!(searches.as_array().unwrap().len(), 2);
    assert_eq!(searches[1]["limit"], 2);
}

#[tokio::test]
async fn errors_are_mapped_and_scrubbed() {
    let server = MockServer::start([
        info(2, "Cosine"),
        MockResponse::json(
            400,
            r#"{"status":{"error":"Wrong input: Vector dimension error: expected dim: 2, got 3"},"time":0.0}"#,
        ),
        MockResponse::json(
            403,
            format!(r#"{{"status":{{"error":"key {KEY} is not allowed"}},"time":0.0}}"#),
        ),
        MockResponse::new(500, "text/plain", "boom"),
        MockResponse::json(200, "not json"),
    ])
    .unwrap();
    let s = store(&server);
    let q = Query::new(vec![1.0, 0.0], 1);
    assert_eq!(
        s.query(&q).await.unwrap_err(),
        StoreError::DimensionMismatch {
            expected: 2,
            actual: 3
        }
    );
    let e = s.query(&q).await.unwrap_err().to_string();
    assert!(
        e.contains("HTTP 403") && e.contains("[REDACTED]") && !e.contains(KEY),
        "{e}"
    );
    let e = s.query(&q).await.unwrap_err().to_string();
    assert!(e.contains("HTTP 500") && e.contains("boom"), "{e}");
    let e = s.query(&q).await.unwrap_err().to_string();
    assert!(e.contains("invalid JSON"), "{e}");
    server.finish().unwrap();
}

#[tokio::test]
async fn rate_limits_are_retried() {
    let server = MockServer::start([
        info(2, "Cosine"),
        MockResponse::json(429, r#"{"status":{"error":"too many"}}"#)
            .with_header("Retry-After", "0"),
        MockResponse::json(503, "{}").with_header("Retry-After", "0"),
        ok(&json!({ "count": 5 })),
    ])
    .unwrap();
    let s = QdrantStore::new(config(&server).max_retries(2)).unwrap();
    assert_eq!(s.len().await.unwrap(), 5);
    assert_eq!(server.finish().unwrap().len(), 4);

    let server = MockServer::start([
        info(2, "Cosine"),
        MockResponse::json(429, r#"{"status":{"error":"too many"}}"#)
            .with_header("Retry-After", "0"),
    ])
    .unwrap();
    let s = QdrantStore::new(config(&server).max_retries(0)).unwrap();
    let e = s.len().await.unwrap_err().to_string();
    assert!(e.contains("rate limiting") && e.contains("too many"), "{e}");
    server.finish().unwrap();
}

#[tokio::test]
async fn responses_are_size_capped() {
    let big = json!({ "points": [point("a", 1.0, &"x".repeat(10_000), &json!({}), None)] });
    let server = MockServer::start([info(2, "Cosine"), ok(&big)]).unwrap();
    let s = QdrantStore::new(config(&server).max_response_bytes(4096)).unwrap();
    let err = s.query(&Query::new(vec![1.0, 0.0], 1)).await.unwrap_err();
    assert!(
        matches!(err, StoreError::LimitExceeded { limit: 4096, .. }),
        "{err:?}"
    );
    server.finish().unwrap();
}

#[tokio::test]
async fn untranslatable_filters_are_errors() {
    let server = MockServer::start([]).unwrap();
    let s = store(&server);
    let q = Query::new(vec![1.0, 0.0], 1).with_filter(Filter::eq("tags", json!(["a", "b"])));
    assert!(matches!(
        s.query(&q).await.unwrap_err(),
        StoreError::InvalidFilter(_)
    ));
    assert!(matches!(
        s.count(&Filter::gt("name", "m")).await.unwrap_err(),
        StoreError::InvalidFilter(_)
    ));
    // Refused before any request.
    assert!(server.finish().unwrap().is_empty());
}

#[tokio::test]
async fn timeouts_are_reported() {
    // A listener that accepts but never answers.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let s = QdrantStore::new(
        QdrantConfig::new(url, "docs")
            .timeout(Duration::from_millis(200))
            .max_retries(0),
    )
    .unwrap();
    let e = s.len().await.unwrap_err().to_string();
    assert!(e.contains("timed out"), "{e}");
    drop(listener);
}

#[test]
fn debug_never_shows_the_key() {
    let s = QdrantStore::new(QdrantConfig::new("https://x.example", "docs").api_key(KEY)).unwrap();
    let d = format!("{s:?}");
    assert!(!d.contains(KEY) && d.contains("[REDACTED]"), "{d}");
    assert!(QdrantStore::new(QdrantConfig::new("http://x.example", "docs").api_key(KEY)).is_err());
}
