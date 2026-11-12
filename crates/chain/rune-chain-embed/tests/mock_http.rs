//! End-to-end tests against a loopback mock HTTP server: the clients build
//! real requests and decode recorded responses. No test touches the network.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::time::{Duration, Instant};

use rune_chain_core::testing::http::{MockResponse, MockServer, RecordedRequest};
use rune_chain_embed::{
    CacheBackedEmbedder, CohereEmbedder, EmbedError, Embedder, EncodingFormat, JinaEmbedder,
    LruStore, OpenAiEmbedder, VoyageEmbedder,
};
use serde_json::json;

const KEY: &str = "sk-test-secret-key";

fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

fn client(server: &MockServer) -> OpenAiEmbedder {
    OpenAiEmbedder::new(KEY)
        .base_url(format!("{}/v1/", server.base_url()))
        .http_client(http())
        .retry_base_delay(Duration::from_millis(1))
}

async fn finish(server: MockServer) -> Vec<RecordedRequest> {
    tokio::task::spawn_blocking(move || server.finish())
        .await
        .unwrap()
        .unwrap()
}

fn assert_embeddings_request(req: &RecordedRequest) {
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/v1/embeddings");
    assert_eq!(
        req.header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
    assert_eq!(req.header("content-type"), Some("application/json"));
}

fn response<const N: usize>(items: &[(usize, [f32; N])]) -> MockResponse {
    let data: Vec<_> = items
        .iter()
        .map(|(index, v)| json!({ "object": "embedding", "index": index, "embedding": v.as_slice() }))
        .collect();
    MockResponse::json(
        200,
        json!({
            "object": "list",
            "data": data,
            "model": "text-embedding-3-small",
            "usage": { "prompt_tokens": 4, "total_tokens": 4 }
        })
        .to_string(),
    )
}

#[tokio::test]
async fn embed_batch_sends_request_and_restores_order() {
    let server = MockServer::start([
        response(&[(1, [0.5, -0.5]), (0, [0.25, 0.75])]),
        response(&[(0, [1.0, 0.0])]),
    ])
    .unwrap();
    let embedder = client(&server)
        .model("text-embedding-3-large")
        .dimensions(2);
    assert_eq!(
        embedder.embed_batch(&["a", "b"]).await.unwrap(),
        vec![vec![0.25, 0.75], vec![0.5, -0.5]]
    );
    assert_eq!(embedder.embed("c").await.unwrap(), vec![1.0, 0.0]);

    let requests = finish(server).await;
    assert_eq!(requests.len(), 2);
    requests.iter().for_each(assert_embeddings_request);
    assert_eq!(
        requests[0].json().unwrap(),
        json!({ "model": "text-embedding-3-large", "input": ["a", "b"], "dimensions": 2 })
    );
    assert_eq!(requests[1].json().unwrap()["input"], json!(["c"]));
}

#[tokio::test]
async fn large_batches_are_split_in_order() {
    let server = MockServer::start([
        response(&[(0, [0.0]), (1, [1.0])]),
        response(&[(0, [2.0]), (1, [3.0])]),
        response(&[(0, [4.0])]),
    ])
    .unwrap();
    let embedder = client(&server).max_batch_size(2).max_concurrency(1);
    assert_eq!(
        embedder
            .embed_documents(&["a", "b", "c", "d", "e"])
            .await
            .unwrap(),
        vec![vec![0.0], vec![1.0], vec![2.0], vec![3.0], vec![4.0]]
    );
    let inputs: Vec<_> = finish(server)
        .await
        .iter()
        .map(|r| r.json().unwrap()["input"].clone())
        .collect();
    assert_eq!(
        inputs,
        vec![json!(["a", "b"]), json!(["c", "d"]), json!(["e"])]
    );
}

#[tokio::test]
async fn base64_encoding_is_requested_and_decoded() {
    let raw: Vec<u8> = [0.5f32, -1.0]
        .iter()
        .flat_map(|f| f.to_le_bytes())
        .collect();
    let body = json!({ "data": [{ "index": 0, "embedding": rune_base64::encode(&raw) }] });
    let server = MockServer::start([MockResponse::json(200, body.to_string())]).unwrap();
    let embedder = client(&server).encoding_format(EncodingFormat::Base64);
    assert_eq!(embedder.embed("x").await.unwrap(), vec![0.5, -1.0]);
    assert_eq!(
        finish(server).await[0].json().unwrap()["encoding_format"],
        "base64"
    );
}

#[tokio::test]
async fn short_response_is_invalid() {
    let server = MockServer::start([response(&[(0, [0.0, 1.0])])]).unwrap();
    let err = client(&server).embed_batch(&["a", "b"]).await.unwrap_err();
    assert!(
        matches!(err, EmbedError::InvalidResponse(ref m) if m.contains("expected 2")),
        "{err:?}"
    );
}

#[tokio::test]
async fn dimension_mismatches_are_errors_not_panics() {
    let server = MockServer::start([
        response(&[(0, [1.0, 2.0])]),
        MockResponse::json(
            200,
            json!({ "data": [
                { "index": 0, "embedding": [1.0, 2.0] },
                { "index": 1, "embedding": [1.0] }
            ]})
            .to_string(),
        ),
    ])
    .unwrap();
    let configured = client(&server).dimensions(3);
    assert!(matches!(
        configured.embed("a").await,
        Err(EmbedError::DimensionMismatch {
            expected: 3,
            actual: 2
        })
    ));
    assert!(matches!(
        client(&server).embed_batch(&["a", "b"]).await,
        Err(EmbedError::DimensionMismatch {
            expected: 2,
            actual: 1
        })
    ));
}

#[tokio::test]
async fn http_errors_map_to_provider_and_request_errors() {
    let server = MockServer::start([
        MockResponse::json(
            401,
            format!(
                r#"{{"error":{{"message":"Incorrect API key provided: {KEY}.","type":"invalid_request_error"}}}}"#
            ),
        ),
        MockResponse::new(502, "text/plain", "502 Bad Gateway"),
    ])
    .unwrap();
    let embedder = client(&server).max_retries(0);
    let err = embedder.embed("x").await.unwrap_err();
    assert!(
        matches!(&err, EmbedError::ProviderError(m)
            if m == "Incorrect API key provided: [REDACTED]. (HTTP 401)"),
        "{err:?}"
    );
    assert!(!err.to_string().contains(KEY));
    assert!(matches!(
        embedder.embed("x").await,
        Err(EmbedError::RequestFailed(m)) if m == "HTTP 502: 502 Bad Gateway"
    ));
}

#[tokio::test]
async fn long_error_bodies_are_truncated() {
    let server = MockResponse::new(400, "text/plain", "x".repeat(100_000));
    let server = MockServer::start([server]).unwrap();
    let err = client(&server).embed("x").await.unwrap_err();
    let EmbedError::RequestFailed(m) = err else {
        panic!("{err:?}")
    };
    assert!(m.len() < 700 && m.ends_with("[truncated]"), "{}", m.len());
}

#[tokio::test]
async fn retries_429_and_5xx_honouring_retry_after() {
    let server = MockServer::start([
        MockResponse::json(429, r#"{"error":{"message":"slow down"}}"#)
            .with_header("Retry-After", "0"),
        MockResponse::new(503, "text/plain", "busy").with_header("retry-after-ms", "1"),
        response(&[(0, [7.0])]),
    ])
    .unwrap();
    assert_eq!(client(&server).embed("x").await.unwrap(), vec![7.0]);
    assert_eq!(finish(server).await.len(), 3);
}

#[tokio::test]
async fn retries_are_bounded_and_long_retry_after_is_not_waited_for() {
    let server = MockServer::start([
        MockResponse::new(500, "text/plain", "e1"),
        MockResponse::new(500, "text/plain", "e2"),
        MockResponse::json(429, r#"{"error":{"message":"quota"}}"#)
            .with_header("Retry-After", "3600"),
    ])
    .unwrap();
    let embedder = client(&server).max_retries(1);
    assert!(matches!(
        embedder.embed("x").await,
        Err(EmbedError::RequestFailed(m)) if m == "HTTP 500: e2"
    ));
    let started = Instant::now();
    assert!(matches!(
        embedder.embed("x").await,
        Err(EmbedError::ProviderError(m)) if m == "quota (HTTP 429)"
    ));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(finish(server).await.len(), 3);
}

#[tokio::test]
async fn response_size_is_capped() {
    let big: Vec<[f32; 64]> = vec![[0.123_456_7; 64]; 4];
    let items: Vec<(usize, [f32; 64])> = big.into_iter().enumerate().collect();
    let server = MockServer::start([response(&items)]).unwrap();
    let err = client(&server)
        .max_response_bytes(1024)
        .embed_batch(&["a", "b", "c", "d"])
        .await
        .unwrap_err();
    assert!(
        matches!(&err, EmbedError::InvalidResponse(m) if m.contains("1024-byte limit")),
        "{err:?}"
    );
}

#[tokio::test]
async fn requests_time_out() {
    // Accepts connections (via the backlog) but never answers.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/v1", listener.local_addr().unwrap());
    let embedder = OpenAiEmbedder::new(KEY)
        .base_url(url)
        .http_client(http())
        .timeout(Duration::from_millis(200))
        .max_retries(0);
    let started = Instant::now();
    assert!(matches!(
        embedder.embed("x").await,
        Err(EmbedError::RequestFailed(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(listener);
}

#[tokio::test]
async fn cache_skips_the_network_for_hits() {
    let server =
        MockServer::start([response(&[(0, [1.0]), (1, [2.0])]), response(&[(0, [3.0])])]).unwrap();
    let cached = CacheBackedEmbedder::new(client(&server), LruStore::new(100)).unwrap();
    assert_eq!(cached.namespace(), "text-embedding-3-small");
    cached.embed_batch(&["a", "b"]).await.unwrap();
    assert_eq!(
        cached.embed_batch(&["b", "c", "a"]).await.unwrap(),
        vec![vec![2.0], vec![3.0], vec![1.0]]
    );
    let requests = finish(server).await;
    assert_eq!(requests[1].json().unwrap()["input"], json!(["c"]));
}

#[tokio::test]
async fn cohere_sends_input_types_and_decodes() {
    let reply = |v: serde_json::Value| {
        MockResponse::json(
            200,
            json!({ "id": "x", "embeddings": { "float": v }, "response_type": "embeddings_by_type" })
                .to_string(),
        )
    };
    let server = MockServer::start([
        reply(json!([[1.0, 0.0], [0.0, 1.0]])),
        reply(json!([[0.5, 0.5]])),
    ])
    .unwrap();
    let embedder = CohereEmbedder::new(KEY)
        .base_url(server.base_url())
        .http_client(http())
        .dimensions(2);
    assert_eq!(
        embedder.embed_documents(&["a", "b"]).await.unwrap(),
        vec![vec![1.0, 0.0], vec![0.0, 1.0]]
    );
    assert_eq!(embedder.embed_query("q").await.unwrap(), vec![0.5, 0.5]);
    let requests = finish(server).await;
    assert_eq!(requests[0].path, "/embed");
    assert_eq!(
        requests[0].json().unwrap(),
        json!({
            "model": "embed-v4.0",
            "texts": ["a", "b"],
            "input_type": "search_document",
            "embedding_types": ["float"],
            "output_dimension": 2
        })
    );
    assert_eq!(requests[1].json().unwrap()["input_type"], "search_query");
}

#[tokio::test]
async fn voyage_and_jina_send_query_and_document_types() {
    let server = MockServer::start([
        response(&[(0, [1.0])]),
        response(&[(0, [2.0])]),
        response(&[(0, [3.0])]),
        response(&[(0, [4.0])]),
    ])
    .unwrap();
    let voyage = VoyageEmbedder::new(KEY)
        .base_url(server.base_url())
        .http_client(http());
    let jina = JinaEmbedder::new(KEY)
        .base_url(server.base_url())
        .http_client(http());
    assert_eq!(voyage.embed("q").await.unwrap(), vec![1.0]);
    assert_eq!(voyage.embed_batch(&["d"]).await.unwrap(), vec![vec![2.0]]);
    assert_eq!(jina.embed_query("q").await.unwrap(), vec![3.0]);
    assert_eq!(jina.embed_documents(&["d"]).await.unwrap(), vec![vec![4.0]]);
    let r: Vec<_> = finish(server)
        .await
        .iter()
        .map(|r| r.json().unwrap())
        .collect();
    assert_eq!(
        r[0],
        json!({ "model": "voyage-3.5", "input": ["q"], "input_type": "query" })
    );
    assert_eq!(r[1]["input_type"], "document");
    assert_eq!(
        r[2],
        json!({
            "model": "jina-embeddings-v3",
            "input": ["q"],
            "task": "retrieval.query",
            "embedding_type": "float"
        })
    );
    assert_eq!(r[3]["task"], "retrieval.passage");
}

#[tokio::test]
async fn empty_key_sends_no_authorization() {
    let server = MockServer::start([response(&[(0, [1.0])])]).unwrap();
    let embedder = OpenAiEmbedder::new("")
        .base_url(format!("{}/v1", server.base_url()))
        .http_client(http());
    embedder.embed("x").await.unwrap();
    assert_eq!(finish(server).await[0].header("authorization"), None);
}
