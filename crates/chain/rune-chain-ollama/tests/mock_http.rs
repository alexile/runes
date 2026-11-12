//! End-to-end tests against a loopback mock of Ollama's `/api/chat`: the
//! client builds real HTTP requests and decodes recorded responses. No test
//! touches the network.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use futures::StreamExt;
use rune_chain_core::LlmErrorKind;
use rune_chain_core::testing::check_llm;
use rune_chain_core::testing::http::{MockResponse, MockServer, RecordedRequest};
use rune_chain_core::{
    ContentPart, FunctionDefinition, Llm, Message, MessageContent, ResponseFormat, StreamData,
};
use rune_chain_embed::Embedder;
use rune_chain_ollama::{Ollama, StreamEvent, collect_events};
use serde_json::json;

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/", $name))
    };
}

fn client(server: &MockServer) -> Ollama {
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    Ollama::new()
        .base_url(format!("{}/", server.base_url()))
        .http_client(http)
}

fn assert_chat_request(req: &RecordedRequest) {
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/chat");
    assert_eq!(req.header("content-type"), Some("application/json"));
    assert!(req.header("authorization").is_none());
}

#[test]
fn generate_sends_chat_request_and_decodes_response() {
    let server = MockServer::start([MockResponse::json(200, fixture!("chat.json"))]).unwrap();
    let llm = client(&server)
        .model("llava")
        .temperature(0.1)
        .max_tokens(32);
    let result =
        tokio_test::block_on(llm.generate(&[Message::human(MessageContent::Parts(vec![
            ContentPart::text("Describe"),
            ContentPart::image_base64("image/png", "iVBORw0KGgo="),
        ]))]))
        .unwrap();
    assert_eq!(result.generation, "Hello! How are you today?");
    assert_eq!(result.tokens.unwrap().total_tokens, 324);

    let requests = server.finish().unwrap();
    assert_eq!(requests.len(), 1);
    assert_chat_request(&requests[0]);
    let body = requests[0].json().unwrap();
    assert_eq!(body["model"], "llava");
    assert_eq!(body["stream"], false);
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], "Describe");
    assert_eq!(body["messages"][0]["images"], json!(["iVBORw0KGgo="]));
    assert_eq!(body["options"]["num_predict"], 32);
    assert!((body["options"]["temperature"].as_f64().unwrap() - 0.1).abs() < 1e-6);
}

#[test]
fn stream_assembles_chunked_ndjson() {
    let server =
        MockServer::start([MockResponse::ndjson(fixture!("stream.ndjson")).chunked(5)]).unwrap();
    let llm = client(&server);
    let chunks: Vec<StreamData> = tokio_test::block_on(async {
        let stream = llm
            .stream(&[Message::human("Why is the sky blue?")])
            .await
            .unwrap();
        stream.map(Result::unwrap).collect().await
    });
    let contents: Vec<&str> = chunks.iter().map(|c| c.content.as_str()).collect();
    assert_eq!(contents, ["The", " sky", ""]);
    assert!(chunks.last().unwrap().is_finished);

    let requests = server.finish().unwrap();
    assert_chat_request(&requests[0]);
    assert_eq!(requests[0].json().unwrap()["stream"], true);
}

#[test]
fn http_errors_map_to_classified_errors() {
    let server = MockServer::start([
        MockResponse::json(404, fixture!("error_model_not_found.json")),
        MockResponse::new(500, "text/plain", "boom"),
    ])
    .unwrap();
    let llm = client(&server).model("llama9");
    let msgs = [Message::human("Hi")];
    tokio_test::block_on(async {
        assert!(matches!(
            llm.generate(&msgs).await,
            Err(m) if m.kind() == LlmErrorKind::InvalidRequest && m.status() == Some(404) && m.message().contains("not found")
        ));
        assert!(matches!(
            llm.stream(&msgs).await.map(drop),
            Err(m) if m.kind() == LlmErrorKind::Server && m.message() == "boom"
        ));
    });
    assert_eq!(server.finish().unwrap().len(), 2);
}

#[test]
fn passes_the_llm_contract() {
    // generate, generate(&[]), generate_with_tools, stream.
    let server = MockServer::start([
        MockResponse::json(200, fixture!("chat.json")),
        MockResponse::json(200, fixture!("chat.json")),
        MockResponse::json(200, fixture!("chat.json")),
        MockResponse::ndjson(fixture!("stream.ndjson")).chunked(3),
    ])
    .unwrap();
    tokio_test::block_on(check_llm(&client(&server))).unwrap();
    let requests = server.finish().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[2].json().unwrap()["tools"][0]["function"]["name"],
        "echo"
    );
    requests.iter().for_each(assert_chat_request);
}

fn weather() -> FunctionDefinition {
    FunctionDefinition::new(
        "get_weather",
        "Weather for a city.",
        json!({ "type": "object", "properties": { "city": { "type": "string" } } }),
    )
}

#[test]
fn tool_calls_round_trip_with_bearer_token() {
    let server =
        MockServer::start([MockResponse::json(200, fixture!("chat_tool_calls.json"))]).unwrap();
    let llm = client(&server).bearer_token("proxy-token-1234");
    let result = tokio_test::block_on(llm.generate_with_tools(
        &[Message::human("Weather in Oslo?")],
        &[weather()],
        None,
    ))
    .unwrap();
    assert_eq!(result.tool_calls.len(), 2);
    assert_eq!(result.tool_calls[0].name, "get_weather");

    let requests = server.finish().unwrap();
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer proxy-token-1234")
    );
    let body = requests[0].json().unwrap();
    assert_eq!(body["tools"][0]["type"], "function");
    assert_eq!(body["stream"], false);
}

#[test]
fn stream_events_assemble_tool_calls_and_thinking() {
    let server =
        MockServer::start([MockResponse::ndjson(fixture!("stream_tool_calls.ndjson")).chunked(7)])
            .unwrap();
    let llm = client(&server).model("qwen3");
    let (thinking, result) = tokio_test::block_on(async {
        let events = llm
            .stream_events(&[Message::human("Weather?")], &[weather()], None)
            .await
            .unwrap();
        let all: Vec<_> = events.collect().await;
        let thinking = all
            .iter()
            .filter(|e| matches!(e, Ok(StreamEvent::Thinking(_))))
            .count();
        let result = collect_events(futures::stream::iter(all)).await.unwrap();
        (thinking, result)
    });
    assert_eq!(thinking, 1);
    assert_eq!(result.generation, "Checking.");
    let ids: Vec<&str> = result.tool_calls.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["call_0", "call_xyz"]);
    let requests = server.finish().unwrap();
    assert_eq!(requests[0].json().unwrap()["stream"], true);
}

#[test]
fn structured_output_sends_schema_as_format() {
    let server = MockServer::start([MockResponse::json(
        200,
        r#"{"message":{"role":"assistant","content":"{\"city\":\"Paris\"}"},"done":true}"#,
    )])
    .unwrap();
    let schema = json!({ "type": "object", "properties": { "city": { "type": "string" } } });
    let format = ResponseFormat::json_schema("capital", schema.clone());
    let out = tokio_test::block_on(
        client(&server).generate_structured(&[Message::human("Capital of France?")], &format),
    )
    .unwrap();
    assert_eq!(format.parse_json(&out.generation).unwrap()["city"], "Paris");
    let requests = server.finish().unwrap();
    assert_eq!(requests[0].json().unwrap()["format"], schema);
}

#[test]
fn embeddings_use_batch_endpoint() {
    let server = MockServer::start([MockResponse::json(200, fixture!("embed.json"))]).unwrap();
    let llm = client(&server).model("nomic-embed-text");
    let vectors = tokio_test::block_on(llm.embed_batch(&["a", "b"])).unwrap();
    assert_eq!(vectors.len(), 2);
    let requests = server.finish().unwrap();
    assert_eq!(requests[0].path, "/api/embed");
    assert_eq!(
        requests[0].json().unwrap(),
        json!({ "model": "nomic-embed-text", "input": ["a", "b"] })
    );
}

#[test]
fn model_management_endpoints() {
    let server = MockServer::start([
        MockResponse::json(200, fixture!("tags.json")),
        MockResponse::json(200, fixture!("show.json")),
        MockResponse::ndjson(fixture!("pull.ndjson")).chunked(11),
    ])
    .unwrap();
    let llm = client(&server);
    tokio_test::block_on(async {
        let models = llm.list_models().await.unwrap();
        assert_eq!(models[0].name, "llama3.2:latest");
        let info = llm.show_model("llama3.2").await.unwrap();
        assert!(info.supports("tools"));
        let progress: Vec<_> = llm
            .pull_model("llama3.2")
            .await
            .unwrap()
            .map(Result::unwrap)
            .collect()
            .await;
        assert!(progress.last().unwrap().is_success());
    });
    let requests = server.finish().unwrap();
    assert_eq!(
        (requests[0].method.as_str(), requests[0].path.as_str()),
        ("GET", "/api/tags")
    );
    assert_eq!(requests[1].path, "/api/show");
    assert_eq!(requests[1].json().unwrap(), json!({ "model": "llama3.2" }));
    assert_eq!(requests[2].path, "/api/pull");
    assert_eq!(
        requests[2].json().unwrap(),
        json!({ "model": "llama3.2", "stream": true })
    );
}

#[test]
fn oversized_response_is_refused() {
    let server = MockServer::start([MockResponse::json(200, fixture!("chat.json"))]).unwrap();
    let err = tokio_test::block_on(
        client(&server)
            .max_response_bytes(64)
            .generate(&[Message::human("Hi")]),
    )
    .unwrap_err();
    assert!(
        matches!(err, m if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("limit"))
    );
    server.finish().unwrap();
}
