//! End-to-end tests against a loopback mock of the Gemini API: the client
//! builds real HTTP requests and decodes recorded responses. No test touches
//! the network.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::time::Duration;

use futures::StreamExt;
use rune_chain_core::testing::check_llm;
use rune_chain_core::testing::http::{MockResponse, MockServer, RecordedRequest};
use rune_chain_core::{
    FinishReason, FunctionDefinition, Llm, LlmErrorKind, Message, ResponseFormat, StreamData,
    ToolChoice,
};
use rune_chain_gemini::{Gemini, StreamEvent, Thinking, models};
use serde_json::json;

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/", $name))
    };
}

const KEY: &str = "AIzaSy-test-key-0123";

fn client(server: &MockServer) -> Gemini {
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    Gemini::new(KEY)
        .base_url(format!("{}/v1beta/", server.base_url()))
        .http_client(http)
}

fn assert_request(req: &RecordedRequest, method: &str) {
    assert_eq!(req.method, "POST");
    assert_eq!(
        req.path,
        format!("/v1beta/models/{}:{method}", models::DEFAULT_MODEL)
    );
    assert_eq!(req.header("x-goog-api-key"), Some(KEY));
    assert_eq!(req.header("content-type"), Some("application/json"));
    assert!(req.header("authorization").is_none());
    assert!(!req.path.contains(KEY));
}

fn weather_tool() -> FunctionDefinition {
    FunctionDefinition::new(
        "get_weather",
        "Current weather for a city.",
        json!({
            "type": "object",
            "properties": { "city": { "type": "string" } },
            "required": ["city"],
            "additionalProperties": false
        }),
    )
}

#[test]
fn generate_sends_request_and_decodes_response() {
    let server =
        MockServer::start([MockResponse::json(200, fixture!("generate_text.json"))]).unwrap();
    let llm = client(&server);
    let result = tokio_test::block_on(llm.generate(&[
        Message::system("Be terse."),
        Message::human("Capital of France?"),
    ]))
    .unwrap();
    assert_eq!(result.generation, "The capital of France is Paris.");
    assert_eq!(result.finish_reason, Some(FinishReason::Stop));
    let usage = result.tokens.unwrap();
    assert_eq!(usage.prompt_tokens, 12);
    assert_eq!(usage.completion_tokens, 18);
    assert_eq!(usage.cache_read_tokens, 4);
    assert_eq!(usage.reasoning_tokens, 10);
    assert_eq!(usage.total_tokens, 30);

    let requests = server.finish().unwrap();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], "generateContent");
    assert_eq!(
        requests[0].json().unwrap(),
        json!({
            "contents": [{ "role": "user", "parts": [{ "text": "Capital of France?" }] }],
            "systemInstruction": { "parts": [{ "text": "Be terse." }] },
        })
    );
}

#[test]
fn tool_call_round_trip_keeps_ids_and_signatures() {
    let server = MockServer::start([
        MockResponse::json(200, fixture!("generate_tool_call.json")),
        MockResponse::json(200, fixture!("generate_after_tool.json")),
    ])
    .unwrap();
    let llm = client(&server);
    let tools = [weather_tool()];
    let mut messages = vec![Message::human("Weather in Paris?")];

    let first = tokio_test::block_on(llm.generate_with_tools(
        &messages,
        &tools,
        Some(ToolChoice::Tool("get_weather".into())),
    ))
    .unwrap();
    assert_eq!(first.finish_reason, Some(FinishReason::ToolCalls));
    assert_eq!(first.tool_calls.len(), 1);
    let call = &first.tool_calls[0];
    assert_eq!(call.name, "get_weather");
    assert_eq!(call.id, "gemini_call_resp-tool-1_0");
    assert_eq!(call.validate(&tools[0]).unwrap()["city"], "Paris");
    assert_eq!(first.reasoning_text(), "Let me check the weather.");
    rune_chain_core::testing::check_generate_result(&first, &tools).unwrap();

    messages.push(first.to_message());
    messages.push(Message::tool_result(
        &call.id,
        r#"{"temp_c": 21, "sky": "sunny"}"#,
    ));
    let second = tokio_test::block_on(llm.generate_with_tools(&messages, &tools, None)).unwrap();
    assert_eq!(second.generation, "It is 21°C and sunny in Paris.");
    assert!(!second.wants_tool_calls());

    let requests = server.finish().unwrap();
    assert_eq!(requests.len(), 2);
    let first_body = requests[0].json().unwrap();
    assert_eq!(
        first_body["tools"],
        json!([{ "functionDeclarations": [{
            "name": "get_weather",
            "description": "Current weather for a city.",
            "parameters": {
                "type": "OBJECT",
                "properties": { "city": { "type": "STRING" } },
                "required": ["city"]
            }
        }]}])
    );
    assert_eq!(
        first_body["toolConfig"],
        json!({ "functionCallingConfig": { "mode": "ANY", "allowedFunctionNames": ["get_weather"] } })
    );
    let second_body = requests[1].json().unwrap();
    assert!(second_body.get("toolConfig").is_none());
    assert_eq!(
        second_body["contents"],
        json!([
            { "role": "user", "parts": [{ "text": "Weather in Paris?" }] },
            { "role": "model", "parts": [
                { "text": "Let me check the weather.", "thought": true, "thoughtSignature": "VEhPVUdIVA==" },
                { "functionCall": { "name": "get_weather", "args": { "city": "Paris" } },
                  "thoughtSignature": "RlVOQ1NJRw==" }
            ]},
            { "role": "user", "parts": [
                { "functionResponse": { "name": "get_weather",
                                        "response": { "temp_c": 21, "sky": "sunny" } } }
            ]}
        ])
    );
}

#[test]
fn stream_assembles_chunked_event_stream() {
    let server =
        MockServer::start([MockResponse::event_stream(fixture!("stream.sse")).chunked(7)]).unwrap();
    let llm = client(&server).thinking(Thinking::thoughts());
    let chunks: Vec<StreamData> = tokio_test::block_on(async {
        let stream = llm.stream(&[Message::human("Say hello")]).await.unwrap();
        stream.map(Result::unwrap).collect().await
    });
    let contents: Vec<&str> = chunks.iter().map(|c| c.content.as_str()).collect();
    assert_eq!(contents, ["Hello", " there!", ""]);
    assert!(chunks.last().unwrap().is_finished);

    let requests = server.finish().unwrap();
    assert_eq!(
        requests[0].path,
        format!(
            "/v1beta/models/{}:streamGenerateContent?alt=sse",
            models::DEFAULT_MODEL
        )
    );
    assert_eq!(requests[0].header("x-goog-api-key"), Some(KEY));
    assert_eq!(
        requests[0].json().unwrap()["generationConfig"],
        json!({ "thinkingConfig": { "includeThoughts": true } })
    );
}

#[test]
fn stream_content_yields_thoughts_calls_and_the_full_response() {
    let server = MockServer::start([
        MockResponse::event_stream(fixture!("stream.sse")).chunked(3),
        MockResponse::event_stream(fixture!("stream_tool_calls.sse")).chunked(11),
    ])
    .unwrap();
    let llm = client(&server);
    let (first, second) = tokio_test::block_on(async {
        let a: Vec<StreamEvent> = llm
            .stream_content(&[Message::human("Say hello")], &[], None)
            .await
            .unwrap()
            .map(Result::unwrap)
            .collect()
            .await;
        let b: Vec<StreamEvent> = llm
            .stream_content(
                &[Message::human("Paris and Rome?")],
                &[weather_tool()],
                None,
            )
            .await
            .unwrap()
            .map(Result::unwrap)
            .collect()
            .await;
        (a, b)
    });
    assert_eq!(
        first[0],
        StreamEvent::Thought("**Greeting** I should say hello.".into())
    );
    let StreamEvent::Done(done) = first.last().unwrap() else {
        panic!("last event is not Done")
    };
    assert_eq!(done.text(), "Hello there!");
    assert_eq!(done.usage().thoughts_tokens, 12);
    let reasoning = done.to_generate_result().reasoning;
    assert_eq!(reasoning.len(), 2);
    assert_eq!(reasoning[1].signature.as_deref(), Some("U0lHTkFUVVJF"));

    let calls: Vec<_> = second
        .iter()
        .filter_map(|e| match e {
            StreamEvent::ToolCall(c) => Some(c.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].arguments, r#"{"city":"Rome"}"#);
    assert_ne!(calls[0].id, calls[1].id);
    let StreamEvent::Done(done) = second.last().unwrap() else {
        panic!("last event is not Done")
    };
    assert_eq!(
        done.to_generate_result().finish_reason,
        Some(FinishReason::ToolCalls)
    );
}

#[test]
fn truncated_stream_is_an_error() {
    let body = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hel\"}]}}]}\n\n";
    let server = MockServer::start([MockResponse::event_stream(body)]).unwrap();
    let llm = client(&server);
    let items: Vec<_> = tokio_test::block_on(async {
        llm.stream(&[Message::human("Hi")])
            .await
            .unwrap()
            .collect()
            .await
    });
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].as_ref().unwrap().content, "Hel");
    assert_eq!(
        items[1].as_ref().unwrap_err().kind(),
        LlmErrorKind::InvalidResponse
    );
    server.finish().unwrap();
}

#[test]
fn oversized_sse_events_are_rejected() {
    let body = format!(
        "data: {{\"candidates\":[{{\"content\":{{\"parts\":[{{\"text\":\"{}\"}}]}}}}]}}\n\n",
        "x".repeat(4096)
    );
    let server = MockServer::start([MockResponse::event_stream(body)]).unwrap();
    let llm = client(&server).max_response_bytes(1024);
    let items: Vec<_> = tokio_test::block_on(async {
        llm.stream(&[Message::human("Hi")])
            .await
            .unwrap()
            .collect()
            .await
    });
    assert_eq!(items.len(), 1);
    assert!(items[0].as_ref().unwrap_err().message().contains("limit"));
    server.finish().unwrap();
}

#[test]
fn http_errors_map_to_classified_errors() {
    let server = MockServer::start([
        MockResponse::json(429, fixture!("error_quota.json")),
        MockResponse::json(400, fixture!("error_invalid_key.json")),
        MockResponse::new(502, "text/html", "<html>bad gateway</html>"),
        MockResponse::json(
            503,
            r#"[{"error":{"code":503,"message":"The model is overloaded.","status":"UNAVAILABLE"}}]"#,
        ),
    ])
    .unwrap();
    let llm = client(&server).max_retries(0);
    let msgs = [Message::human("Hi")];
    tokio_test::block_on(async {
        let e = llm.generate(&msgs).await.unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::RateLimit);
        assert_eq!(e.status(), Some(429));
        assert_eq!(e.retry_after(), Some(Duration::from_secs(36)));
        assert!(e.message().starts_with("You exceeded your current quota"));

        let e = llm.generate(&msgs).await.unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::Auth);
        assert!(!e.to_string().contains(KEY));

        let e = llm.generate(&msgs).await.unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::Server);
        assert_eq!(e.message(), "<html>bad gateway</html>");

        let e = llm.stream(&msgs).await.map(drop).unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::Overloaded);
        assert_eq!(e.message(), "The model is overloaded.");
    });
    assert_eq!(server.finish().unwrap().len(), 4);
}

#[test]
fn retries_honour_retry_hints() {
    let server = MockServer::start([
        MockResponse::json(503, r#"{"error":{"code":503,"message":"busy","status":"UNAVAILABLE"}}"#)
            .with_header("retry-after", "0"),
        MockResponse::json(
            429,
            r#"{"error":{"code":429,"message":"slow down","status":"RESOURCE_EXHAUSTED",
                "details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"0.01s"}]}}"#,
        ),
        MockResponse::json(200, fixture!("generate_text.json")),
        // A wait longer than we honour is not retried.
        MockResponse::json(429, fixture!("error_quota.json")).with_header("retry-after", "3600"),
    ])
    .unwrap();
    let llm = client(&server);
    let msgs = [Message::human("Hi")];
    tokio_test::block_on(async {
        let ok = llm.generate(&msgs).await.unwrap();
        assert_eq!(ok.generation, "The capital of France is Paris.");
        let e = llm.generate(&msgs).await.unwrap_err();
        assert_eq!(e.retry_after(), Some(Duration::from_secs(3600)));
    });
    assert_eq!(server.finish().unwrap().len(), 4);
}

#[test]
fn blocked_prompt_is_a_refusal_error() {
    let server =
        MockServer::start([MockResponse::json(200, fixture!("blocked_prompt.json"))]).unwrap();
    let llm = client(&server);
    let e = tokio_test::block_on(llm.generate(&[Message::human("…")])).unwrap_err();
    assert_eq!(e.kind(), LlmErrorKind::Provider);
    assert!(!e.is_retryable());
    assert!(e.message().contains("blockReason: SAFETY"), "{e}");
    assert!(e.message().contains("HARM_CATEGORY_DANGEROUS_CONTENT"));
    assert!(!e.message().contains("HARM_CATEGORY_HARASSMENT"));
    server.finish().unwrap();
}

#[test]
fn safety_stop_is_a_content_filter() {
    let server = MockServer::start([
        MockResponse::json(200, fixture!("safety_stop.json")),
        MockResponse::json(200, fixture!("safety_stop.json")),
    ])
    .unwrap();
    let llm = client(&server);
    let msgs = [Message::human("…")];
    tokio_test::block_on(async {
        let r = llm.generate(&msgs).await.unwrap();
        assert_eq!(r.finish_reason, Some(FinishReason::ContentFilter));
        assert_eq!(r.generation, "");
        let format = ResponseFormat::JsonObject;
        let e = llm.generate_structured(&msgs, &format).await.unwrap_err();
        assert!(e.message().contains("content filter"));
    });
    server.finish().unwrap();
}

#[test]
fn structured_output_sends_json_mode_and_schema() {
    let reply = r#"{"candidates":[{"content":{"parts":[{"text":"{\"name\":\"Paris\",\"country\":\"France\"}"}]},"finishReason":"STOP"}]}"#;
    let server = MockServer::start([
        MockResponse::json(200, reply),
        MockResponse::json(200, reply),
    ])
    .unwrap();
    let llm = client(&server);
    let format = ResponseFormat::json_schema(
        "city",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "country": { "type": "string" }
            },
            "required": ["name", "country"],
            "additionalProperties": false
        }),
    );
    let recursive = ResponseFormat::json_schema(
        "tree",
        json!({
            "type": "object",
            "properties": { "children": { "type": "array", "items": { "$ref": "#" } } }
        }),
    );
    let msgs = [Message::human("Capital of France?")];
    tokio_test::block_on(async {
        let out = llm.generate_structured(&msgs, &format).await.unwrap();
        assert_eq!(
            format.parse_json(&out.generation).unwrap()["country"],
            "France"
        );
        // Not expressible in Gemini's subset: JSON mode plus instructions.
        llm.generate_structured(&msgs, &recursive).await.unwrap();
    });
    let requests = server.finish().unwrap();
    assert_eq!(
        requests[0].json().unwrap()["generationConfig"],
        json!({
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "OBJECT",
                "properties": { "name": { "type": "STRING" }, "country": { "type": "STRING" } },
                "required": ["name", "country"]
            }
        })
    );
    let fallback = requests[1].json().unwrap();
    assert_eq!(
        fallback["generationConfig"],
        json!({ "responseMimeType": "application/json" })
    );
    assert!(
        fallback["systemInstruction"]["parts"][0]["text"]
            .as_str()
            .unwrap()
            .contains("children")
    );
}

#[test]
fn response_size_cap() {
    let server =
        MockServer::start([MockResponse::json(200, fixture!("generate_text.json"))]).unwrap();
    let llm = client(&server).max_response_bytes(64);
    let e = tokio_test::block_on(llm.generate(&[Message::human("Hi")])).unwrap_err();
    assert_eq!(e.kind(), LlmErrorKind::InvalidResponse);
    assert!(e.message().contains("64-byte limit"));
    server.finish().unwrap();
}

#[test]
fn passes_the_llm_contract() {
    let server = MockServer::start([
        MockResponse::json(200, fixture!("generate_text.json")),
        MockResponse::json(200, fixture!("generate_text.json")),
        MockResponse::event_stream(fixture!("stream.sse")),
    ])
    .unwrap();
    tokio_test::block_on(check_llm(&client(&server))).unwrap();
    let requests = server.finish().unwrap();
    assert_eq!(requests.len(), 3);
}

#[test]
fn vertex_ai_uses_a_bearer_token() {
    let server =
        MockServer::start([MockResponse::json(200, fixture!("generate_text.json"))]).unwrap();
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let llm = Gemini::vertex_ai("my-project", "us-central1", "ya29.access-token")
        .unwrap()
        .base_url(format!(
            "{}/v1/projects/my-project/locations/us-central1/publishers/google",
            server.base_url()
        ))
        .http_client(http)
        .model(models::GEMINI_2_5_PRO);
    tokio_test::block_on(llm.generate(&[Message::human("Hi")])).unwrap();
    let requests = server.finish().unwrap();
    assert_eq!(
        requests[0].path,
        "/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-2.5-pro:generateContent"
    );
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer ya29.access-token")
    );
    assert!(requests[0].header("x-goog-api-key").is_none());
}

#[cfg(feature = "embed")]
mod embeddings {
    use rune_chain_embed::Embedder;
    use rune_chain_gemini::GeminiEmbedder;

    use super::*;

    #[test]
    fn batch_and_query_requests() {
        let server = MockServer::start([
            MockResponse::json(200, fixture!("embed_batch.json")),
            MockResponse::json(200, fixture!("embed_one.json")),
            MockResponse::json(200, r#"{"embeddings":[{"values":[1.0]}]}"#),
        ])
        .unwrap();
        let embedder = client(&server)
            .embedder("gemini-embedding-001")
            .dimensions(3);
        tokio_test::block_on(async {
            let docs = embedder.embed_documents(&["a", "b"]).await.unwrap();
            assert_eq!(docs, [vec![0.1, -0.2, 0.3], vec![0.0, 0.5, -0.5]]);
            let q = embedder.embed_query("q").await.unwrap();
            assert_eq!(q, [0.25, 0.5, -0.75]);
            assert_eq!(embedder.embed_batch(&[]).await.unwrap().len(), 0);
            // Count mismatch.
            assert!(embedder.embed_batch(&["x", "y"]).await.is_err());
        });
        let requests = server.finish().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[0].path,
            "/v1beta/models/gemini-embedding-001:batchEmbedContents"
        );
        assert_eq!(requests[0].header("x-goog-api-key"), Some(KEY));
        assert_eq!(
            requests[0].json().unwrap(),
            json!({ "requests": [
                { "model": "models/gemini-embedding-001", "content": { "parts": [{ "text": "a" }] },
                  "taskType": "RETRIEVAL_DOCUMENT", "outputDimensionality": 3 },
                { "model": "models/gemini-embedding-001", "content": { "parts": [{ "text": "b" }] },
                  "taskType": "RETRIEVAL_DOCUMENT", "outputDimensionality": 3 }
            ]})
        );
        assert_eq!(
            requests[1].path,
            "/v1beta/models/gemini-embedding-001:embedContent"
        );
        assert_eq!(
            requests[1].json().unwrap(),
            json!({ "content": { "parts": [{ "text": "q" }] },
                    "taskType": "RETRIEVAL_QUERY", "outputDimensionality": 3 })
        );
    }

    #[test]
    fn large_batches_are_split_in_order() {
        let reply = |start: usize, n: usize| {
            let items: Vec<String> = (start..start + n)
                .map(|i| format!("{{\"values\":[{i}.0]}}"))
                .collect();
            format!("{{\"embeddings\":[{}]}}", items.join(","))
        };
        let server = MockServer::start([
            MockResponse::json(200, reply(0, 2)),
            MockResponse::json(200, reply(2, 1)),
        ])
        .unwrap();
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let embedder = GeminiEmbedder::new(KEY)
            .base_url(format!("{}/v1beta", server.base_url()))
            .http_client(http)
            .batch_size(2)
            .max_concurrency(1);
        let out = tokio_test::block_on(embedder.embed_batch(&["a", "b", "c"])).unwrap();
        assert_eq!(out, [vec![0.0], vec![1.0], vec![2.0]]);
        assert_eq!(server.finish().unwrap().len(), 2);
    }
}
