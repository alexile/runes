//! End-to-end tests against a loopback mock of `/v1/chat/completions`: the
//! client builds real HTTP requests and decodes recorded responses. No test
//! touches the network.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use futures::StreamExt;
use rune_chain_core::LlmErrorKind;
use rune_chain_core::testing::check_llm;
use rune_chain_core::testing::http::{MockResponse, MockServer, RecordedRequest};
use std::time::Duration;

use rune_chain_core::{
    FunctionDefinition, Llm, Message, ResponseFormat, StreamAccumulator, StreamData,
    StreamEvent as CoreEvent, ToolChoice,
};
use rune_chain_openai::{OpenAi, StreamEvent, collect_events, models};
use serde_json::json;

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/", $name))
    };
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

fn client(server: &MockServer) -> OpenAi {
    OpenAi::new("sk-test")
        .base_url(format!("{}/v1", server.base_url()))
        .http_client(http())
        .retry_delay(Duration::ZERO)
}

fn assert_chat_request(req: &RecordedRequest) {
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/v1/chat/completions");
    assert_eq!(req.header("authorization"), Some("Bearer sk-test"));
    assert_eq!(req.header("content-type"), Some("application/json"));
}

#[test]
fn generate_sends_chat_request_and_decodes_response() {
    let server = MockServer::start([MockResponse::json(200, fixture!("chat_text.json"))]).unwrap();
    let llm = client(&server).max_tokens(64);
    let result = tokio_test::block_on(llm.generate(&[
        Message::system("Be terse."),
        Message::human("What is 2 + 2?"),
    ]))
    .unwrap();
    assert_eq!(result.generation, "2 + 2 = 4.");
    assert_eq!(result.tokens.unwrap().total_tokens, 27);

    let requests = server.finish().unwrap();
    assert_eq!(requests.len(), 1);
    assert_chat_request(&requests[0]);
    assert_eq!(
        requests[0].json().unwrap(),
        json!({
            "model": models::DEFAULT_MODEL,
            "max_completion_tokens": 64,
            "messages": [
                { "role": "system", "content": "Be terse." },
                { "role": "user", "content": "What is 2 + 2?" },
            ],
        })
    );
}

#[test]
fn generate_with_tools_sends_function_definitions() {
    let server =
        MockServer::start([MockResponse::json(200, fixture!("chat_tool_calls.json"))]).unwrap();
    let llm = client(&server);
    let tools = [FunctionDefinition::single_input(
        "get_current_weather",
        "Current weather for a city.",
    )];
    let result = tokio_test::block_on(llm.generate_with_tools(
        &[Message::human("Weather?")],
        &tools,
        Some(ToolChoice::Required),
    ))
    .unwrap();
    assert_eq!(result.tool_calls.len(), 2);

    let requests = server.finish().unwrap();
    assert_chat_request(&requests[0]);
    let body = requests[0].json().unwrap();
    assert_eq!(body["tools"][0]["type"], "function");
    assert_eq!(body["tools"][0]["function"]["name"], "get_current_weather");
    assert_eq!(
        body["tools"][0]["function"]["parameters"],
        tools[0].parameters
    );
    assert_eq!(body["tool_choice"], "required");
    assert!(body.get("stream").is_none());
}

#[test]
fn stream_assembles_chunked_event_stream() {
    let server =
        MockServer::start([MockResponse::event_stream(fixture!("stream.sse")).chunked(5)]).unwrap();
    let llm = client(&server);
    let chunks: Vec<StreamData> = tokio_test::block_on(async {
        let stream = llm.stream(&[Message::human("Say hello")]).await.unwrap();
        stream.map(Result::unwrap).collect().await
    });
    let contents: Vec<&str> = chunks.iter().map(|c| c.content.as_str()).collect();
    assert_eq!(contents, ["Hello", " there", ""]);
    assert!(chunks.last().unwrap().is_finished);

    let requests = server.finish().unwrap();
    assert_chat_request(&requests[0]);
    assert_eq!(requests[0].json().unwrap()["stream"], true);
}

#[test]
fn http_errors_map_to_classified_errors() {
    let server = MockServer::start([
        MockResponse::json(401, fixture!("error_invalid_key.json")),
        MockResponse::new(502, "text/html", "<html>502 Bad Gateway</html>"),
        MockResponse::json(401, fixture!("error_invalid_key.json")),
    ])
    .unwrap();
    let llm = client(&server).max_retries(0);
    let msgs = [Message::human("Hi")];
    tokio_test::block_on(async {
        assert!(matches!(
            llm.generate(&msgs).await,
            Err(m) if m.kind() == LlmErrorKind::Auth && m.message().starts_with("Incorrect API key")
        ));
        assert!(matches!(
            llm.generate(&msgs).await,
            Err(m) if m.kind() == LlmErrorKind::Server && m.status() == Some(502) && m.message().contains("502")
        ));
        assert!(matches!(
            llm.stream(&msgs).await.map(drop),
            Err(e) if e.kind() == LlmErrorKind::Auth && e.status() == Some(401)
        ));
    });
    assert_eq!(server.finish().unwrap().len(), 3);
}

#[test]
fn passes_the_llm_contract() {
    let tool_call = json!({
        "id": "chatcmpl-1", "object": "chat.completion", "model": "m",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant", "content": null,
                "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": { "name": "echo", "arguments": "{\"input\":\"ping\"}" }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": { "prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8 }
    });
    let server = MockServer::start([
        MockResponse::json(200, fixture!("chat_text.json")),
        MockResponse::json(200, fixture!("chat_text.json")),
        MockResponse::json(200, tool_call.to_string()),
        MockResponse::event_stream(fixture!("stream.sse")).chunked(3),
    ])
    .unwrap();
    tokio_test::block_on(check_llm(&client(&server))).unwrap();
    let requests = server.finish().unwrap();
    assert_eq!(requests.len(), 4);
    requests.iter().for_each(assert_chat_request);
}

#[test]
fn retries_429_and_5xx_honouring_retry_after() {
    let server = MockServer::start([
        MockResponse::json(429, r#"{"error":{"message":"Rate limit reached"}}"#)
            .with_header("Retry-After", "0"),
        MockResponse::new(503, "text/plain", "busy").with_header("retry-after-ms", "1"),
        MockResponse::json(200, fixture!("chat_text.json")),
    ])
    .unwrap();
    let result = tokio_test::block_on(client(&server).generate(&[Message::human("Hi")])).unwrap();
    assert_eq!(result.generation, "2 + 2 = 4.");
    let requests = server.finish().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|r| r.body == requests[0].body));
}

#[test]
fn gives_up_after_max_retries_and_never_retries_4xx() {
    let server = MockServer::start([
        MockResponse::json(500, r#"{"error":{"message":"boom"}}"#),
        MockResponse::json(500, r#"{"error":{"message":"boom"}}"#),
        MockResponse::json(400, r#"{"error":{"message":"bad request"}}"#),
        MockResponse::json(429, r#"{"error":{"message":"slow down"}}"#)
            .with_header("Retry-After", "3600"),
    ])
    .unwrap();
    let llm = client(&server).max_retries(1);
    let msgs = [Message::human("Hi")];
    tokio_test::block_on(async {
        assert!(matches!(
            llm.generate(&msgs).await,
            Err(m) if m.kind() == LlmErrorKind::Server && m.message() == "boom (HTTP 500)"
        ));
        assert!(matches!(
            llm.generate(&msgs).await,
            Err(m) if m.kind() == LlmErrorKind::InvalidRequest && m.message().contains("HTTP 400")
        ));
        // A Retry-After beyond the cap is returned, not waited for.
        assert!(matches!(
            llm.generate(&msgs).await,
            Err(m) if m.kind() == LlmErrorKind::RateLimit
                && m.retry_after() == Some(std::time::Duration::from_secs(3600))
                && m.message().contains("HTTP 429")
        ));
    });
    assert_eq!(server.finish().unwrap().len(), 4);
}

#[test]
fn api_key_never_leaks_into_errors() {
    let key = "sk-live-0123456789abcdef";
    let echo = format!(r#"{{"error":{{"message":"Incorrect API key provided: {key}"}}}}"#);
    let server = MockServer::start([MockResponse::json(401, echo)]).unwrap();
    let llm = client(&server).api_key(key);
    let err = tokio_test::block_on(llm.generate(&[Message::human("Hi")])).unwrap_err();
    assert!(!err.to_string().contains(key), "{err}");
    assert!(!format!("{err:?} {llm:?}").contains(key));
    let requests = server.finish().unwrap();
    assert_eq!(
        requests[0].header("authorization"),
        Some(format!("Bearer {key}").as_str())
    );
}

#[test]
fn oversized_response_is_rejected() {
    let big = format!(r#"{{"choices":[],"pad":"{}"}}"#, "x".repeat(4096));
    let server = MockServer::start([MockResponse::json(200, big)]).unwrap();
    let llm = client(&server).max_response_bytes(1024);
    let err = tokio_test::block_on(llm.generate(&[Message::human("Hi")])).unwrap_err();
    assert!(
        matches!(&err, m if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("1024-byte limit")),
        "{err:?}"
    );
    server.finish().unwrap();
}

#[test]
fn stream_events_report_tool_calls_and_usage() {
    let server = MockServer::start([
        MockResponse::event_stream(fixture!("stream_tool_calls.sse")).chunked(7),
    ])
    .unwrap();
    let llm = client(&server);
    let tools = [FunctionDefinition::single_input("get_weather", "Weather.")];
    let result = tokio_test::block_on(async {
        let events = llm
            .stream_events(&[Message::human("Weather?")], &tools, None)
            .await
            .unwrap();
        collect_events(events).await.unwrap()
    });
    assert_eq!(result.tool_calls.len(), 2);
    assert_eq!(result.tool_calls[0].name, "get_weather");
    assert_eq!(result.tokens.unwrap().total_tokens, 61);

    let requests = server.finish().unwrap();
    let body = requests[0].json().unwrap();
    assert_eq!(body["stream"], true);
    assert_eq!(body["stream_options"], json!({ "include_usage": true }));
    assert_eq!(body["tools"][0]["function"]["name"], "get_weather");
}

#[test]
fn llm_stream_events_stream_tool_call_fragments() {
    let server = MockServer::start([
        MockResponse::event_stream(fixture!("stream_tool_calls.sse")).chunked(7),
    ])
    .unwrap();
    let llm: &dyn Llm = &client(&server);
    let tools = [FunctionDefinition::single_input("get_weather", "Weather.")];
    let events: Vec<CoreEvent> = tokio_test::block_on(async {
        let s = llm
            .stream_events(
                &[Message::human("Weather?")],
                Some(&tools),
                Some(ToolChoice::Auto),
            )
            .await
            .unwrap();
        s.map(Result::unwrap).collect().await
    });
    let deltas = events
        .iter()
        .filter(|e| matches!(e, CoreEvent::ToolCallDelta { .. }))
        .count();
    assert_eq!(deltas, 4, "{events:?}");
    let mut acc = StreamAccumulator::new();
    for e in &events {
        acc.push(e).unwrap();
    }
    let result = acc.finish();
    assert_eq!(result.tool_calls[0].arg("location"), Some(json!("Oslo")));
    assert_eq!(result.tool_calls[1].arg("tz"), Some(json!("UTC")));
    assert_eq!(result.tokens.unwrap().total_tokens, 61);

    let body = server.finish().unwrap()[0].json().unwrap();
    assert_eq!(body["stream"], true);
    assert_eq!(body["tool_choice"], "auto");
    assert_eq!(body["tools"][0]["function"]["name"], "get_weather");
}

#[test]
fn stream_events_yield_text_and_finish() {
    let server =
        MockServer::start([MockResponse::event_stream(fixture!("stream.sse")).chunked(2)]).unwrap();
    let events: Vec<StreamEvent> = tokio_test::block_on(async {
        let s = client(&server)
            .stream_events(&[Message::human("Hi")], &[], None)
            .await
            .unwrap();
        s.map(Result::unwrap).collect().await
    });
    assert!(matches!(&events[0], StreamEvent::Text(t) if t == "Hello"));
    assert!(matches!(&events[2], StreamEvent::Finished { reason } if reason == "stop"));
    assert!(matches!(events.last(), Some(StreamEvent::Done)));
    server.finish().unwrap();
}

#[test]
fn generate_structured_sends_strict_json_schema() {
    let reply = json!({
        "choices": [{ "message": { "role": "assistant", "content": "{\"city\":\"Paris\"}" } }]
    });
    let server = MockServer::start([MockResponse::json(200, reply.to_string())]).unwrap();
    let schema = json!({
        "type": "object",
        "properties": { "city": { "type": "string" } },
        "required": ["city"],
        "additionalProperties": false
    });
    let format = ResponseFormat::json_schema("capital", schema.clone());
    let out = tokio_test::block_on(
        client(&server).generate_structured(&[Message::human("Capital of France?")], &format),
    )
    .unwrap();
    assert_eq!(format.parse_json(&out.generation).unwrap()["city"], "Paris");

    let body = server.finish().unwrap()[0].json().unwrap();
    assert_eq!(
        body["response_format"],
        json!({
            "type": "json_schema",
            "json_schema": { "name": "capital", "schema": schema, "strict": true }
        })
    );
}

#[test]
fn azure_uses_deployment_path_api_version_and_api_key_header() {
    let server = MockServer::start([MockResponse::json(200, fixture!("chat_text.json"))]).unwrap();
    let llm = OpenAi::azure(server.base_url(), "prod-gpt4o", "azure-key")
        .api_version("2024-10-21")
        .http_client(http());
    tokio_test::block_on(llm.generate(&[Message::human("Hi")])).unwrap();
    let req = &server.finish().unwrap()[0];
    assert_eq!(
        req.path,
        "/openai/deployments/prod-gpt4o/chat/completions?api-version=2024-10-21"
    );
    assert_eq!(req.header("api-key"), Some("azure-key"));
    assert_eq!(req.header("authorization"), None);
}

#[test]
fn local_servers_send_no_auth_and_compat_fields() {
    let server = MockServer::start([MockResponse::json(200, fixture!("chat_text.json"))]).unwrap();
    let llm = OpenAi::vllm(format!("{}/v1", server.base_url()), "qwen")
        .max_tokens(8)
        .header("X-Trace", "abc")
        .http_client(http());
    tokio_test::block_on(llm.generate(&[Message::human("Hi")])).unwrap();
    let req = &server.finish().unwrap()[0];
    assert_eq!(req.header("authorization"), None);
    assert_eq!(req.header("x-trace"), Some("abc"));
    let body = req.json().unwrap();
    assert_eq!(body["model"], "qwen");
    assert_eq!(body["max_tokens"], 8);
}

#[test]
fn refusals_are_results_but_fail_structured_output() {
    let refusal = json!({
        "choices": [{
            "message": { "role": "assistant", "content": null, "refusal": "I can't help with that." },
            "finish_reason": "stop"
        }]
    })
    .to_string();
    let server = MockServer::start([
        MockResponse::json(200, refusal.clone()),
        MockResponse::json(200, refusal),
    ])
    .unwrap();
    let llm = client(&server);
    let msgs = [Message::human("Hi")];
    tokio_test::block_on(async {
        let r = llm.generate(&msgs).await.unwrap();
        assert_eq!(
            r.finish_reason,
            Some(rune_chain_core::FinishReason::Refusal)
        );
        let err = llm
            .generate_structured(&msgs, &ResponseFormat::JsonObject)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), LlmErrorKind::Provider);
        assert!(err.message().contains("refused"));
    });
    server.finish().unwrap();
}

#[test]
fn absurd_retry_after_does_not_panic() {
    for (name, value) in [("retry-after", "1e30"), ("retry-after-ms", "1e300")] {
        let server =
            MockServer::start([MockResponse::json(429, "{}").with_header(name, value)]).unwrap();
        let err =
            tokio_test::block_on(client(&server).generate(&[Message::human("Hi")])).unwrap_err();
        assert_eq!(err.kind(), LlmErrorKind::RateLimit, "{err:?}");
        assert_eq!(server.finish().unwrap().len(), 1);
    }
}
