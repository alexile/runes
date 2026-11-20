//! End-to-end tests against a loopback mock of the Messages API: the client
//! builds real HTTP requests and decodes recorded responses. No test touches
//! the network.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use futures::StreamExt;
use rune_chain_anthropic::{
    Anthropic, CachePolicy, CacheTtl, DEFAULT_MAX_TOKENS, DEFAULT_STREAM_MAX_TOKENS, FallbackModel,
    Fallbacks, SERVER_SIDE_FALLBACK_BETA, StreamEvent, StructuredOutput, Usage, models,
};
use rune_chain_core::LlmErrorKind;
use rune_chain_core::testing::check_llm;
use rune_chain_core::testing::http::{MockResponse, MockServer, RecordedRequest};
use rune_chain_core::{
    FunctionDefinition, Llm, Message, ResponseFormat, StreamAccumulator, StreamData,
    StreamEvent as CoreEvent, ToolChoice,
};
use serde_json::json;

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/", $name))
    };
}

fn client(server: &MockServer) -> Anthropic {
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    Anthropic::new("sk-ant-test")
        .base_url(format!("{}/", server.base_url()))
        .http_client(http)
}

fn assert_messages_request(req: &RecordedRequest) {
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/v1/messages");
    assert_eq!(req.header("x-api-key"), Some("sk-ant-test"));
    assert_eq!(req.header("anthropic-version"), Some("2023-06-01"));
    assert_eq!(req.header("content-type"), Some("application/json"));
    assert!(req.header("authorization").is_none());
}

#[test]
fn generate_sends_messages_request_and_decodes_response() {
    let server =
        MockServer::start([MockResponse::json(200, fixture!("messages_text.json"))]).unwrap();
    let llm = client(&server);
    let result = tokio_test::block_on(llm.generate(&[
        Message::system("Be terse."),
        Message::human("Capital of France?"),
    ]))
    .unwrap();
    assert_eq!(result.generation, "The capital of France is Paris.");
    assert_eq!(result.tokens.unwrap().total_tokens, 30);

    let requests = server.finish().unwrap();
    assert_eq!(requests.len(), 1);
    assert_messages_request(&requests[0]);
    assert_eq!(
        requests[0].json().unwrap(),
        json!({
            "model": models::DEFAULT_MODEL,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "system": "Be terse.",
            "messages": [{ "role": "user", "content": "Capital of France?" }],
        })
    );
}

#[test]
fn generate_with_tools_sends_tool_definitions() {
    let server =
        MockServer::start([MockResponse::json(200, fixture!("messages_tool_use.json"))]).unwrap();
    let llm = client(&server).model(models::CLAUDE_HAIKU_4_5);
    let tools = [FunctionDefinition::single_input(
        "get_weather",
        "Current weather for a city.",
    )];
    let result = tokio_test::block_on(llm.generate_with_tools(
        &[Message::human("Weather in Paris?")],
        &tools,
        Some(ToolChoice::Tool("get_weather".into())),
    ))
    .unwrap();
    assert_eq!(result.tool_calls.len(), 1);
    assert_eq!(result.tool_calls[0].name, "get_weather");

    let requests = server.finish().unwrap();
    assert_messages_request(&requests[0]);
    let body = requests[0].json().unwrap();
    assert_eq!(body["model"], models::CLAUDE_HAIKU_4_5);
    assert_eq!(body["tools"][0]["name"], "get_weather");
    assert_eq!(body["tools"][0]["input_schema"], tools[0].parameters);
    assert_eq!(
        body["tool_choice"],
        json!({ "type": "tool", "name": "get_weather" })
    );
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
    assert_eq!(contents, ["Hello", "!", ""]);
    assert!(chunks.last().unwrap().is_finished);

    let requests = server.finish().unwrap();
    assert_messages_request(&requests[0]);
    let body = requests[0].json().unwrap();
    assert_eq!(body["stream"], true);
    assert_eq!(body["max_tokens"], DEFAULT_STREAM_MAX_TOKENS);
}

#[test]
fn http_errors_map_to_classified_errors() {
    let server = MockServer::start([
        MockResponse::json(529, fixture!("error_overloaded.json")),
        MockResponse::new(502, "text/plain", "upstream connect error"),
        MockResponse::json(529, fixture!("error_overloaded.json")),
    ])
    .unwrap();
    let llm = client(&server).max_retries(0);
    let msgs = [Message::human("Hi")];
    tokio_test::block_on(async {
        assert!(matches!(
            llm.generate(&msgs).await,
            Err(m) if m.kind() == LlmErrorKind::Overloaded && m.status() == Some(529) && m.message() == "Overloaded"
        ));
        assert!(matches!(
            llm.generate(&msgs).await,
            Err(m) if m.kind() == LlmErrorKind::Server && m.message() == "upstream connect error"
        ));
        assert!(matches!(
            llm.stream(&msgs).await.map(drop),
            Err(m) if m.kind() == LlmErrorKind::Overloaded && m.message() == "Overloaded"
        ));
    });
    assert_eq!(server.finish().unwrap().len(), 3);
}

#[test]
fn passes_the_llm_contract() {
    let tool_use = json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "m",
        "content": [{ "type": "tool_use", "id": "toolu_1", "name": "echo", "input": { "input": "ping" } }],
        "stop_reason": "tool_use",
        "usage": { "input_tokens": 5, "output_tokens": 3 }
    });
    let server = MockServer::start([
        MockResponse::json(200, fixture!("messages_text.json")),
        MockResponse::json(200, fixture!("messages_text.json")),
        MockResponse::json(200, tool_use.to_string()),
        MockResponse::event_stream(fixture!("stream.sse")).chunked(3),
    ])
    .unwrap();
    tokio_test::block_on(check_llm(&client(&server))).unwrap();
    let requests = server.finish().unwrap();
    assert_eq!(requests.len(), 4);
    requests.iter().for_each(assert_messages_request);
}

#[test]
fn retries_overload_and_rate_limit_honouring_retry_after() {
    let server = MockServer::start([
        MockResponse::json(529, fixture!("error_overloaded.json")).with_header("retry-after", "0"),
        MockResponse::json(
            429,
            r#"{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}"#,
        )
        .with_header("retry-after-ms", "1"),
        MockResponse::json(200, fixture!("messages_text.json")),
    ])
    .unwrap();
    let result = tokio_test::block_on(client(&server).generate(&[Message::human("Hi")])).unwrap();
    assert_eq!(result.generation, "The capital of France is Paris.");
    let requests = server.finish().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].body, requests[2].body);
}

#[test]
fn gives_up_after_max_retries_and_never_retries_client_errors() {
    let overloaded = || {
        MockResponse::json(529, fixture!("error_overloaded.json")).with_header("retry-after", "0")
    };
    let server = MockServer::start([overloaded(), overloaded()]).unwrap();
    let err = tokio_test::block_on(
        client(&server)
            .max_retries(1)
            .generate(&[Message::human("Hi")]),
    )
    .unwrap_err();
    assert_eq!(err.kind(), LlmErrorKind::Overloaded);
    assert_eq!(err.message(), "Overloaded");
    assert_eq!(err.retry_after(), Some(std::time::Duration::ZERO));
    assert_eq!(server.finish().unwrap().len(), 2);

    let server = MockServer::start([MockResponse::json(
        400,
        r#"{"type":"error","error":{"type":"invalid_request_error","message":"bad"}}"#,
    )])
    .unwrap();
    assert!(tokio_test::block_on(client(&server).generate(&[Message::human("Hi")])).is_err());
    assert_eq!(server.finish().unwrap().len(), 1);
}

#[test]
fn error_bodies_are_truncated_and_scrubbed() {
    let body = format!("proxy says sk-ant-test-0123456789 {}", "x".repeat(10_000));
    let server = MockServer::start([MockResponse::new(502, "text/plain", body)]).unwrap();
    let llm = Anthropic::new("sk-ant-test-0123456789")
        .base_url(server.base_url())
        .http_client(reqwest::Client::builder().no_proxy().build().unwrap())
        .max_retries(0);
    let err = tokio_test::block_on(llm.generate(&[Message::human("Hi")])).unwrap_err();
    assert_eq!(err.kind(), LlmErrorKind::Server, "{err:?}");
    assert_eq!(err.status(), Some(502));
    let m = err.message();
    assert!(!m.contains("0123456789"));
    assert!(m.contains("[REDACTED]"));
    assert!(m.len() < 2_000);
    server.finish().unwrap();
}

#[test]
fn oversized_response_is_rejected() {
    let server =
        MockServer::start([MockResponse::json(200, fixture!("messages_text.json"))]).unwrap();
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

#[test]
fn cache_breakpoints_are_sent_and_cache_usage_is_exposed() {
    let reply = json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
        "content": [{ "type": "text", "text": "Done." }],
        "stop_reason": "end_turn",
        "usage": { "input_tokens": 12, "cache_creation_input_tokens": 0,
                   "cache_read_input_tokens": 4096, "output_tokens": 3 }
    });
    let server = MockServer::start([MockResponse::json(200, reply.to_string())]).unwrap();
    let llm = client(&server).cache(CachePolicy::none().with_system(CacheTtl::OneHour));
    let message = tokio_test::block_on(llm.generate_message(
        &[Message::system("Manual."), Message::human("Go")],
        &[],
        None,
    ))
    .unwrap();
    assert_eq!(*message.usage(), Usage::new(12, 3, 0, 4096));
    assert_eq!(
        message.to_generate_result().tokens.unwrap().prompt_tokens,
        4108
    );

    let body = server.finish().unwrap()[0].json().unwrap();
    assert_eq!(
        body["system"],
        json!([{ "type": "text", "text": "Manual.", "cache_control": { "type": "ephemeral", "ttl": "1h" } }])
    );
}

#[test]
fn count_tokens_posts_to_the_count_endpoint() {
    let server = MockServer::start([MockResponse::json(200, r#"{"input_tokens":1234}"#)]).unwrap();
    let tools = [FunctionDefinition::single_input("echo", "Echo.")];
    let n = tokio_test::block_on(
        client(&server)
            .model(models::CLAUDE_OPUS_5_5)
            .count_tokens(&[Message::system("S"), Message::human("Hi")], &tools),
    )
    .unwrap();
    assert_eq!(n, 1234);
    let requests = server.finish().unwrap();
    assert_eq!(requests[0].path, "/v1/messages/count_tokens");
    assert_eq!(requests[0].header("x-api-key"), Some("sk-ant-test"));
    let body = requests[0].json().unwrap();
    assert_eq!(body["model"], models::CLAUDE_OPUS_5_5);
    assert_eq!(body["system"], "S");
    assert_eq!(body["tools"][0]["name"], "echo");
    assert!(body.get("max_tokens").is_none());
}

fn city_format() -> ResponseFormat {
    ResponseFormat::json_schema(
        "city",
        json!({ "type": "object", "properties": { "name": { "type": "string" } },
                "required": ["name"], "additionalProperties": false }),
    )
}

#[test]
fn structured_output_uses_native_json_schema_on_current_models() {
    let reply = json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
        "content": [{ "type": "text", "text": "{\"name\":\"Paris\"}" }],
        "stop_reason": "end_turn",
        "usage": { "input_tokens": 20, "output_tokens": 6 }
    });
    let server = MockServer::start([MockResponse::json(200, reply.to_string())]).unwrap();
    let format = city_format();
    let out = tokio_test::block_on(
        client(&server).generate_structured(&[Message::human("Capital of France?")], &format),
    )
    .unwrap();
    assert_eq!(format.parse_json(&out.generation).unwrap()["name"], "Paris");
    let body = server.finish().unwrap()[0].json().unwrap();
    assert_eq!(
        body["output_config"]["format"],
        json!({ "type": "json_schema", "schema": format.schema().unwrap() })
    );
    assert!(body.get("tools").is_none());
}

#[test]
fn structured_output_falls_back_to_forced_tool_use() {
    let reply = json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-4-6",
        "content": [{ "type": "tool_use", "id": "toolu_1", "name": "city", "input": { "name": "Paris" } }],
        "stop_reason": "tool_use",
        "usage": { "input_tokens": 20, "output_tokens": 6 }
    });
    let server = MockServer::start([MockResponse::json(200, reply.to_string())]).unwrap();
    let format = city_format();
    let out = tokio_test::block_on(
        client(&server)
            .model(models::CLAUDE_OPUS_4_6)
            .generate_structured(&[Message::human("Capital of France?")], &format),
    )
    .unwrap();
    assert_eq!(out.generation, r#"{"name":"Paris"}"#);
    assert_eq!(out.tool_calls.len(), 0);
    let body = server.finish().unwrap()[0].json().unwrap();
    assert_eq!(
        body["tool_choice"],
        json!({ "type": "tool", "name": "city" })
    );
    assert_eq!(body["tools"][0]["input_schema"], *format.schema().unwrap());
    assert!(body.get("output_config").is_none());
}

#[test]
fn structured_output_rejects_truncated_and_refused_answers() {
    let reply = |stop: &str| {
        json!({
            "content": [{ "type": "text", "text": "{\"name\":\"Pa" }],
            "stop_reason": stop,
            "usage": { "input_tokens": 1, "output_tokens": 1 }
        })
        .to_string()
    };
    let server = MockServer::start([
        MockResponse::json(200, reply("max_tokens")),
        MockResponse::json(200, reply("refusal")),
    ])
    .unwrap();
    let llm = client(&server).structured_output(StructuredOutput::Native);
    let msgs = [Message::human("?")];
    tokio_test::block_on(async {
        assert!(matches!(
            llm.generate_structured(&msgs, &city_format()).await,
            Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("max_tokens")
        ));
        assert!(matches!(
            llm.generate_structured(&msgs, &city_format()).await,
            Err(m) if m.kind() == LlmErrorKind::Provider && m.message().contains("refusal")
        ));
    });
    server.finish().unwrap();
}

#[test]
fn stream_message_yields_tool_calls_and_final_usage() {
    let server =
        MockServer::start([MockResponse::event_stream(fixture!("stream.sse")).chunked(7)]).unwrap();
    let tools = [FunctionDefinition::single_input("get_weather", "Weather.")];
    let events: Vec<StreamEvent> = tokio_test::block_on(async {
        let stream = client(&server)
            .stream_message(&[Message::human("Weather?")], &tools, None)
            .await
            .unwrap();
        stream.map(Result::unwrap).collect().await
    });
    assert!(matches!(&events[2], StreamEvent::ToolCall(c) if c.arguments == r#"{"city":"Paris"}"#));
    let Some(StreamEvent::Done(message)) = events.last() else {
        panic!("{events:?}")
    };
    assert_eq!(message.usage().cache_read_input_tokens, 2048);
    assert_eq!(
        server.finish().unwrap()[0].json().unwrap()["tools"][0]["name"],
        "get_weather"
    );
}

#[test]
fn llm_stream_events_stream_tool_input_fragments() {
    let server =
        MockServer::start([MockResponse::event_stream(fixture!("stream.sse")).chunked(7)]).unwrap();
    let tools = [FunctionDefinition::single_input("get_weather", "Weather.")];
    let llm: &dyn Llm = &client(&server);
    let events: Vec<CoreEvent> = tokio_test::block_on(async {
        let stream = llm
            .stream_events(&[Message::human("Weather?")], Some(&tools), None)
            .await
            .unwrap();
        stream.map(Result::unwrap).collect().await
    });
    let fragments = events
        .iter()
        .filter(|e| matches!(e, CoreEvent::ToolCallDelta { .. }))
        .count();
    assert_eq!(fragments, 3, "{events:?}");
    let mut acc = StreamAccumulator::new();
    for e in &events {
        acc.push(e).unwrap();
    }
    let result = acc.finish();
    assert_eq!(result.generation, "Hello!");
    assert_eq!(result.tool_calls[0].arg("city"), Some(json!("Paris")));
    assert_eq!(result.tokens.unwrap().cache_read_tokens, 2048);
    let body = server.finish().unwrap()[0].json().unwrap();
    assert_eq!(body["stream"], true);
    assert_eq!(body["tools"][0]["name"], "get_weather");
}

#[test]
fn default_client_does_not_follow_redirects() {
    // A redirect to another origin would carry `x-api-key` along (reqwest
    // only strips `authorization` and cookies), and could downgrade to http.
    let elsewhere =
        MockServer::start([MockResponse::json(200, fixture!("messages_text.json"))]).unwrap();
    let target = format!("{}/v1/messages", elsewhere.base_url());
    let server =
        MockServer::start([MockResponse::json(307, "{}").with_header("Location", &target)])
            .unwrap();
    let llm = Anthropic::new("sk-ant-test")
        .base_url(server.base_url())
        .max_retries(0);
    let err = tokio_test::block_on(llm.generate(&[Message::human("Hi")])).unwrap_err();
    assert_eq!(err.status(), Some(307), "{err:?}");
    assert_eq!(server.finish().unwrap().len(), 1);
}

#[test]
fn fallbacks_send_the_beta_header_and_body_field() {
    let server = MockServer::start([
        MockResponse::json(200, fixture!("messages_fallback.json")),
        MockResponse::json(200, fixture!("messages_fallback.json")),
        MockResponse::json(200, r#"{"input_tokens":7}"#),
    ])
    .unwrap();
    let base = client(&server).model(models::CLAUDE_OPUS_5_5);
    let msgs = [Message::human("Explain the scanner.")];
    tokio_test::block_on(async {
        let reply = base
            .clone()
            .fallbacks(Fallbacks::Default)
            .generate_message(&msgs, &[], None)
            .await
            .unwrap();
        assert!(reply.served_by_fallback());

        let llm = base
            .clone()
            .betas(["feature-a-2026-01-01", SERVER_SIDE_FALLBACK_BETA])
            .fallbacks(Fallbacks::models([FallbackModel::new("claude-opus-4-8")]));
        llm.generate_message(&msgs, &[], None).await.unwrap();
        // Token counting takes the configured betas, not the fallback one.
        base.clone()
            .beta("feature-a-2026-01-01")
            .fallbacks(Fallbacks::Default)
            .count_tokens(&msgs, &[])
            .await
            .unwrap();
    });

    let requests = server.finish().unwrap();
    assert_eq!(
        requests[0].header("anthropic-beta"),
        Some(SERVER_SIDE_FALLBACK_BETA)
    );
    assert_eq!(requests[0].json().unwrap()["fallbacks"], "default");
    assert_eq!(
        requests[1].header("anthropic-beta"),
        Some("feature-a-2026-01-01,server-side-fallback-2026-07-01")
    );
    assert_eq!(
        requests[1].json().unwrap()["fallbacks"],
        json!([{ "model": "claude-opus-4-8" }])
    );
    assert_eq!(requests[2].path, "/v1/messages/count_tokens");
    assert_eq!(
        requests[2].header("anthropic-beta"),
        Some("feature-a-2026-01-01")
    );
    assert!(requests[2].json().unwrap().get("fallbacks").is_none());
}

#[test]
fn no_beta_header_without_betas() {
    let server =
        MockServer::start([MockResponse::json(200, fixture!("messages_text.json"))]).unwrap();
    tokio_test::block_on(client(&server).generate(&[Message::human("Hi")])).unwrap();
    assert!(
        server.finish().unwrap()[0]
            .header("anthropic-beta")
            .is_none()
    );
}

#[test]
fn invalid_fallbacks_never_reach_the_server() {
    let server = MockServer::start([]).unwrap();
    let llm = client(&server).fallbacks(Fallbacks::models([]));
    let err = tokio_test::block_on(llm.generate(&[Message::human("Hi")])).unwrap_err();
    assert!(err.message().contains("fallbacks"));
    assert_eq!(server.finish().unwrap().len(), 0);
}

#[test]
fn stream_message_reports_a_mid_stream_fallback() {
    let server =
        MockServer::start(
            [MockResponse::event_stream(fixture!("stream_fallback.sse")).chunked(11)],
        )
        .unwrap();
    let events: Vec<StreamEvent> = tokio_test::block_on(async {
        let stream = client(&server)
            .model(models::CLAUDE_OPUS_5_5)
            .fallbacks(Fallbacks::Default)
            .stream_message(&[Message::human("Explain the parser.")], &[], None)
            .await
            .unwrap();
        stream.map(Result::unwrap).collect().await
    });
    assert!(matches!(&events[1], StreamEvent::Fallback(s) if s.to == "claude-opus-4-8"));
    let Some(StreamEvent::Done(message)) = events.last() else {
        panic!("{events:?}")
    };
    assert!(message.served_by_fallback());
    assert_eq!(message.text(), "The parser reads\n each rule file once.");
    let requests = server.finish().unwrap();
    assert_eq!(
        requests[0].header("anthropic-beta"),
        Some(SERVER_SIDE_FALLBACK_BETA)
    );
}
