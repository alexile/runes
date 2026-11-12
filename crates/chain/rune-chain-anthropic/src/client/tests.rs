//! Wire-format tests against recorded Anthropic Messages API fixtures.
//! None of them touch the network.

use rune_chain_core::LlmErrorKind;
use rune_chain_core::{FinishReason, Llm, ReasoningBlock, ToolCall};

use crate::{ThinkingDisplay, Usage};
use serde_json::{Value, json};

use super::*;

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/", $name))
    };
}

fn body(messages: &[Message], tools: &[FunctionDefinition], choice: Option<&ToolChoice>) -> Value {
    let llm = Anthropic::new("k").model("claude-test");
    serde_json::to_value(llm.request_body(messages, tools, choice, None)).unwrap()
}

// ── request building ──────────────────────────────────────────────────────────

#[test]
fn minimal_request_omits_optional_fields() {
    let v = body(&[Message::human("Hi")], &[], None);
    assert_eq!(
        v,
        json!({
            "model": "claude-test",
            "max_tokens": DEFAULT_MAX_TOKENS,
            "messages": [{ "role": "user", "content": "Hi" }],
        })
    );
}

#[test]
fn builder_settings_reach_the_request() {
    let llm = Anthropic::new("sk-ant-test")
        .model(models::CLAUDE_HAIKU_4_5)
        .temperature(0.25)
        .max_tokens(64);
    let v = serde_json::to_value(llm.request_body(&[Message::human("Hi")], &[], None, Some(true)))
        .unwrap();
    assert_eq!(v["model"], "claude-haiku-4-5");
    assert_eq!(v["temperature"], 0.25);
    assert_eq!(v["max_tokens"], 64);
    assert_eq!(v["stream"], true);
}

#[test]
fn system_messages_are_lifted_into_the_system_field() {
    let v = body(
        &[
            Message::system("Be terse."),
            Message::human("Hi"),
            Message::system("Answer in French."),
            Message::ai("Bonjour"),
        ],
        &[],
        None,
    );
    assert_eq!(v["system"], "Be terse.\nAnswer in French.");
    assert_eq!(
        v["messages"],
        json!([
            { "role": "user", "content": "Hi" },
            { "role": "assistant", "content": "Bonjour" },
        ])
    );
}

#[test]
fn image_parts_become_content_blocks() {
    let msg = Message::human(MessageContent::Parts(vec![
        ContentPart::text("Describe both."),
        ContentPart::image_url("https://example.com/a.png"),
        ContentPart::image_base64("image/jpeg", "/9j/4AAQ"),
    ]));
    let v = body(&[msg], &[], None);
    assert_eq!(
        v["messages"][0]["content"],
        json!([
            { "type": "text", "text": "Describe both." },
            { "type": "image", "source": { "type": "url", "url": "https://example.com/a.png" } },
            { "type": "image", "source": {
                "type": "base64", "media_type": "image/jpeg", "data": "/9j/4AAQ"
            } },
        ])
    );
}

#[test]
fn tool_round_trip_messages_use_tool_use_and_tool_result_blocks() {
    let v = body(
        &[
            Message::human("Weather in Paris?"),
            Message::ai_with_tool_calls(
                "Checking.",
                vec![ToolCall::new(
                    "toolu_1",
                    "get_weather",
                    r#"{"city":"Paris"}"#,
                )],
            ),
            Message::tool_result("toolu_1", "18°C, clear"),
        ],
        &[],
        None,
    );
    assert_eq!(
        v["messages"][1],
        json!({
            "role": "assistant",
            "content": [
                { "type": "text", "text": "Checking." },
                { "type": "tool_use", "id": "toolu_1", "name": "get_weather",
                  "input": { "city": "Paris" } },
            ],
        })
    );
    assert_eq!(
        v["messages"][2],
        json!({
            "role": "user",
            "content": [
                { "type": "tool_result", "tool_use_id": "toolu_1", "content": "18°C, clear" },
            ],
        })
    );
}

#[test]
fn tool_call_without_text_or_valid_json_still_serializes() {
    let v = body(
        &[Message::ai_with_tool_calls(
            "",
            vec![ToolCall::new("t", "noop", "not json")],
        )],
        &[],
        None,
    );
    assert_eq!(
        v["messages"][0]["content"],
        json!([{ "type": "tool_use", "id": "t", "name": "noop", "input": null }])
    );
}

#[test]
fn tool_result_without_call_id_is_marked_unknown() {
    let mut msg = Message::tool_result("x", "out");
    msg.tool_call_id = None;
    let v = body(&[msg], &[], None);
    assert_eq!(v["messages"][0]["content"][0]["tool_use_id"], "unknown");
}

#[test]
fn tools_and_tool_choice_map_to_anthropic_names() {
    let tools = [FunctionDefinition::single_input(
        "upper",
        "Upper-case text.",
    )];
    let v = body(&[Message::human("x")], &tools, None);
    assert_eq!(v["tools"][0]["name"], "upper");
    assert_eq!(v["tools"][0]["description"], "Upper-case text.");
    assert_eq!(v["tools"][0]["input_schema"], tools[0].parameters);
    assert!(v.get("parameters").is_none());

    for (choice, expected) in [
        (ToolChoice::Auto, json!({ "type": "auto" })),
        (ToolChoice::None, json!({ "type": "none" })),
        (ToolChoice::Required, json!({ "type": "any" })),
        (
            ToolChoice::Tool("upper".into()),
            json!({ "type": "tool", "name": "upper" }),
        ),
    ] {
        let v = body(&[Message::human("x")], &tools, Some(&choice));
        assert_eq!(v["tool_choice"], expected, "{choice:?}");
    }
}

// ── response decoding ─────────────────────────────────────────────────────────

#[test]
fn decodes_text_response_with_usage() {
    let message = decode_response(fixture!("messages_text.json").as_bytes()).unwrap();
    assert_eq!(message.stop_reason.as_deref(), Some("end_turn"));
    let result = message.to_generate_result();
    assert_eq!(result.generation, "The capital of France is Paris.");
    assert!(!result.wants_tool_calls());
    let tokens = result.tokens.unwrap();
    assert_eq!(
        (
            tokens.prompt_tokens,
            tokens.completion_tokens,
            tokens.total_tokens
        ),
        (21, 9, 30)
    );
}

#[test]
fn decodes_tool_use_and_skips_unknown_blocks() {
    let message = decode_response(fixture!("messages_tool_use.json").as_bytes()).unwrap();
    // The thinking block is kept apart from the text.
    assert_eq!(message.thinking(), "The user wants the weather.");
    assert!(matches!(
        &message.content[0],
        ContentBlock::Thinking { signature, .. } if signature == "EqQBCgIYAhIM"
    ));
    let result = message.to_generate_result();
    assert_eq!(result.generation, "Let me check the weather.\nOne moment.");
    assert_eq!(result.tool_calls.len(), 1);
    let call = &result.tool_calls[0];
    assert_eq!(call.id, "toolu_01A09q90qw90lq917835lq9");
    assert_eq!(call.name, "get_weather");
    assert_eq!(call.arg("city"), Some(json!("Paris")));
    assert_eq!(call.arg("unit"), Some(json!("celsius")));
    assert_eq!(result.tokens.unwrap().total_tokens, 441);
}

#[test]
fn thinking_round_trips_with_its_signature() {
    let message = decode_response(fixture!("messages_tool_use.json").as_bytes()).unwrap();
    let result = message.to_generate_result();
    assert_eq!(result.finish_reason, Some(FinishReason::ToolCalls));
    assert_eq!(result.reasoning_text(), "The user wants the weather.");
    assert_eq!(
        result.reasoning[0].signature.as_deref(),
        Some("EqQBCgIYAhIM")
    );
    // Thinking never reaches the visible text.
    assert!(!result.generation.contains("The user wants"));

    // Next turn: the assistant message carries the thinking block first,
    // signature intact, then text and tool use.
    let mut assistant = result.to_message();
    assistant
        .reasoning
        .push(ReasoningBlock::redacted("ZW5jcnlwdGVk"));
    // Unsigned reasoning (e.g. from another provider) cannot be verified and
    // is not sent.
    assistant.reasoning.push(ReasoningBlock::new("unsigned"));
    let history = [
        Message::human("Weather in Paris?"),
        assistant,
        Message::tool_result("toolu_01A09q90qw90lq917835lq9", "18C"),
    ];
    let v =
        serde_json::to_value(Anthropic::new("k").request_body(&history, &[], None, None)).unwrap();
    let blocks = v["messages"][1]["content"].as_array().unwrap();
    assert_eq!(
        blocks[0],
        json!({
            "type": "thinking",
            "thinking": "The user wants the weather.",
            "signature": "EqQBCgIYAhIM"
        })
    );
    assert_eq!(
        blocks[1],
        json!({ "type": "redacted_thinking", "data": "ZW5jcnlwdGVk" })
    );
    assert_eq!(blocks[2]["type"], "text");
    assert_eq!(blocks.last().unwrap()["type"], "tool_use");
    assert!(!v.to_string().contains("unsigned"));

    // A plain answer with only reasoning still sends its thinking.
    let answer =
        Message::ai("Sunny.").with_reasoning(vec![ReasoningBlock::new("t").with_signature("s")]);
    let v =
        serde_json::to_value(Anthropic::new("k").request_body(&[answer], &[], None, None)).unwrap();
    assert_eq!(
        v["messages"][0]["content"],
        json!([
            { "type": "thinking", "thinking": "t", "signature": "s" },
            { "type": "text", "text": "Sunny." }
        ])
    );
}

#[test]
fn stop_reasons_and_cache_usage_are_portable() {
    for (wire, reason) in [
        ("end_turn", FinishReason::Stop),
        ("stop_sequence", FinishReason::Stop),
        ("max_tokens", FinishReason::Length),
        ("tool_use", FinishReason::ToolCalls),
        ("refusal", FinishReason::Refusal),
        ("pause_turn", FinishReason::Other("pause_turn".into())),
    ] {
        assert_eq!(crate::finish_reason(wire), reason);
    }
    let body = br#"{"id":"m","model":"x","content":[{"type":"text","text":"hi"}],
        "stop_reason":"max_tokens",
        "usage":{"input_tokens":10,"output_tokens":5,
                 "cache_creation_input_tokens":200,"cache_read_input_tokens":1000}}"#;
    let result = decode_response(body).unwrap().to_generate_result();
    assert!(result.is_truncated());
    let usage = result.tokens.unwrap();
    assert_eq!(usage.prompt_tokens, 1210);
    assert_eq!(usage.cache_read_tokens, 1000);
    assert_eq!(usage.cache_creation_tokens, 200);
    assert_eq!(usage.uncached_prompt_tokens(), 10);
    rune_chain_core::testing::check_token_usage(&usage).unwrap();
}

#[test]
fn malformed_response_is_invalid_response() {
    assert!(matches!(
        decode_response(br#"{"content": []}"#),
        Err(e) if e.kind() == LlmErrorKind::InvalidResponse
    ));
    assert!(matches!(
        decode_response(b"not json"),
        Err(e) if e.kind() == LlmErrorKind::InvalidResponse
    ));
}

// ── error mapping ─────────────────────────────────────────────────────────────

#[test]
fn api_error_body_maps_to_classified_error() {
    let err = http::decode_error(
        529,
        fixture!("error_overloaded.json"),
        &ApiKey::new("k".into()),
    );
    assert_eq!(err.kind(), LlmErrorKind::Overloaded, "{err:?}");
    assert_eq!(err.status(), Some(529));
    assert_eq!(err.message(), "Overloaded");
    assert!(err.is_retryable());
}

#[test]
fn error_types_refine_the_status() {
    let key = ApiKey::new("k".into());
    let body = |kind: &str, msg: &str| {
        format!(r#"{{"type":"error","error":{{"type":"{kind}","message":"{msg}"}}}}"#)
    };
    for (status, kind, msg, expected) in [
        (
            429,
            "rate_limit_error",
            "slow down",
            LlmErrorKind::RateLimit,
        ),
        (401, "authentication_error", "bad key", LlmErrorKind::Auth),
        (403, "permission_error", "no", LlmErrorKind::Auth),
        (
            404,
            "not_found_error",
            "no model",
            LlmErrorKind::InvalidRequest,
        ),
        (
            413,
            "request_too_large",
            "big",
            LlmErrorKind::InvalidRequest,
        ),
        (500, "api_error", "oops", LlmErrorKind::Server),
        // Some proxies return 500 for overload; the type wins.
        (
            500,
            "overloaded_error",
            "Overloaded",
            LlmErrorKind::Overloaded,
        ),
        (
            400,
            "invalid_request_error",
            "prompt is too long: 210000 tokens > 200000 maximum",
            LlmErrorKind::ContextLengthExceeded,
        ),
        (
            400,
            "invalid_request_error",
            "bad field",
            LlmErrorKind::InvalidRequest,
        ),
    ] {
        let err = http::decode_error(status, &body(kind, msg), &key);
        assert_eq!(err.kind(), expected, "{kind}: {err:?}");
        assert_eq!(err.status(), Some(status));
        assert_eq!(err.message(), msg);
    }
}

#[test]
fn non_json_error_body_maps_to_status_kind() {
    let err = http::decode_error(502, "upstream connect error", &ApiKey::new("k".into()));
    assert_eq!(err.kind(), LlmErrorKind::Server);
    assert_eq!(err.message(), "upstream connect error");
}

// ── streaming ─────────────────────────────────────────────────────────────────

/// Run `body` through the stream assembler in chunks of `size` bytes.
fn assemble(body: &[u8], size: usize) -> Vec<Result<StreamData, LlmError>> {
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        body.chunks(size).map(|c| Ok(c.to_vec())).collect();
    futures::executor::block_on(
        text_chunks(assemble_events(
            futures::stream::iter(chunks),
            DEFAULT_MAX_STREAM_BYTES,
        ))
        .collect(),
    )
}

/// Run `body` through the typed event assembler in chunks of `size` bytes.
fn events(body: &[u8], size: usize, limit: usize) -> Vec<Result<StreamEvent, LlmError>> {
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        body.chunks(size).map(|c| Ok(c.to_vec())).collect();
    futures::executor::block_on(assemble_events(futures::stream::iter(chunks), limit).collect())
}

const START_TEXT: &str = "data: {\"type\":\"content_block_start\",\"index\":0,\
                          \"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n";

#[test]
fn sse_transcript_yields_text_then_done_at_any_chunking() {
    let body = fixture!("stream.sse").as_bytes();
    for size in [1, 2, 3, 7, 64, body.len()] {
        let chunks: Vec<StreamData> = assemble(body, size)
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap();
        let contents: Vec<&str> = chunks.iter().map(|c| c.content.as_str()).collect();
        assert_eq!(contents, ["Hello", "!", ""], "chunk size {size}");
        assert!(!chunks[0].is_finished);
        assert!(chunks[2].is_finished);
    }
}

#[test]
fn sse_tolerates_crlf_comments_and_unknown_events() {
    let body = "data: {\"type\":\"content_block_start\",\"index\":0,\
                \"content_block\":{\"type\":\"text\",\"text\":\"\"}}\r\n\r\n\
                : keep-alive\r\n\r\nevent: ping\r\ndata: {\"type\":\"ping\"}\r\n\r\n\
                event: future\r\ndata: {\"type\":\"something_new\"}\r\n\r\n\
                data: {\"type\":\"content_block_delta\",\"index\":0,\
                \"delta\":{\"type\":\"text_delta\",\"text\":\"\"}}\r\n\r\n\
                data: {\"type\":\"content_block_delta\",\"index\":0,\
                \"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\r\n\r\n\
                data: {\"type\":\"message_stop\"}\r\n\r\n";
    let items = assemble(body.as_bytes(), 5);
    let contents: Vec<String> = items.into_iter().map(|c| c.unwrap().content).collect();
    assert_eq!(contents, ["hi", ""]);
}

#[test]
fn sse_error_event_ends_the_stream_with_the_provider_message() {
    let body = format!(
        "{START_TEXT}event: content_block_delta\n\
         data: {{\"type\":\"content_block_delta\",\"index\":0,\
         \"delta\":{{\"type\":\"text_delta\",\"text\":\"Hel\"}}}}\n\n\
         event: error\n\
         data: {{\"type\":\"error\",\"error\":{{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}}}\n\n\
         data: {{\"type\":\"message_stop\"}}\n\n"
    );
    let items = assemble(body.as_bytes(), 9);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].as_ref().unwrap().content, "Hel");
    assert!(
        matches!(&items[1], Err(m) if m.kind() == LlmErrorKind::Overloaded && m.message() == "Overloaded")
    );
}

#[test]
fn sse_malformed_data_is_invalid_response() {
    let items = assemble(b"data: {broken\n\ndata: {\"type\":\"message_stop\"}\n\n", 4);
    assert_eq!(items.len(), 1);
    assert!(matches!(&items[0], Err(e) if e.kind() == LlmErrorKind::InvalidResponse));
}

#[test]
fn sse_truncated_stream_is_an_error() {
    let full = fixture!("stream.sse");
    let cut = &full[..full.find("event: message_stop").unwrap()];
    let items = assemble(cut.as_bytes(), 16);
    let (last, chunks) = items.split_last().unwrap();
    assert!(chunks.iter().all(Result::is_ok));
    assert!(
        matches!(last, Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("message_stop"))
    );
}

#[test]
fn sse_transport_error_is_request_failed() {
    let chunks = futures::stream::iter([
        Ok(START_TEXT.as_bytes().to_vec()),
        Ok(b"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"a\"}}\n\n".to_vec()),
        Err(std::io::Error::other("connection reset")),
    ]);
    let items: Vec<_> = futures::executor::block_on(
        text_chunks(assemble_events(chunks, DEFAULT_MAX_STREAM_BYTES)).collect(),
    );
    assert_eq!(items.len(), 2);
    assert!(
        matches!(&items[1], Err(m) if m.kind() == LlmErrorKind::Network && m.message().contains("connection reset"))
    );
}

// ── client ────────────────────────────────────────────────────────────────────

#[test]
fn client_defaults() {
    let llm = Anthropic::new("sk-ant-test");
    assert!(!format!("{llm:?}").contains("sk-ant-test"));
    assert_eq!(llm.max_retries, DEFAULT_MAX_RETRIES);
    assert_eq!(llm.timeout, DEFAULT_TIMEOUT);
    assert_eq!(llm.model, "claude-sonnet-5-5");
    assert_eq!(llm.model_id(), models::DEFAULT_MODEL);
    assert_eq!(
        llm.model_info().map(|m| m.id),
        Some(models::CLAUDE_SONNET_5_5)
    );
    assert!(llm.max_tokens.is_none());
    assert_eq!(llm.base_url, DEFAULT_BASE_URL);
    assert!(llm.temperature.is_none());
    let _: Box<dyn Llm> = Box::new(llm);
}

#[test]
fn max_tokens_defaults_suit_thinking_models() {
    let llm = Anthropic::new("k");
    let blocking = body_for(&llm, None);
    let streaming = body_for(&llm, Some(true));
    assert_eq!(blocking["max_tokens"], DEFAULT_MAX_TOKENS);
    assert_eq!(streaming["max_tokens"], DEFAULT_STREAM_MAX_TOKENS);

    // Every known model can take the default budgets in full or capped.
    for info in models::KNOWN_MODELS {
        let llm = Anthropic::new("k").model(info.id);
        for stream in [None, Some(true)] {
            let sent = body_for(&llm, stream)["max_tokens"].as_u64().unwrap();
            assert!(sent <= u64::from(info.max_output_tokens), "{}", info.id);
            assert!(sent >= u64::from(DEFAULT_MAX_TOKENS), "{}", info.id);
        }
    }

    // Unknown models get the defaults; an explicit value always wins.
    let unknown = Anthropic::new("k").model("claude-next");
    assert_eq!(
        body_for(&unknown, Some(true))["max_tokens"],
        DEFAULT_STREAM_MAX_TOKENS
    );
    let explicit = Anthropic::new("k").max_tokens(300);
    assert_eq!(body_for(&explicit, None)["max_tokens"], 300);
    assert_eq!(body_for(&explicit, Some(true))["max_tokens"], 300);
}

#[test]
fn base_url_trims_trailing_slash() {
    assert_eq!(
        Anthropic::new("k").base_url("http://h:1/").base_url,
        "http://h:1"
    );
}

fn body_for(llm: &Anthropic, stream: Option<bool>) -> Value {
    serde_json::to_value(llm.request_body(&[Message::human("Hi")], &[], None, stream)).unwrap()
}

// ── model capability pre-flight ───────────────────────────────────────────────

#[test]
fn model_is_free_form() {
    let llm = Anthropic::new("k").model("claude-from-the-future");
    assert_eq!(llm.model_id(), "claude-from-the-future");
    assert!(llm.model_info().is_none());
    // Unknown ids are never second-guessed, whatever the settings.
    let llm = llm.temperature(0.5);
    assert!(
        llm.preflight(&[], Some(&ToolChoice::Required), false)
            .is_ok()
    );
}

#[test]
fn preflight_rejects_temperature_on_models_without_sampling() {
    for id in [
        models::CLAUDE_FABLE_5_2,
        models::CLAUDE_OPUS_5_5,
        models::CLAUDE_SONNET_5_5,
        models::CLAUDE_HAIKU_5_5,
    ] {
        let err = Anthropic::new("k")
            .model(id)
            .temperature(0.3)
            .preflight(&[], None, false)
            .unwrap_err();
        assert!(
            matches!(&err, m if m.kind() == LlmErrorKind::Other && m.message().contains(id)),
            "{err}"
        );
        assert!(
            Anthropic::new("k")
                .model(id)
                .preflight(&[], None, false)
                .is_ok()
        );
    }
    for id in [models::CLAUDE_SONNET_4_6, models::CLAUDE_HAIKU_4_5] {
        assert!(
            Anthropic::new("k")
                .model(id)
                .temperature(0.3)
                .preflight(&[], None, false)
                .is_ok()
        );
    }
}

#[test]
fn preflight_rejects_forced_tool_choice_where_unsupported() {
    let forced = [ToolChoice::Required, ToolChoice::Tool("echo".into())];
    for choice in &forced {
        let llm = Anthropic::new("k").model(models::CLAUDE_OPUS_5_5);
        assert!(matches!(
            llm.preflight(&[], Some(choice), false),
            Err(e) if e.kind() == LlmErrorKind::Other
        ));
        let llm = Anthropic::new("k").model(models::CLAUDE_OPUS_5);
        assert!(llm.preflight(&[], Some(choice), false).is_ok());
    }
    let llm = Anthropic::new("k").model(models::CLAUDE_SONNET_5_5);
    assert!(llm.preflight(&[], Some(&ToolChoice::Auto), false).is_ok());
    assert!(llm.preflight(&[], Some(&ToolChoice::None), false).is_ok());
}

#[test]
fn preflight_failure_short_circuits_every_entry_point() {
    // The API key is bogus and the URL is real: reaching the network would
    // yield a different error (or hang), so `Other` proves nothing was sent.
    let llm = Anthropic::new("k")
        .model(models::CLAUDE_OPUS_5_5)
        .temperature(1.0);
    let msgs = [Message::human("Hi")];
    tokio_test::block_on(async {
        assert!(matches!(llm.generate(&msgs).await, Err(e) if e.kind() == LlmErrorKind::Other));
        assert!(matches!(
            llm.generate_with_tools(&msgs, &[], None).await,
            Err(e) if e.kind() == LlmErrorKind::Other
        ));
        assert!(matches!(llm.stream(&msgs).await, Err(e) if e.kind() == LlmErrorKind::Other));
    });
}

#[test]
fn huge_usage_saturates_instead_of_overflowing() {
    // Regression: `input_tokens + output_tokens` overflowed (a panic in debug
    // builds) on counts near `u32::MAX` from a misbehaving server.
    let body = format!(
        r#"{{"content":[{{"type":"text","text":"ok"}}],"usage":{{"input_tokens":{},"output_tokens":{}}}}}"#,
        u32::MAX,
        7
    );
    let tokens = decode_response(body.as_bytes())
        .unwrap()
        .to_generate_result()
        .tokens
        .unwrap();
    assert_eq!(tokens.total_tokens, u32::MAX);
    assert_eq!(tokens.completion_tokens, 7);
}

// ── prompt caching ────────────────────────────────────────────────────────────

#[test]
fn cache_policy_places_breakpoints_on_tools_system_and_tail() {
    let tools = [
        FunctionDefinition::single_input("a", "A."),
        FunctionDefinition::single_input("b", "B."),
    ];
    let llm = Anthropic::new("k").model("claude-test").cache(
        CachePolicy::none()
            .with_tools(CacheTtl::OneHour)
            .with_system(CacheTtl::OneHour)
            .with_messages(CacheTtl::FiveMinutes),
    );
    let v = serde_json::to_value(llm.request_body(
        &[
            Message::system("Long stable manual."),
            Message::human("First"),
            Message::ai("Reply"),
            Message::human("Second"),
        ],
        &tools,
        None,
        None,
    ))
    .unwrap();
    assert!(v["tools"][0].get("cache_control").is_none());
    assert_eq!(
        v["tools"][1]["cache_control"],
        json!({ "type": "ephemeral", "ttl": "1h" })
    );
    assert_eq!(
        v["system"],
        json!([{ "type": "text", "text": "Long stable manual.",
                 "cache_control": { "type": "ephemeral", "ttl": "1h" } }])
    );
    assert_eq!(v["messages"][0]["content"], "First");
    assert_eq!(
        v["messages"][2]["content"],
        json!([{ "type": "text", "text": "Second", "cache_control": { "type": "ephemeral" } }])
    );
}

#[test]
fn cache_breakpoint_lands_on_the_last_tool_result() {
    let llm = Anthropic::new("k")
        .model("claude-test")
        .cache(CachePolicy::all(CacheTtl::FiveMinutes));
    let v = serde_json::to_value(llm.request_body(
        &[
            Message::human("Weather?"),
            Message::ai_with_tool_calls(
                "",
                vec![
                    ToolCall::new("t1", "w", "{}"),
                    ToolCall::new("t2", "w", "{}"),
                ],
            ),
            Message::tool_result("t1", "sunny"),
            Message::tool_result("t2", "rainy"),
        ],
        &[],
        None,
        None,
    ))
    .unwrap();
    // Parallel results share one user message; only the last block is marked.
    let content = &v["messages"][2]["content"];
    assert_eq!(content.as_array().unwrap().len(), 2);
    assert!(content[0].get("cache_control").is_none());
    assert_eq!(content[1]["cache_control"], json!({ "type": "ephemeral" }));
    // No system prompt and no tools: nothing else to mark.
    assert!(v.get("system").is_none());
    assert!(v.get("tools").is_none());
}

#[test]
fn cache_ttl_order_is_checked_before_sending() {
    let bad = Anthropic::new("k").cache(
        CachePolicy::none()
            .with_system(CacheTtl::FiveMinutes)
            .with_messages(CacheTtl::OneHour),
    );
    assert!(
        matches!(bad.preflight(&[], None, false), Err(m) if m.kind() == LlmErrorKind::Other && m.message().contains("one-hour"))
    );
    let good = Anthropic::new("k").cache(
        CachePolicy::none()
            .with_system(CacheTtl::OneHour)
            .with_messages(CacheTtl::FiveMinutes),
    );
    assert!(good.preflight(&[], None, false).is_ok());
    assert!(CachePolicy::default().is_empty());
}

#[test]
fn usage_counts_cache_reads_and_writes_in_the_prompt() {
    let body = br#"{"id":"m","model":"x","content":[{"type":"text","text":"ok"}],
        "stop_reason":"end_turn",
        "usage":{"input_tokens":10,"cache_creation_input_tokens":2000,
                 "cache_read_input_tokens":30000,"output_tokens":5}}"#;
    let message = decode_response(body).unwrap();
    assert_eq!(*message.usage(), Usage::new(10, 5, 2000, 30000));
    let tokens = message.to_generate_result().tokens.unwrap();
    assert_eq!(tokens.prompt_tokens, 32_010);
    assert_eq!(tokens.total_tokens, 32_015);

    // `null` cache fields read as zero.
    let body = br#"{"content":[],"usage":{"input_tokens":1,"output_tokens":1,
        "cache_creation_input_tokens":null,"cache_read_input_tokens":null}}"#;
    assert_eq!(
        decode_response(body).unwrap().usage.cache_read_input_tokens,
        0
    );
}

// ── thinking and effort ───────────────────────────────────────────────────────

#[test]
fn thinking_and_effort_serialize_to_the_wire_format() {
    let llm = Anthropic::new("k")
        .model("claude-test")
        .thinking(Thinking::adaptive().with_display(ThinkingDisplay::Summarized))
        .effort(Effort::Xhigh);
    let v = body_for(&llm, None);
    assert_eq!(
        v["thinking"],
        json!({ "type": "adaptive", "display": "summarized" })
    );
    assert_eq!(v["output_config"], json!({ "effort": "xhigh" }));

    let v = body_for(&Anthropic::new("k").thinking(Thinking::budget(2048)), None);
    assert_eq!(
        v["thinking"],
        json!({ "type": "enabled", "budget_tokens": 2048 })
    );
    let v = body_for(&Anthropic::new("k").thinking(Thinking::Disabled), None);
    assert_eq!(v["thinking"], json!({ "type": "disabled" }));
    assert!(
        body_for(&Anthropic::new("k"), None)
            .get("output_config")
            .is_none()
    );
}

#[test]
fn preflight_checks_thinking_modes_per_model() {
    let check = |id: &str, t: Thinking| {
        Anthropic::new("k")
            .model(id)
            .thinking(t)
            .preflight(&[], None, false)
    };
    assert!(check(models::CLAUDE_OPUS_5_5, Thinking::adaptive()).is_ok());
    assert!(check(models::CLAUDE_OPUS_5_5, Thinking::budget(4096)).is_err());
    assert!(check(models::CLAUDE_OPUS_5_5, Thinking::Disabled).is_err());
    assert!(check(models::CLAUDE_FABLE_5_2, Thinking::Disabled).is_err());
    assert!(check(models::CLAUDE_SONNET_5_5, Thinking::Disabled).is_err());
    assert!(check(models::CLAUDE_OPUS_5, Thinking::Disabled).is_ok());
    assert!(check(models::CLAUDE_SONNET_4_6, Thinking::budget(4096)).is_ok());
    assert!(check(models::CLAUDE_HAIKU_4_5, Thinking::budget(4096)).is_ok());
    assert!(check(models::CLAUDE_HAIKU_4_5, Thinking::adaptive()).is_err());
    // Generic budget rules apply to unknown models too.
    assert!(check("claude-next", Thinking::budget(512)).is_err());
    let over = Anthropic::new("k")
        .model("claude-next")
        .max_tokens(2000)
        .thinking(Thinking::budget(2000));
    assert!(over.preflight(&[], None, false).is_err());
    // Forced tool use is incompatible with thinking.
    let forced = Anthropic::new("k")
        .model("claude-next")
        .thinking(Thinking::adaptive());
    assert!(
        forced
            .preflight(&[], Some(&ToolChoice::Required), false)
            .is_err()
    );
    assert!(
        forced
            .preflight(&[], Some(&ToolChoice::Auto), false)
            .is_ok()
    );
}

// ── transport hardening ───────────────────────────────────────────────────────

#[test]
fn base_url_must_be_https_unless_loopback() {
    for ok in [
        "https://api.anthropic.com",
        "https://gateway.internal:8443/prefix",
        "http://localhost:8080",
        "http://LOCALHOST",
        "http://127.0.0.1:9",
        "http://[::1]:9",
    ] {
        assert!(http::check_base_url(ok).is_ok(), "{ok}");
    }
    for bad in [
        "http://api.anthropic.com",
        "http://10.0.0.1",
        "http://localhost.evil.com",
        "ftp://localhost",
        "https://user:pw@api.anthropic.com",
        "not a url",
    ] {
        assert!(
            matches!(http::check_base_url(bad), Err(e) if e.kind() == LlmErrorKind::Other),
            "{bad}"
        );
    }
    let llm = Anthropic::new("k").base_url("http://api.anthropic.com");
    let err = tokio_test::block_on(llm.generate(&[Message::human("Hi")])).unwrap_err();
    assert!(
        matches!(err, m if m.kind() == LlmErrorKind::Other && m.message().contains("plain HTTP"))
    );
}

#[test]
fn api_key_never_leaks() {
    let secret = "sk-ant-api03-SECRETSECRETSECRET";
    let key = ApiKey::new(secret.into());
    assert_eq!(format!("{key:?}"), "ApiKey([REDACTED])");
    assert!(key.header_value().unwrap().is_sensitive());
    let llm = Anthropic::new(secret);
    assert!(!format!("{llm:?}").contains("SECRET"));
    let err = http::decode_error(
        401,
        &format!(
            r#"{{"type":"error","error":{{"type":"authentication_error","message":"bad key {secret}"}}}}"#
        ),
        &key,
    );
    assert!(
        matches!(&err, m if m.kind() == LlmErrorKind::Auth && m.message() == "bad key [REDACTED]"),
        "{err:?}"
    );
    assert!(!err.to_string().contains("SECRET"));
    assert!(ApiKey::new("bad\nkey".into()).header_value().is_err());
}

#[test]
fn error_bodies_are_truncated() {
    let key = ApiKey::new("k".into());
    let long = "é".repeat(5000);
    let err = http::decode_error(502, &long, &key);
    assert_eq!(err.kind(), LlmErrorKind::Server);
    let m = err.message();
    assert!(m.ends_with("[truncated]"));
    assert!(m.chars().count() < 1100);
    let err = http::decode_error(503, "  ", &key);
    assert_eq!(err.kind(), LlmErrorKind::Overloaded);
    assert!(err.message().contains("503"));
}

#[test]
fn retry_policy_honours_retry_after() {
    use reqwest::header::HeaderMap;
    for status in [408, 409, 429, 500, 502, 503, 529] {
        assert!(http::is_retryable(status), "{status}");
    }
    for status in [400, 401, 403, 404, 413] {
        assert!(!http::is_retryable(status), "{status}");
    }
    let mut h = HeaderMap::new();
    h.insert("retry-after", HeaderValue::from_static("2"));
    assert_eq!(http::retry_delay(0, &h), Some(Duration::from_secs(2)));
    h.insert("retry-after-ms", HeaderValue::from_static("150"));
    assert_eq!(http::retry_delay(0, &h), Some(Duration::from_millis(150)));
    let mut long = HeaderMap::new();
    long.insert("retry-after", HeaderValue::from_static("3600"));
    assert_eq!(http::retry_delay(0, &long), None);
    let mut junk = HeaderMap::new();
    junk.insert(
        "retry-after",
        HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
    );
    let none = HeaderMap::new();
    for attempt in [0, 1, 5, 40, u32::MAX] {
        for h in [&none, &junk] {
            let d = http::retry_delay(attempt, h).unwrap();
            assert!(
                d >= Duration::from_millis(375) && d <= Duration::from_secs(8),
                "{d:?}"
            );
        }
    }
}

#[test]
fn parallel_tool_results_share_one_user_message() {
    let v = body(
        &[
            Message::human("Weather?"),
            Message::ai_with_tool_calls(
                "",
                vec![ToolCall::new("a", "w", "{}"), ToolCall::new("b", "w", "")],
            ),
            Message::tool_result("a", "1"),
            Message::tool_result("b", "2"),
            Message::human("Thanks"),
        ],
        &[],
        None,
    );
    let msgs = v["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 4);
    assert_eq!(msgs[1]["content"][1]["input"], json!({}));
    assert_eq!(msgs[2]["content"].as_array().unwrap().len(), 2);
    assert_eq!(msgs[3]["content"], "Thanks");
}

#[test]
fn invalid_images_fail_before_sending() {
    let msg = Message::human(MessageContent::Parts(vec![ContentPart::image_url(
        "file:///etc/passwd",
    )]));
    let err = Anthropic::new("k")
        .preflight(&[msg], None, false)
        .unwrap_err();
    assert!(matches!(err, m if m.kind() == LlmErrorKind::Other && m.message().contains("image")));
}

// ── structured output ─────────────────────────────────────────────────────────

fn schema() -> ResponseFormat {
    ResponseFormat::json_schema(
        "city answer!",
        json!({ "type": "object", "properties": { "name": { "type": "string" } },
                "required": ["name"], "additionalProperties": false }),
    )
}

fn plan(llm: &Anthropic, format: &ResponseFormat) -> &'static str {
    match llm.plan_structured(format) {
        Ok(Plan::Native(_)) => "native",
        Ok(Plan::ForcedTool { .. }) => "tool",
        Ok(Plan::Prompt) => "prompt",
        Err(_) => "error",
    }
}

#[test]
fn structured_output_strategy_follows_model_capabilities() {
    let llm = |id: &str| Anthropic::new("k").model(id);
    let object = ResponseFormat::JsonObject;
    assert_eq!(plan(&llm(models::CLAUDE_SONNET_5_5), &schema()), "native");
    assert_eq!(plan(&llm(models::CLAUDE_OPUS_5_5), &schema()), "native");
    assert_eq!(plan(&llm("claude-next"), &schema()), "native");
    assert_eq!(plan(&llm(models::CLAUDE_OPUS_4_6), &schema()), "tool");
    assert_eq!(
        plan(
            &llm(models::CLAUDE_OPUS_4_6).thinking(Thinking::adaptive()),
            &schema()
        ),
        "prompt"
    );
    assert_eq!(plan(&llm(models::CLAUDE_SONNET_5_5), &object), "prompt");
    assert_eq!(plan(&llm(models::CLAUDE_HAIKU_4_5), &object), "tool");
    assert_eq!(
        plan(&llm(models::CLAUDE_OPUS_5_5), &ResponseFormat::Text),
        "prompt"
    );
    let native = llm(models::CLAUDE_SONNET_5_5).structured_output(StructuredOutput::Native);
    assert_eq!(plan(&native, &object), "error");
    let forced = llm(models::CLAUDE_SONNET_5_5).structured_output(StructuredOutput::ForcedTool);
    assert_eq!(plan(&forced, &schema()), "tool");
    let prompt = llm(models::CLAUDE_SONNET_5_5).structured_output(StructuredOutput::Prompt);
    assert_eq!(plan(&prompt, &schema()), "prompt");
}

#[test]
fn forced_tool_schemas_are_objects_with_valid_names() {
    assert_eq!(tool_name("city answer!"), "cityanswer");
    assert_eq!(tool_name("!!!"), JSON_OBJECT_TOOL);
    assert_eq!(tool_name(&"x".repeat(100)).len(), 64);

    let (s, wrapped) = object_schema(&json!({ "type": "object" }));
    assert!(!wrapped);
    assert_eq!(s, json!({ "type": "object" }));
    let (s, wrapped) = object_schema(&json!({
        "type": "array", "items": { "$ref": "#/$defs/item" },
        "$defs": { "item": { "type": "string" } }
    }));
    assert!(wrapped);
    assert_eq!(s["type"], "object");
    assert_eq!(s["$defs"]["item"]["type"], "string");
    assert_eq!(s["properties"]["value"]["type"], "array");
    assert!(s["properties"]["value"].get("$defs").is_none());
}

#[test]
fn count_tokens_body_drops_generation_settings() {
    let llm = Anthropic::new("k")
        .model("claude-test")
        .max_tokens(10)
        .thinking(Thinking::adaptive());
    let req = llm.request_body(
        &[Message::system("S"), Message::human("Hi")],
        &[],
        None,
        Some(true),
    );
    let v = serde_json::to_value(CountTokensRequest::from(&req)).unwrap();
    assert_eq!(
        v,
        json!({
            "model": "claude-test",
            "system": "S",
            "messages": [{ "role": "user", "content": "Hi" }],
            "thinking": { "type": "adaptive" },
        })
    );
}

// ── stream assembly ───────────────────────────────────────────────────────────

#[test]
fn stream_fixture_assembles_text_tool_call_and_usage_at_any_chunking() {
    let body = fixture!("stream.sse").as_bytes();
    for size in [1, 2, 5, 13, body.len()] {
        let out: Vec<StreamEvent> = events(body, size, DEFAULT_MAX_STREAM_BYTES)
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(out.len(), 4, "chunk size {size}");
        assert_eq!(out[0], StreamEvent::Text("Hello".into()));
        assert_eq!(out[1], StreamEvent::Text("!".into()));
        let StreamEvent::ToolCall(call) = &out[2] else {
            panic!("{:?}", out[2])
        };
        assert_eq!(call.name, "get_weather");
        assert_eq!(call.arg("city"), Some(json!("Paris")));
        let StreamEvent::Done(message) = &out[3] else {
            panic!("{:?}", out[3])
        };
        assert_eq!(message.text(), "Hello!");
        assert_eq!(message.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(*message.usage(), Usage::new(25, 15, 0, 2048));
        assert_eq!(message.tool_calls(), vec![call.clone()]);
    }
}

fn push_all(lines: &[&str]) -> Result<Vec<StreamEvent>, LlmError> {
    let mut acc = MessageAccumulator::new();
    let mut out = Vec::new();
    for line in lines {
        out.extend(acc.push(line)?);
    }
    Ok(out)
}

const MSG_START: &str =
    r#"{"type":"message_start","message":{"id":"m","model":"x","usage":{"input_tokens":1}}}"#;

#[test]
fn thinking_deltas_stay_out_of_the_text() {
    let out = push_all(&[
        MSG_START,
        r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}"#,
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Paris is the capital."}}"#,
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig"}}"#,
        r#"{"type":"content_block_stop","index":0}"#,
        r#"{"type":"content_block_start","index":1,"content_block":{"type":"redacted_thinking","data":"opaque"}}"#,
        r#"{"type":"content_block_stop","index":1}"#,
        r#"{"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}"#,
        r#"{"type":"content_block_delta","index":2,"delta":{"type":"citations_delta","citation":{}}}"#,
        r#"{"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"Paris."}}"#,
        r#"{"type":"content_block_stop","index":2}"#,
        r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":9}}"#,
        r#"{"type":"message_stop"}"#,
    ])
    .unwrap();
    assert_eq!(
        out[0],
        StreamEvent::Thinking("Paris is the capital.".into())
    );
    assert_eq!(out[1], StreamEvent::Text("Paris.".into()));
    let StreamEvent::Done(m) = &out[2] else {
        panic!()
    };
    assert_eq!(m.text(), "Paris.");
    assert_eq!(m.thinking(), "Paris is the capital.");
    assert_eq!(
        m.content[0],
        ContentBlock::Thinking {
            thinking: "Paris is the capital.".into(),
            signature: "sig".into()
        }
    );
    assert_eq!(
        m.content[1],
        ContentBlock::RedactedThinking {
            data: "opaque".into()
        }
    );
}

#[test]
fn tool_input_edge_cases() {
    let tool_start = r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"noop","input":{}}}"#;
    let stop = r#"{"type":"content_block_stop","index":0}"#;
    // No deltas: the tool takes no arguments.
    let out = push_all(&[MSG_START, tool_start, stop]).unwrap();
    assert!(matches!(&out[0], StreamEvent::ToolCall(c) if c.arguments == "{}"));
    // Truncated JSON is an error, not a silent `{}`.
    let cut = r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"a\": "}}"#;
    assert!(matches!(
        push_all(&[MSG_START, tool_start, cut, stop]),
        Err(e) if e.kind() == LlmErrorKind::InvalidResponse
    ));
    // Valid JSON that is not an object is rejected.
    let arr = r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"[1]"}}"#;
    assert!(push_all(&[MSG_START, tool_start, arr, stop]).is_err());
}

#[test]
fn protocol_violations_are_errors_not_panics() {
    let text_start =
        r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#;
    let json_delta = r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}"#;
    let far_delta = r#"{"type":"content_block_delta","index":18446744073709551615,"delta":{"type":"text_delta","text":"x"}}"#;
    let far_start = r#"{"type":"content_block_start","index":99999999999,"content_block":{"type":"text","text":""}}"#;
    let stop = r#"{"type":"content_block_stop","index":0}"#;
    let text_delta =
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x"}}"#;
    let message_stop = r#"{"type":"message_stop"}"#;
    for case in [
        vec![MSG_START, text_start, json_delta],
        vec![MSG_START, far_delta],
        vec![MSG_START, far_start],
        vec![MSG_START, text_start, stop, text_delta],
        vec![MSG_START, text_start, stop, stop],
        vec![MSG_START, MSG_START],
        vec![MSG_START, message_stop, text_start],
        vec!["{\"type\":\"content_block_delta\"}"],
        vec!["[]"],
    ] {
        assert!(
            matches!(push_all(&case), Err(e) if e.kind() == LlmErrorKind::InvalidResponse),
            "{case:?}"
        );
    }
    let mut acc = MessageAccumulator::new();
    acc.push(MSG_START).unwrap();
    assert!(!acc.is_finished());
    assert!(acc.finish().is_err());
}

#[test]
fn stream_content_is_capped() {
    let mut acc = MessageAccumulator::with_limit(8);
    acc.push(
        r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
    )
    .unwrap();
    let delta =
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"12345"}}"#;
    assert!(acc.push(delta).is_ok());
    assert!(
        matches!(acc.push(delta), Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("limit"))
    );

    let body = fixture!("stream.sse").as_bytes();
    let out = events(body, 64, 4);
    assert!(matches!(
        out.last(),
        Some(Err(e)) if e.kind() == LlmErrorKind::InvalidResponse
    ));
}

proptest::proptest! {
    #[test]
    fn arbitrary_stream_bytes_never_panic(body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512), size in 1usize..32) {
        let out = events(&body, size, 1024);
        // Always terminates with exactly one error or a Done.
        let last = out.last().unwrap();
        proptest::prop_assert!(last.is_err() || matches!(last, Ok(StreamEvent::Done(_))));
        proptest::prop_assert!(out[..out.len() - 1].iter().all(Result::is_ok));
    }

    #[test]
    fn arbitrary_event_json_never_panics(data in "\\{\"type\":\"(content_block_(start|delta|stop)|message_(start|delta|stop)|ping)\",\"index\":[0-9]{1,3}(,\"delta\":\\{\"type\":\"(text_delta|input_json_delta|thinking_delta)\",\"(text|partial_json|thinking)\":\"[a-z{}\\[\\]:,]{0,6}\"\\})?(,\"content_block\":\\{\"type\":\"(text|tool_use|thinking)\",\"text\":\"\",\"id\":\"i\",\"name\":\"n\",\"input\":\\{\\}\\})?\\}", n in 1usize..6) {
        let mut acc = MessageAccumulator::with_limit(4096);
        for _ in 0..n {
            let _ = acc.push(&data);
        }
    }
}
