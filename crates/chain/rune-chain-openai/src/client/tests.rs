//! Wire-format tests against recorded `OpenAI` chat completions fixtures.
//! None of them touch the network.

use rune_chain_core::Llm;
use rune_chain_core::LlmErrorKind;
use serde_json::{Value, json};

use super::*;
use crate::StreamEvent;

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/", $name))
    };
}

fn body(
    llm: &OpenAi,
    messages: &[Message],
    tools: &[FunctionDefinition],
    choice: Option<&ToolChoice>,
) -> Value {
    serde_json::to_value(llm.request_body(
        messages,
        BodyOptions {
            tools,
            tool_choice: choice,
            ..BodyOptions::default()
        },
    ))
    .unwrap()
}

fn stream_body(llm: &OpenAi, include_usage: bool) -> Value {
    serde_json::to_value(llm.request_body(
        &[Message::human("x")],
        BodyOptions {
            stream: true,
            include_usage,
            ..BodyOptions::default()
        },
    ))
    .unwrap()
}

// ── request building ──────────────────────────────────────────────────────────

#[test]
fn minimal_request_omits_optional_fields() {
    let v = body(&OpenAi::new("k"), &[Message::human("Hi")], &[], None);
    assert_eq!(
        v,
        json!({
            "model": "gpt-5-mini",
            "messages": [{ "role": "user", "content": "Hi" }],
        })
    );
}

#[test]
fn builder_settings_reach_the_request() {
    let llm = OpenAi::new("k")
        .model("gpt-4o-mini")
        .temperature(0.5)
        .max_tokens(32);
    let v = stream_body(&llm, false);
    assert_eq!(v["model"], "gpt-4o-mini");
    assert_eq!(v["temperature"], 0.5);
    assert_eq!(v["max_completion_tokens"], 32);
    assert!(v.get("max_tokens").is_none());
    assert_eq!(v["stream"], true);
}

#[test]
fn roles_map_to_openai_names() {
    let v = body(
        &OpenAi::new("k"),
        &[
            Message::system("s"),
            Message::human("h"),
            Message::ai("a"),
            Message::tool_result("call_1", "t"),
        ],
        &[],
        None,
    );
    let roles: Vec<&str> = v["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles, ["system", "user", "assistant", "tool"]);
    assert_eq!(v["messages"][3]["tool_call_id"], "call_1");
}

#[test]
fn empty_text_serializes_as_null_content() {
    // OpenAI requires `content: null` (not "") on assistant tool-call turns.
    let v = body(
        &OpenAi::new("k"),
        &[Message::ai_with_tool_calls(
            "",
            vec![ToolCall::new("call_1", "get_time", "{}")],
        )],
        &[],
        None,
    );
    assert_eq!(
        v["messages"][0],
        json!({
            "role": "assistant",
            "content": null,
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": { "name": "get_time", "arguments": "{}" },
            }],
        })
    );
}

#[test]
fn images_become_image_url_parts_with_data_urls() {
    let msg = Message::human(MessageContent::Parts(vec![
        ContentPart::text("Compare."),
        ContentPart::image_url("https://example.com/a.png"),
        ContentPart::image_base64("image/png", "iVBORw0KGgo="),
    ]));
    let v = body(&OpenAi::new("k"), &[msg], &[], None);
    assert_eq!(
        v["messages"][0]["content"],
        json!([
            { "type": "text", "text": "Compare." },
            { "type": "image_url", "image_url": { "url": "https://example.com/a.png" } },
            { "type": "image_url", "image_url": { "url": "data:image/png;base64,iVBORw0KGgo=" } },
        ])
    );
}

#[test]
fn tools_and_tool_choice_use_function_wrappers() {
    let tools = [FunctionDefinition::single_input(
        "upper",
        "Upper-case text.",
    )];
    let llm = OpenAi::new("k");
    let v = body(&llm, &[Message::human("x")], &tools, None);
    assert_eq!(
        v["tools"],
        json!([{
            "type": "function",
            "function": {
                "name": "upper",
                "description": "Upper-case text.",
                "parameters": tools[0].parameters,
            },
        }])
    );
    assert!(v.get("tool_choice").is_none());

    for (choice, expected) in [
        (ToolChoice::Auto, json!("auto")),
        (ToolChoice::None, json!("none")),
        (ToolChoice::Required, json!("required")),
        (
            ToolChoice::Tool("upper".into()),
            json!({ "type": "function", "function": { "name": "upper" } }),
        ),
    ] {
        let v = body(&llm, &[Message::human("x")], &tools, Some(&choice));
        assert_eq!(v["tool_choice"], expected, "{choice:?}");
    }
}

// ── response decoding ─────────────────────────────────────────────────────────

#[test]
fn decodes_text_completion_with_usage() {
    let result = decode_response(fixture!("chat_text.json").as_bytes()).unwrap();
    assert_eq!(result.generation, "2 + 2 = 4.");
    assert!(!result.wants_tool_calls());
    let tokens = result.tokens.unwrap();
    assert_eq!(
        (
            tokens.prompt_tokens,
            tokens.completion_tokens,
            tokens.total_tokens
        ),
        (19, 8, 27)
    );
}

#[test]
fn decodes_parallel_tool_calls_with_null_content() {
    let result = decode_response(fixture!("chat_tool_calls.json").as_bytes()).unwrap();
    assert_eq!(result.generation, "");
    assert_eq!(result.tool_calls.len(), 2);
    assert_eq!(result.tool_calls[0].id, "call_abc123");
    assert_eq!(result.tool_calls[0].name, "get_current_weather");
    assert_eq!(
        result.tool_calls[0].arg("location"),
        Some(json!("Boston, MA"))
    );
    assert_eq!(
        result.tool_calls[1].arg("tz"),
        Some(json!("America/New_York"))
    );
    assert_eq!(result.tokens.unwrap().total_tokens, 99);
}

#[test]
fn empty_choices_and_missing_usage_are_tolerated() {
    let result = decode_response(br#"{"choices": []}"#).unwrap();
    assert_eq!(result.generation, "");
    assert!(result.tokens.is_none());
}

#[test]
fn malformed_response_is_invalid_response() {
    for body in ["", "[]", r#"{"choices": [{"message": {}}]}"#] {
        assert!(
            matches!(
                decode_response(body.as_bytes()),
                Err(e) if e.kind() == LlmErrorKind::InvalidResponse
            ),
            "{body:?}"
        );
    }
}

// ── error mapping ─────────────────────────────────────────────────────────────

#[test]
fn api_error_body_maps_to_classified_error() {
    let err = decode_error(401, fixture!("error_invalid_key.json").as_bytes(), None);
    assert_eq!(err.kind(), LlmErrorKind::Auth, "{err:?}");
    assert_eq!(err.status(), Some(401));
    assert!(err.message().starts_with("Incorrect API key provided"));
    assert!(err.message().ends_with("(HTTP 401)"));
    assert!(!err.is_retryable());
}

#[test]
fn non_json_error_body_maps_to_status_kind() {
    let err = decode_error(502, b"<html>502 Bad Gateway</html>", None);
    assert_eq!(err.kind(), LlmErrorKind::Server);
    assert_eq!(err.status(), Some(502));
    assert!(err.message().starts_with("HTTP 502: <html>"));
    assert!(err.is_retryable());
}

#[test]
fn error_codes_refine_the_kind() {
    let wait = Some(Duration::from_secs(7));
    let rate = br#"{"error":{"message":"Rate limit reached for gpt-4o","type":"requests","code":"rate_limit_exceeded"}}"#;
    let err = decode_error(429, rate, wait);
    assert_eq!(err.kind(), LlmErrorKind::RateLimit);
    assert_eq!(err.retry_after(), wait);
    assert!(err.is_retryable());

    let quota = br#"{"error":{"message":"You exceeded your current quota","type":"insufficient_quota","code":"insufficient_quota"}}"#;
    let err = decode_error(429, quota, None);
    assert_eq!(err.kind(), LlmErrorKind::Auth);
    assert_eq!(err.status(), Some(429));
    assert!(!err.is_retryable());

    let ctx = br#"{"error":{"message":"This model's maximum context length is 128000 tokens.","type":"invalid_request_error","code":"context_length_exceeded"}}"#;
    let err = decode_error(400, ctx, None);
    assert!(err.is_context_length_exceeded());

    let err = decode_error(503, br#"{"error":{"message":"busy"}}"#, None);
    assert_eq!(err.kind(), LlmErrorKind::Overloaded);
}

// ── streaming ─────────────────────────────────────────────────────────────────

/// Run `body` through the event assembler in chunks of `size` bytes.
fn events(body: &[u8], size: usize) -> Vec<Result<StreamEvent, LlmError>> {
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        body.chunks(size).map(|c| Ok(c.to_vec())).collect();
    futures::executor::block_on(
        stream::assemble_events(futures::stream::iter(chunks), 1 << 20).collect(),
    )
}

/// Run `body` through the `Llm::stream` adapter in chunks of `size` bytes.
fn assemble(body: &[u8], size: usize) -> Vec<Result<StreamData, LlmError>> {
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        body.chunks(size).map(|c| Ok(c.to_vec())).collect();
    futures::executor::block_on(
        stream::text_stream(stream::assemble_events(
            futures::stream::iter(chunks),
            1 << 20,
        ))
        .collect(),
    )
}

fn push(data: &str) -> Result<Vec<StreamEvent>, LlmError> {
    stream::Assembler::default().push(data)
}

#[test]
fn sse_transcript_yields_text_then_done_at_any_chunking() {
    let body = fixture!("stream.sse").as_bytes();
    for size in [1, 2, 3, 7, 64, body.len()] {
        let chunks: Vec<StreamData> = assemble(body, size)
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap();
        let contents: Vec<&str> = chunks.iter().map(|c| c.content.as_str()).collect();
        // The `finish_reason: "stop"` chunk ends the text stream.
        assert_eq!(contents, ["Hello", " there", ""], "chunk size {size}");
        assert!(chunks[2].is_finished);
    }
}

#[test]
fn streamed_tool_call_deltas_are_assembled_with_usage() {
    let body = fixture!("stream_tool_calls.sse").as_bytes();
    for size in [1, 5, 13, body.len()] {
        let items: Vec<StreamEvent> = events(body, size)
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(items.len(), 4, "chunk size {size}: {items:?}");
        let StreamEvent::ToolCalls(calls) = &items[0] else {
            panic!("{items:?}")
        };
        assert_eq!(calls.len(), 2);
        assert_eq!(
            (calls[0].id.as_str(), calls[0].name.as_str()),
            ("call_a", "get_weather")
        );
        assert_eq!(calls[0].arg("location"), Some(json!("Oslo")));
        assert_eq!(calls[1].id, "call_b");
        assert_eq!(calls[1].arg("tz"), Some(json!("UTC")));
        assert!(matches!(&items[1], StreamEvent::Finished { reason } if reason == "tool_calls"));
        assert!(matches!(&items[2], StreamEvent::Usage(u) if u.total_tokens == 61));
        assert!(matches!(items[3], StreamEvent::Done));
    }
}

#[test]
fn collect_events_folds_a_stream() {
    let body = fixture!("stream_tool_calls.sse").as_bytes().to_vec();
    let s = stream::assemble_events(
        futures::stream::iter([Ok::<_, std::io::Error>(body)]),
        1 << 20,
    );
    let result = futures::executor::block_on(crate::collect_events(s)).unwrap();
    assert_eq!(result.tool_calls.len(), 2);
    assert_eq!(result.tokens.as_ref().unwrap().prompt_tokens, 40);
    assert!(result.wants_tool_calls());
}

#[test]
fn tool_calls_without_index_are_keyed_by_id() {
    // Mistral-style: whole calls, no `index`.
    let mut asm = stream::Assembler::default();
    asm.push(r#"{"choices":[{"delta":{"tool_calls":[{"id":"x1","function":{"name":"a","arguments":"{}"}},{"id":"x2","function":{"name":"b","arguments":"{\"k\":1}"}}]}}]}"#).unwrap();
    let out = asm
        .push(r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":4}}"#)
        .unwrap();
    let StreamEvent::ToolCalls(calls) = &out[0] else {
        panic!("{out:?}")
    };
    assert_eq!(
        calls.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
    // `total_tokens` is derived when omitted.
    assert!(matches!(&out[2], StreamEvent::Usage(u) if u.total_tokens == 7));
    // EOF without `[DONE]` after a finish is a clean end.
    assert!(matches!(asm.finish().unwrap()[..], [StreamEvent::Done]));
}

#[test]
fn tool_call_without_name_is_invalid_and_missing_id_is_generated() {
    let mut asm = stream::Assembler::default();
    asm.push(
        r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{}"}}]}}]}"#,
    )
    .unwrap();
    assert!(matches!(
        asm.push("[DONE]"),
        Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("no function name")
    ));

    let mut asm = stream::Assembler::default();
    asm.push(r#"{"choices":[{"delta":{"tool_calls":[{"index":3,"function":{"name":"f"}}]}}]}"#)
        .unwrap();
    let out = asm.push("[DONE]").unwrap();
    let StreamEvent::ToolCalls(calls) = &out[0] else {
        panic!("{out:?}")
    };
    assert_eq!(
        (calls[0].id.as_str(), calls[0].arguments.as_str()),
        ("call_3", "{}")
    );
}

#[test]
fn groq_usage_is_read_from_x_groq() {
    let out = push(r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"x_groq":{"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}}"#).unwrap();
    assert!(matches!(&out[1], StreamEvent::Usage(u) if u.total_tokens == 3));
}

#[test]
fn sse_data_handles_noise_and_garbage() {
    let out = push(r#"{"choices":[{"delta":{"content":"hi"},"finish_reason":null}]}"#).unwrap();
    assert!(matches!(&out[..], [StreamEvent::Text(t)] if t == "hi"));
    assert!(matches!(push(" [DONE] ").unwrap()[..], [StreamEvent::Done]));
    for noise in [
        "",
        "  ",
        r#"{"choices":[]}"#,
        r#"{"choices":null,"usage":null}"#,
        r#"{"choices":[{"index":1,"delta":{"content":"other choice"}}]}"#,
    ] {
        assert!(push(noise).unwrap().is_empty(), "{noise:?}");
    }
    for garbage in ["{oops", "[1,2]", "\"str\"", "{\"choices\":5}"] {
        assert!(
            matches!(push(garbage), Err(e) if e.kind() == LlmErrorKind::InvalidResponse),
            "{garbage:?}"
        );
    }
}

#[test]
fn sse_tolerates_crlf_comments_and_done_only() {
    let body = ": keep-alive\r\n\r\nevent: ping\r\ndata:\r\n\r\n\
                data: {\"choices\":[{\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\r\n\r\n\
                data: [DONE]\r\n\r\n";
    let contents: Vec<String> = assemble(body.as_bytes(), 4)
        .into_iter()
        .map(|c| c.unwrap().content)
        .collect();
    assert_eq!(contents, ["hi", ""]);
}

#[test]
fn sse_error_object_ends_the_stream_with_the_provider_message() {
    let body = "data: {\"choices\":[{\"delta\":{\"content\":\"a\"},\"finish_reason\":null}]}\n\n\
                data: {\"error\":{\"message\":\"The server had an error\",\"type\":\"server_error\"}}\n\n\
                data: [DONE]\n\n";
    let items = assemble(body.as_bytes(), 11);
    assert_eq!(items.len(), 2);
    assert!(
        matches!(&items[1], Err(m) if m.kind() == LlmErrorKind::Server && m.message() == "The server had an error")
    );
    assert!(matches!(
        push(r#"{"error":"model not loaded"}"#),
        Err(m) if m.kind() == LlmErrorKind::Provider && m.message() == "model not loaded"
    ));
}

#[test]
fn sse_truncated_stream_is_an_error() {
    let full = fixture!("stream.sse");
    let cut = &full[..full.find("\"finish_reason\":\"stop\"").unwrap()];
    let cut = &cut[..cut.rfind("data:").unwrap()];
    let items = assemble(cut.as_bytes(), 16);
    let (last, chunks) = items.split_last().unwrap();
    assert!(chunks.iter().all(Result::is_ok));
    assert!(
        matches!(last, Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("[DONE]"))
    );
}

#[test]
fn sse_oversized_event_is_an_error_not_a_panic() {
    let body = format!("data: {{\"x\":\"{}\"}}\n\n", "a".repeat(4096));
    let chunks = futures::stream::iter([Ok::<_, std::io::Error>(body.into_bytes())]);
    let items: Vec<_> =
        futures::executor::block_on(stream::assemble_events(chunks, 1024).collect());
    assert_eq!(items.len(), 1);
    assert!(items[0].is_err());
}

#[test]
fn sse_transport_error_is_request_failed() {
    let chunks = futures::stream::iter([
        Ok(
            b"data: {\"choices\":[{\"delta\":{\"content\":\"a\"},\"finish_reason\":null}]}\n\n"
                .to_vec(),
        ),
        Err(std::io::Error::other("connection reset")),
    ]);
    let items: Vec<_> = futures::executor::block_on(
        stream::text_stream(stream::assemble_events(chunks, 1 << 20)).collect(),
    );
    assert_eq!(items.len(), 2);
    assert!(
        matches!(&items[1], Err(m) if m.kind() == LlmErrorKind::Network && m.message().contains("connection reset"))
    );
}

// ── providers, structured output, security ───────────────────────────────────

#[test]
fn stream_options_follow_quirks() {
    let v = stream_body(&OpenAi::new("k"), true);
    assert_eq!(v["stream_options"], json!({ "include_usage": true }));
    assert!(
        stream_body(&OpenAi::new("k"), false)
            .get("stream_options")
            .is_none()
    );
    assert!(
        stream_body(&OpenAi::mistral("k"), true)
            .get("stream_options")
            .is_none()
    );
    assert!(
        stream_body(&OpenAi::deepseek("k"), true)
            .get("stream_options")
            .is_some()
    );
}

#[test]
fn max_tokens_field_follows_quirks() {
    let v = body(
        &OpenAi::mistral("k").max_tokens(9),
        &[Message::human("x")],
        &[],
        None,
    );
    assert_eq!(v["max_tokens"], 9);
    assert!(v.get("max_completion_tokens").is_none());
    let v = body(
        &OpenAi::groq("k").max_tokens(9),
        &[Message::human("x")],
        &[],
        None,
    );
    assert_eq!(v["max_completion_tokens"], 9);
}

#[test]
fn provider_presets() {
    for (llm, url, model) in [
        (
            OpenAi::mistral("k"),
            "https://api.mistral.ai/v1",
            "mistral-small-latest",
        ),
        (
            OpenAi::groq("k"),
            "https://api.groq.com/openai/v1",
            "llama-3.3-70b-versatile",
        ),
        (
            OpenAi::together("k"),
            "https://api.together.xyz/v1",
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        ),
        (
            OpenAi::deepseek("k"),
            "https://api.deepseek.com/v1",
            "deepseek-chat",
        ),
        (
            OpenAi::openrouter("k"),
            "https://openrouter.ai/api/v1",
            "openrouter/auto",
        ),
        (
            OpenAi::lm_studio("qwen"),
            "http://localhost:1234/v1",
            "qwen",
        ),
        (
            OpenAi::vllm("http://localhost:8000/v1/", "m"),
            "http://localhost:8000/v1",
            "m",
        ),
    ] {
        assert_eq!(llm.base_url, url);
        assert_eq!(llm.model_id(), model);
        assert!(llm.chat_url().is_ok(), "{url}");
    }
    let llm = OpenAi::openrouter("k").model("openai/gpt-5");
    assert_eq!(llm.model_info().map(|m| m.id), Some(models::GPT_5));
    assert!(
        OpenAi::openrouter("k")
            .model("gpt-5")
            .model_info()
            .is_none()
    );
    assert!(
        OpenAi::for_provider(Provider::AzureOpenAi, "k")
            .chat_url()
            .is_err()
    );
    assert!(OpenAi::from_provider_env(Provider::AzureOpenAi).is_err());
}

#[test]
fn azure_url_encodes_deployment_and_version() {
    let llm =
        OpenAi::azure("https://r.openai.azure.com/", "my dep/x", "k").api_version("2025-01-01");
    assert_eq!(
        llm.chat_url().unwrap().as_str(),
        "https://r.openai.azure.com/openai/deployments/my%20dep%2Fx/chat/completions?api-version=2025-01-01"
    );
    assert_eq!(llm.active_quirks().auth, AuthStyle::ApiKeyHeader);
}

#[test]
fn https_is_required_off_loopback() {
    let msgs = [Message::human("Hi")];
    let llm = OpenAi::new("sk-secret-key-1234").base_url("http://example.com/v1");
    let err = tokio_test::block_on(llm.generate(&msgs)).unwrap_err();
    assert!(
        matches!(&err, m if m.kind() == LlmErrorKind::Other && m.message().contains("plain HTTP")),
        "{err:?}"
    );
    assert!(!err.to_string().contains("sk-secret"));
    assert!(llm.allow_http_host("example.com").chat_url().is_ok());
}

#[test]
fn debug_never_shows_the_key() {
    let llm = OpenAi::new("sk-super-secret-value").header("X-Title", "t");
    let dbg = format!("{llm:?}");
    assert!(!dbg.contains("sk-super-secret-value"), "{dbg}");
    assert!(dbg.contains("REDACTED"));
    let err = llm.scrub(LlmError::request_failed("echo sk-super-secret-value"));
    assert_eq!(err.to_string(), "request failed: echo [REDACTED]");
}

#[test]
fn invalid_images_fail_preflight() {
    let msg = Message::human(MessageContent::Parts(vec![ContentPart::image_base64(
        "text/html",
        "PGh0bWw+",
    )]));
    assert!(matches!(
        OpenAi::new("k").preflight(&[msg]),
        Err(m) if m.kind() == LlmErrorKind::Other && m.message().starts_with("message 0:")
    ));
}

fn structured(llm: &OpenAi, format: &ResponseFormat) -> Value {
    serde_json::to_value(llm.structured_body(&[Message::human("q")], format).unwrap()).unwrap()
}

#[test]
fn structured_output_uses_native_json_schema() {
    let schema = json!({"type": "object", "properties": {"a": {"type": "string"}},
                        "required": ["a"], "additionalProperties": false});
    let format = ResponseFormat::json_schema("answer", schema.clone());
    let v = structured(&OpenAi::new("k"), &format);
    assert_eq!(
        v["response_format"],
        json!({"type": "json_schema", "json_schema": {"name": "answer", "schema": schema, "strict": true}})
    );
    assert_eq!(v["messages"].as_array().unwrap().len(), 1);

    // No JSON Schema support → json_object plus schema instructions.
    let v = structured(&OpenAi::deepseek("k"), &format);
    assert_eq!(v["response_format"], json!({"type": "json_object"}));
    assert_eq!(v["messages"][0]["role"], "system");
    assert!(
        v["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("Schema")
    );

    // JSON object mode always carries a JSON instruction.
    let v = structured(&OpenAi::new("k"), &ResponseFormat::JsonObject);
    assert_eq!(v["response_format"], json!({"type": "json_object"}));
    assert!(
        v["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("JSON")
    );

    // LM Studio has no json_object mode → prompt only.
    let v = structured(&OpenAi::lm_studio("m"), &ResponseFormat::JsonObject);
    assert!(v.get("response_format").is_none());
    assert_eq!(v["messages"].as_array().unwrap().len(), 2);

    let v = structured(&OpenAi::new("k"), &ResponseFormat::Text);
    assert!(v.get("response_format").is_none());

    let bad = ResponseFormat::json_schema("has space", json!({}));
    assert!(OpenAi::new("k").structured_body(&[], &bad).is_err());
}

#[test]
fn refusal_is_reported_as_finish_reason() {
    let body = br#"{"choices":[{"message":{"role":"assistant","content":null,"refusal":"I can't help with that."},"finish_reason":"stop"}]}"#;
    let r = decode_response(body).unwrap();
    assert_eq!(r.generation, "I can't help with that.");
    assert_eq!(r.finish_reason, Some(FinishReason::Refusal));
}

#[test]
fn finish_reason_usage_details_and_reasoning() {
    let body =
        br#"{"choices":[{"message":{"role":"assistant","content":"x","reasoning_content":"think"},
                    "finish_reason":"length"}],
                    "usage":{"prompt_tokens":2000,"completion_tokens":300,"total_tokens":2300,
                      "prompt_tokens_details":{"cached_tokens":1920,"audio_tokens":0},
                      "completion_tokens_details":{"reasoning_tokens":256}}}"#;
    let r = decode_response(body).unwrap();
    assert!(r.is_truncated());
    let usage = r.tokens.clone().unwrap();
    assert_eq!(usage.cache_read_tokens, 1920);
    assert_eq!(usage.cache_creation_tokens, 0);
    assert_eq!(usage.reasoning_tokens, 256);
    assert_eq!(usage.uncached_prompt_tokens(), 80);
    rune_chain_core::testing::check_token_usage(&usage).unwrap();
    assert_eq!(r.reasoning_text(), "think");
    // Reasoning never leaks into the text or back into a request.
    assert_eq!(r.generation, "x");
    let v = serde_json::to_value(
        OpenAi::new("k").request_body(&[r.to_message()], BodyOptions::default()),
    )
    .unwrap();
    assert!(!v.to_string().contains("think"), "{v}");

    for (wire, reason) in [
        ("stop", FinishReason::Stop),
        ("tool_calls", FinishReason::ToolCalls),
        ("function_call", FinishReason::ToolCalls),
        ("content_filter", FinishReason::ContentFilter),
        ("eos", FinishReason::Other("eos".into())),
    ] {
        let body = format!(
            r#"{{"choices":[{{"message":{{"role":"assistant","content":"x"}},"finish_reason":"{wire}"}}]}}"#
        );
        assert_eq!(
            decode_response(body.as_bytes()).unwrap().finish_reason,
            Some(reason)
        );
    }
    // Null details (some compatible servers) decode as zero.
    let body = br#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,
                    "prompt_tokens_details":null,"completion_tokens_details":null}}"#;
    assert_eq!(
        decode_response(body)
            .unwrap()
            .tokens
            .unwrap()
            .cache_read_tokens,
        0
    );
}

#[test]
fn lenient_response_decoding() {
    // Compatible servers: missing tool-call id/type, null tool_calls, no total.
    let body = br#"{"choices":[{"message":{"role":"assistant","content":"x","tool_calls":null}}],
                    "usage":{"prompt_tokens":2,"completion_tokens":3}}"#;
    let r = decode_response(body).unwrap();
    assert_eq!(r.tokens.unwrap().total_tokens, 5);
    let body = br#"{"choices":[{"message":{"role":"assistant","content":null,
                    "tool_calls":[{"function":{"name":"f","arguments":"{}"}}]}}]}"#;
    assert_eq!(decode_response(body).unwrap().tool_calls[0].id, "call_0");
}

#[test]
fn error_bodies_are_truncated() {
    let long = "x".repeat(10_000);
    let err = decode_error(500, long.as_bytes(), None);
    assert!(err.to_string().len() < 700);
    let err = decode_error(
        422,
        br#"{"object":"error","message":"Extra inputs are not permitted","type":"invalid_request_error"}"#,
        None,
    );
    assert_eq!(err.kind(), LlmErrorKind::InvalidRequest);
    assert!(err.message().starts_with("Extra inputs"));
}

#[test]
fn base_url_trims_trailing_slash() {
    let llm = OpenAi::new("k");
    assert_eq!(llm.base_url, DEFAULT_BASE_URL);
    assert_eq!(llm.base_url("http://h:1/v1/").base_url, "http://h:1/v1");
}

// ── client ────────────────────────────────────────────────────────────────────

#[test]
fn client_defaults() {
    let llm = OpenAi::new("sk-test");
    assert_eq!(llm.api_key.expose(), "sk-test");
    assert_eq!(llm.model, "gpt-5-mini");
    assert_eq!(llm.model_id(), models::DEFAULT_MODEL);
    assert!(llm.model_info().is_some_and(|m| m.reasoning));
    assert!(llm.temperature.is_none() && llm.max_tokens.is_none());
    let _: Box<dyn Llm> = Box::new(llm);
}

// ── model capability pre-flight ───────────────────────────────────────────────

#[test]
fn model_is_free_form() {
    let llm = OpenAi::new("k")
        .model("gpt-from-the-future")
        .temperature(0.5);
    assert_eq!(llm.model_id(), "gpt-from-the-future");
    assert!(llm.model_info().is_none());
    assert!(llm.preflight(&[]).is_ok());
}

#[test]
fn preflight_rejects_temperature_on_reasoning_models() {
    for id in [models::GPT_5, models::GPT_5_MINI, models::O3] {
        let err = OpenAi::new("k").model(id).temperature(0.3).preflight(&[]);
        assert!(
            matches!(&err, Err(m) if m.kind() == LlmErrorKind::Other && m.message().contains(id)),
            "{err:?}"
        );
        assert!(OpenAi::new("k").model(id).preflight(&[]).is_ok());
    }
    for id in [models::GPT_4_1, models::GPT_4O_MINI] {
        assert!(
            OpenAi::new("k")
                .model(id)
                .temperature(0.3)
                .preflight(&[])
                .is_ok()
        );
    }
}

#[test]
fn preflight_failure_short_circuits_every_entry_point() {
    let llm = OpenAi::new("k").temperature(1.0);
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
fn debug_hides_custom_header_and_query_values() {
    let llm = OpenAi::new("sk-test-key-123456")
        .header("X-Gateway-Token", "gw-secret-header-value")
        .query_param("token", "gw-secret-query-value");
    let shown = format!("{llm:?}");
    assert!(!shown.contains("sk-test-key-123456"), "{shown}");
    assert!(!shown.contains("gw-secret-header-value"), "{shown}");
    assert!(!shown.contains("gw-secret-query-value"), "{shown}");
    // The names are still useful when debugging a configuration.
    assert!(shown.contains("X-Gateway-Token"), "{shown}");
    assert!(shown.contains("token"), "{shown}");
}
