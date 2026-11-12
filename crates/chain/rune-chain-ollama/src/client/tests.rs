//! Wire-format tests against recorded Ollama `/api/chat` fixtures.
//! None of them touch the network.

use futures::StreamExt;
use rune_chain_core::LlmErrorKind;
use rune_chain_core::{Llm, StreamData, ToolCall};
use serde_json::{Value, json};

use super::*;
use crate::StreamEvent;
use crate::http::decode_error;
use crate::stream::{assemble_events, collect_events, text_stream};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/", $name))
    };
}

fn body(llm: &Ollama, messages: &[Message], stream: bool) -> Value {
    let opts = BodyOptions {
        stream,
        ..BodyOptions::default()
    };
    serde_json::to_value(llm.request_body(messages, opts).unwrap()).unwrap()
}

fn tools_body(
    messages: &[Message],
    tools: &[FunctionDefinition],
    choice: Option<&ToolChoice>,
) -> Result<Value, LlmError> {
    let opts = BodyOptions {
        tools,
        tool_choice: choice,
        ..BodyOptions::default()
    };
    Ollama::new()
        .request_body(messages, opts)
        .map(|b| serde_json::to_value(b).unwrap())
}

fn weather_tool() -> FunctionDefinition {
    FunctionDefinition::new(
        "get_weather",
        "Weather for a city.",
        json!({
            "type": "object",
            "properties": { "city": { "type": "string" } },
            "required": ["city"]
        }),
    )
}

// ── request building ──────────────────────────────────────────────────────────

#[test]
fn default_request_has_no_options() {
    let v = body(&Ollama::new(), &[Message::human("Hi")], false);
    assert_eq!(
        v,
        json!({
            "model": "llama3.2",
            "messages": [{ "role": "user", "content": "Hi" }],
            "stream": false,
        })
    );
}

#[test]
fn builder_settings_become_options() {
    let llm = Ollama::new()
        .model("mistral")
        .temperature(0.0)
        .max_tokens(50);
    let v = body(&llm, &[Message::human("Hi")], true);
    assert_eq!(v["model"], "mistral");
    assert_eq!(v["stream"], true);
    assert_eq!(
        v["options"],
        json!({ "temperature": 0.0, "num_predict": 50 })
    );

    let only_temp = body(&Ollama::new().temperature(0.5), &[], false);
    assert_eq!(only_temp["options"], json!({ "temperature": 0.5 }));
}

#[test]
fn all_options_keep_alive_and_think() {
    let llm = Ollama::new()
        .temperature(0.1)
        .top_p(0.9)
        .top_k(40)
        .seed(-7)
        .stop("</s>")
        .stop("\n\n")
        .num_ctx(16_384)
        .max_tokens(256)
        .option("repeat_penalty", 1.1)
        .option("top_k", 1) // the typed setter wins
        .keep_alive(KeepAlive::For(Duration::from_secs(600)))
        .think(Think::High);
    let v = body(&llm, &[Message::human("Hi")], false);
    assert_eq!(
        v["options"],
        json!({
            "temperature": 0.1,
            "top_p": 0.9,
            "top_k": 40,
            "seed": -7,
            "stop": ["</s>", "\n\n"],
            "num_ctx": 16384,
            "num_predict": 256,
            "repeat_penalty": 1.1,
        })
    );
    // Shortest decimal form on the wire, not f32 widening noise.
    let text =
        serde_json::to_string(&llm.request_body(&[], BodyOptions::default()).unwrap()).unwrap();
    assert!(text.contains("\"temperature\":0.1,"), "{text}");
    assert_eq!(v["keep_alive"], 600);
    assert_eq!(v["think"], "high");
    assert_eq!(
        body(&Ollama::new().think(Think::On), &[], false)["think"],
        true
    );
}

#[test]
fn non_finite_option_is_rejected_before_sending() {
    let err = Ollama::new()
        .temperature(f32::NAN)
        .request_body(&[], BodyOptions::default())
        .unwrap_err();
    assert!(
        matches!(err, m if m.kind() == LlmErrorKind::Other && m.message().contains("temperature"))
    );
}

#[test]
fn base_url_is_normalized_and_checked() {
    let url = |llm: &Ollama| llm.endpoint("/api/chat").map(|u| u.to_string());
    assert_eq!(
        url(&Ollama::new()).unwrap(),
        "http://localhost:11434/api/chat"
    );
    assert_eq!(
        url(&Ollama::default().base_url("https://proxy.example.com/ollama/")).unwrap(),
        "https://proxy.example.com/ollama/api/chat"
    );
    // Plain HTTP to a remote host needs an explicit opt-in.
    let remote = Ollama::new().base_url("http://gpu-box:11434/");
    assert!(
        matches!(url(&remote), Err(m) if m.kind() == LlmErrorKind::Other && m.message().contains("allow_http_host"))
    );
    assert_eq!(
        url(&remote.clone().allow_http_host("gpu-box")).unwrap(),
        "http://gpu-box:11434/api/chat"
    );
    assert!(url(&remote.allow_insecure_http()).is_ok());
}

#[test]
fn remote_plain_http_fails_without_network() {
    let llm = Ollama::new().base_url("http://10.255.255.1:11434");
    let err = tokio_test::block_on(llm.generate(&[Message::human("hi")])).unwrap_err();
    assert!(
        matches!(err, m if m.kind() == LlmErrorKind::Other && m.message().contains("plain HTTP"))
    );
}

#[test]
fn debug_redacts_the_bearer_token() {
    let llm = Ollama::new().bearer_token("super-secret-token");
    let dbg = format!("{llm:?}");
    assert!(!dbg.contains("super-secret-token"), "{dbg}");
    assert!(dbg.contains("[REDACTED]"));
    let err = llm.scrub(LlmError::provider("echo super-secret-token"));
    assert!(
        matches!(err, m if m.kind() == LlmErrorKind::Provider && m.message() == "echo [REDACTED]")
    );
}

#[test]
fn roles_map_to_ollama_names() {
    let v = body(
        &Ollama::new(),
        &[
            Message::system("s"),
            Message::human("h"),
            Message::ai("a"),
            Message::tool_result("c", "t"),
        ],
        false,
    );
    let roles: Vec<&str> = v["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles, ["system", "user", "assistant", "tool"]);
}

#[test]
fn multimodal_parts_split_into_text_and_images() {
    let msg = Message::human(MessageContent::Parts(vec![
        ContentPart::text("What is"),
        ContentPart::image_base64("image/png", "iVBORw0KGgo="),
        ContentPart::text("in this picture?"),
    ]));
    let v = body(&Ollama::new(), &[msg], false);
    assert_eq!(
        v["messages"][0],
        json!({
            "role": "user",
            "content": "What is in this picture?",
            "images": ["iVBORw0KGgo="],
        })
    );
}

#[test]
fn base64_and_data_url_images_match_wire_fixture() {
    let msg = Message::human(MessageContent::Parts(vec![
        ContentPart::text("Compare these two pictures."),
        ContentPart::image_base64("image/png", "iVBORw0KGgo="),
        ContentPart::image_url("data:image/gif;base64,R0lGODlhAQABAAAAACw="),
    ]));
    let expected: Value = serde_json::from_str(fixture!("request_images.json")).unwrap();
    assert_eq!(body(&Ollama::new().model("llava"), &[msg], false), expected);
}

#[test]
fn remote_image_url_is_rejected_before_sending() {
    for url in [
        "https://example.com/cat.png",
        "data:image/png,not-base64",
        "data:image/png;base64",
    ] {
        let msg = Message::human(MessageContent::Parts(vec![
            ContentPart::text("What is this?"),
            ContentPart::image_url(url),
        ]));
        let err = Ollama::new()
            .request_body(&[msg], BodyOptions::default())
            .err();
        assert!(
            matches!(&err, Some(m) if m.kind() == LlmErrorKind::Other && m.message().contains("base64") && m.message().contains(url)),
            "{url}: {err:?}"
        );
    }
}

#[test]
fn malformed_images_are_rejected() {
    for image in [
        ContentPart::image_base64("image/png", "not base64!"),
        ContentPart::image_base64("text/html", "PGgxPg=="),
        ContentPart::image_url("data:text/html;base64,PGgxPg=="),
    ] {
        let msg = Message::human(MessageContent::Parts(vec![image]));
        let err = Ollama::new()
            .request_body(&[msg], BodyOptions::default())
            .unwrap_err();
        assert!(
            matches!(&err, m if m.kind() == LlmErrorKind::Other && m.message().starts_with("message 0:")),
            "{err:?}"
        );
    }
}

#[test]
fn generate_with_remote_image_url_fails_without_network() {
    // Nothing listens on this port; the error must come from request building.
    let llm = Ollama::new().base_url("http://127.0.0.1:9");
    let msg = Message::human(MessageContent::Parts(vec![ContentPart::image_url(
        "https://example.com/cat.png",
    )]));
    let err = tokio_test::block_on(llm.generate(&[msg])).unwrap_err();
    assert!(
        matches!(&err, e if e.kind() == LlmErrorKind::Other),
        "{err:?}"
    );
}

// ── tools ─────────────────────────────────────────────────────────────────────

#[test]
fn tools_are_sent_as_functions() {
    let v = tools_body(&[Message::human("Weather?")], &[weather_tool()], None).unwrap();
    assert_eq!(
        v["tools"],
        json!([{
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Weather for a city.",
                "parameters": {
                    "type": "object",
                    "properties": { "city": { "type": "string" } },
                    "required": ["city"]
                }
            }
        }])
    );
    assert_eq!(v["messages"].as_array().unwrap().len(), 1);
}

#[test]
fn tool_choice_is_emulated() {
    let msgs = [Message::system("Be brief."), Message::human("Weather?")];
    let tools = [
        weather_tool(),
        FunctionDefinition::single_input("echo", "Echo."),
    ];

    let none = tools_body(&msgs, &tools, Some(&ToolChoice::None)).unwrap();
    assert!(none.get("tools").is_none());

    let req = tools_body(&msgs, &tools, Some(&ToolChoice::Required)).unwrap();
    assert_eq!(req["tools"].as_array().unwrap().len(), 2);
    assert_eq!(req["messages"][1]["role"], "system");
    assert!(
        req["messages"][1]["content"]
            .as_str()
            .unwrap()
            .contains("must call")
    );

    let one = tools_body(&msgs, &tools, Some(&ToolChoice::Tool("echo".into()))).unwrap();
    assert_eq!(one["tools"].as_array().unwrap().len(), 1);
    assert_eq!(one["tools"][0]["function"]["name"], "echo");
    assert!(
        one["messages"][1]["content"]
            .as_str()
            .unwrap()
            .contains("`echo`")
    );

    assert!(tools_body(&msgs, &tools, Some(&ToolChoice::Tool("nope".into()))).is_err());
}

#[test]
fn tool_round_trip_messages() {
    let msgs = [
        Message::human("Weather in Oslo?"),
        Message::ai_with_tool_calls(
            "",
            vec![ToolCall::new("call_0", "get_weather", r#"{"city":"Oslo"}"#)],
        ),
        Message::tool_result("call_0", "12°C"),
        Message::tool_result("unknown", "?"),
    ];
    let v = tools_body(&msgs, &[weather_tool()], None).unwrap();
    assert_eq!(
        v["messages"][1],
        json!({
            "role": "assistant",
            "content": "",
            "tool_calls": [{ "function": { "name": "get_weather", "arguments": { "city": "Oslo" } } }]
        })
    );
    assert_eq!(
        v["messages"][2],
        json!({ "role": "tool", "content": "12°C", "tool_name": "get_weather" })
    );
    assert!(v["messages"][3].get("tool_name").is_none());

    // Empty arguments become an empty object; garbage is refused.
    let empty = [Message::ai_with_tool_calls(
        "",
        vec![ToolCall::new("c", "t", "")],
    )];
    let v = tools_body(&empty, &[], None).unwrap();
    assert_eq!(
        v["messages"][0]["tool_calls"][0]["function"]["arguments"],
        json!({})
    );
    let bad = [Message::ai_with_tool_calls(
        "",
        vec![ToolCall::new("c", "t", "{oops")],
    )];
    assert!(matches!(
        tools_body(&bad, &[], None),
        Err(e) if e.kind() == LlmErrorKind::Other
    ));
}

// ── structured output ─────────────────────────────────────────────────────────

#[test]
fn structured_output_uses_format() {
    let llm = Ollama::new();
    let msgs = [Message::human("Capital of France?")];
    let schema = json!({ "type": "object", "properties": { "city": { "type": "string" } } });

    let v = serde_json::to_value(
        llm.structured_body(&msgs, &ResponseFormat::json_schema("c", schema.clone()))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(v["format"], schema);
    assert_eq!(v["messages"][0]["role"], "system");
    assert!(
        v["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("Schema")
    );

    let v = serde_json::to_value(
        llm.structured_body(&msgs, &ResponseFormat::JsonObject)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(v["format"], "json");

    let v =
        serde_json::to_value(llm.structured_body(&msgs, &ResponseFormat::Text).unwrap()).unwrap();
    assert!(v.get("format").is_none());
    assert_eq!(v["messages"].as_array().unwrap().len(), 1);

    let bad = ResponseFormat::json_schema("c", json!(true));
    assert!(llm.structured_body(&msgs, &bad).is_err());
}

// ── response decoding ─────────────────────────────────────────────────────────

#[test]
fn decodes_chat_response_with_eval_counts() {
    let reply = decode_response(fixture!("chat.json").as_bytes()).unwrap();
    let result = reply.result;
    assert_eq!(result.generation, "Hello! How are you today?");
    assert!(!result.wants_tool_calls());
    assert_eq!(reply.done_reason.as_deref(), Some("stop"));
    assert_eq!(result.finish_reason, Some(FinishReason::Stop));
    let tokens = result.tokens.unwrap();
    assert_eq!(
        (
            tokens.prompt_tokens,
            tokens.completion_tokens,
            tokens.total_tokens
        ),
        (26, 298, 324)
    );
}

#[test]
fn decodes_tool_calls_and_thinking() {
    let result = decode_response(fixture!("chat_tool_calls.json").as_bytes())
        .unwrap()
        .result;
    assert_eq!(result.tool_calls.len(), 2);
    let call = &result.tool_calls[0];
    assert_eq!(
        (call.id.as_str(), call.name.as_str()),
        ("call_0", "get_weather")
    );
    let args: Value = call.parse_arguments().unwrap();
    assert_eq!(args, json!({ "city": "Oslo", "unit": "celsius" }));
    assert_eq!(result.tool_calls[1].id, "call_1");
    assert_eq!(result.tool_calls[1].arguments, "{}");

    let reply = decode_response(
        br#"{"message":{"role":"assistant","content":"4","thinking":"2+2"},"done":true}"#,
    )
    .unwrap();
    assert_eq!(reply.thinking.as_deref(), Some("2+2"));
    assert_eq!(reply.result.generation, "4");
    assert_eq!(reply.result.reasoning_text(), "2+2");
    assert_eq!(reply.result.finish_reason, None);

    // Thinking goes back as `thinking` on the assistant turn, never as text.
    let history = [Message::human("2+2?"), reply.result.to_message()];
    let v = serde_json::to_value(map_messages(&history).unwrap()).unwrap();
    assert_eq!(
        v[1],
        json!({ "role": "assistant", "content": "4", "thinking": "2+2" })
    );
}

#[test]
fn done_reason_maps_to_finish_reason() {
    let reply = |done: &str, calls: &str| {
        let body = format!(
            r#"{{"message":{{"role":"assistant","content":"x","tool_calls":{calls}}},"done":true,"done_reason":"{done}"}}"#
        );
        decode_response(body.as_bytes())
            .unwrap()
            .result
            .finish_reason
    };
    let call = r#"[{"function":{"name":"f","arguments":{}}}]"#;
    assert_eq!(reply("stop", "[]"), Some(FinishReason::Stop));
    assert_eq!(reply("stop", call), Some(FinishReason::ToolCalls));
    assert_eq!(reply("length", "[]"), Some(FinishReason::Length));
    assert_eq!(
        reply("load", "[]"),
        Some(FinishReason::Other("load".into()))
    );
}

#[test]
fn nameless_tool_call_is_invalid() {
    let body = br#"{"message":{"content":"","tool_calls":[{"function":{"name":" ","arguments":{}}}]},"done":true}"#;
    assert!(matches!(
        decode_response(body),
        Err(e) if e.kind() == LlmErrorKind::InvalidResponse
    ));
}

#[test]
fn missing_eval_counts_leave_tokens_unset() {
    let result = decode_response(br#"{"message":{"role":"assistant","content":"ok"},"done":true}"#)
        .unwrap()
        .result;
    assert_eq!(result.generation, "ok");
    assert!(result.tokens.is_none());
}

#[test]
fn huge_eval_counts_saturate_instead_of_overflowing() {
    let body = format!(
        r#"{{"message":{{"role":"assistant","content":"ok"}},"done":true,"prompt_eval_count":{},"eval_count":{}}}"#,
        u32::MAX,
        u32::MAX
    );
    let tokens = decode_response(body.as_bytes())
        .unwrap()
        .result
        .tokens
        .unwrap();
    assert_eq!(tokens.total_tokens, u32::MAX);
}

#[test]
fn malformed_response_is_invalid_response() {
    for body in ["", r#"{"done":true}"#, r#"{"message":{"content":7}}"#] {
        assert!(
            matches!(
                decode_response(body.as_bytes()),
                Err(e) if e.kind() == LlmErrorKind::InvalidResponse
            ),
            "{body:?}"
        );
    }
}

#[test]
fn error_field_is_extracted() {
    let err = decode_error(404, fixture!("error_model_not_found.json").as_bytes());
    assert!(
        matches!(&err, m if m.kind() == LlmErrorKind::InvalidRequest && m.message() == "model \"llama9\" not found, try pulling it first"),
        "{err:?}"
    );
}

// ── streaming ─────────────────────────────────────────────────────────────────

const BIG: Limits = Limits {
    max_line: 1 << 20,
    max_total: 1 << 24,
};

fn events(body: &[u8], size: usize, limits: Limits) -> Vec<Result<StreamEvent, LlmError>> {
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        body.chunks(size.max(1)).map(|c| Ok(c.to_vec())).collect();
    futures::executor::block_on(assemble_events(futures::stream::iter(chunks), limits).collect())
}

/// Run `body` through the event assembler and the `Llm::stream` adapter.
fn assemble(body: &[u8], size: usize) -> Vec<Result<StreamData, LlmError>> {
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        body.chunks(size).map(|c| Ok(c.to_vec())).collect();
    futures::executor::block_on(
        text_stream(assemble_events(futures::stream::iter(chunks), BIG)).collect(),
    )
}

#[test]
fn ndjson_transcript_yields_text_then_done_at_any_chunking() {
    let body = fixture!("stream.ndjson").as_bytes();
    for size in [1, 2, 3, 7, 64, body.len()] {
        let chunks: Vec<StreamData> = assemble(body, size)
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap();
        let contents: Vec<&str> = chunks.iter().map(|c| c.content.as_str()).collect();
        assert_eq!(contents, ["The", " sky", ""], "chunk size {size}");
        assert!(!chunks[1].is_finished);
        assert!(chunks[2].is_finished);
    }
}

#[test]
fn stream_events_report_finish_and_usage() {
    let items: Vec<StreamEvent> = events(fixture!("stream.ndjson").as_bytes(), 9, BIG)
        .into_iter()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(matches!(&items[0], StreamEvent::Text(t) if t == "The"));
    assert!(matches!(&items[2], StreamEvent::Finished { reason } if reason == "stop"));
    assert!(matches!(&items[3], StreamEvent::Usage(u) if u.total_tokens == 308));
    assert!(matches!(items[4], StreamEvent::Done));
}

#[test]
fn streamed_tool_calls_and_thinking_at_any_chunking() {
    let body = fixture!("stream_tool_calls.ndjson").as_bytes();
    for size in [1, 4, 33, body.len()] {
        let items: Vec<StreamEvent> = events(body, size, BIG)
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(matches!(&items[0], StreamEvent::Thinking(t) if t == "The user wants weather."));
        assert!(matches!(&items[1], StreamEvent::Text(t) if t == "Checking."));
        let StreamEvent::ToolCalls(first) = &items[2] else {
            panic!("{items:?}")
        };
        assert_eq!(first[0].id, "call_0");
        assert_eq!(first[0].arguments, r#"{"city":"Oslo"}"#);
        let StreamEvent::ToolCalls(second) = &items[3] else {
            panic!("{items:?}")
        };
        assert_eq!(
            (second[0].id.as_str(), second[0].name.as_str()),
            ("call_xyz", "get_time")
        );
    }
    let result = futures::executor::block_on(collect_events(Box::pin(futures::stream::iter(
        events(body, 16, BIG),
    ))))
    .unwrap();
    assert_eq!(result.generation, "Checking.");
    assert_eq!(result.tool_calls.len(), 2);
    assert_eq!(result.tokens.unwrap().total_tokens, 70);
}

#[test]
fn multibyte_text_survives_any_chunking() {
    let body = "{\"message\":{\"role\":\"assistant\",\"content\":\"héllo — 世界 🦀\"},\"done\":false}\n\
                {\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true}";
    for size in 1..=8 {
        let items = assemble(body.as_bytes(), size);
        assert_eq!(items.len(), 2, "chunk size {size}");
        assert_eq!(items[0].as_ref().unwrap().content, "héllo — 世界 🦀");
        // The final line has no trailing newline and still ends the stream.
        assert!(items[1].as_ref().unwrap().is_finished);
    }
}

#[test]
fn stream_handles_crlf_blank_lines_and_garbage() {
    let body = "\r\n{\"message\":{\"role\":\"assistant\",\"content\":\"hi\"},\"done\":false}\r\n  \n{\"oops\"\n";
    let items = assemble(body.as_bytes(), 5);
    assert_eq!(items[0].as_ref().unwrap().content, "hi");
    assert!(matches!(&items[1], Err(e) if e.kind() == LlmErrorKind::InvalidResponse));
    assert_eq!(items.len(), 2);
}

#[test]
fn error_line_ends_the_stream_with_the_server_message() {
    let body = "{\"message\":{\"role\":\"assistant\",\"content\":\"a\"},\"done\":false}\n\
                {\"error\":\"out of memory\"}\n\
                {\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true}\n";
    let items = assemble(body.as_bytes(), 10);
    assert_eq!(items.len(), 2);
    assert!(
        matches!(&items[1], Err(m) if m.kind() == LlmErrorKind::Provider && m.message() == "out of memory")
    );
}

#[test]
fn truncated_stream_is_an_error() {
    let full = fixture!("stream.ndjson");
    let cut = &full[..full.rfind("{\"model\"").unwrap()];
    let items = assemble(cut.as_bytes(), 16);
    let (last, chunks) = items.split_last().unwrap();
    assert!(chunks.iter().all(Result::is_ok));
    assert!(
        matches!(last, Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("done"))
    );
}

#[test]
fn oversized_line_and_body_are_errors() {
    let line = format!(
        "{{\"message\":{{\"content\":\"{}\"}},\"done\":false}}\n",
        "x".repeat(500)
    );
    let small_line = Limits {
        max_line: 100,
        max_total: 1 << 20,
    };
    let items = events(line.as_bytes(), 7, small_line);
    assert_eq!(items.len(), 1);
    assert!(
        matches!(&items[0], Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("line"))
    );

    let many = line.repeat(10);
    let small_total = Limits {
        max_line: 1 << 20,
        max_total: 2000,
    };
    let items = events(many.as_bytes(), 64, small_total);
    assert!(items[..items.len() - 1].iter().all(Result::is_ok));
    assert!(
        matches!(items.last(), Some(Err(m)) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("stream"))
    );
}

#[test]
fn too_many_streamed_tool_calls_is_an_error() {
    let call = r#"{"function":{"name":"t","arguments":{}}}"#;
    let calls = vec![call; 100].join(",");
    let line =
        format!("{{\"message\":{{\"content\":\"\",\"tool_calls\":[{calls}]}},\"done\":false}}\n");
    let items = events(line.repeat(2).as_bytes(), 4096, BIG);
    assert!(items[0].is_ok());
    assert!(
        matches!(&items[1], Err(m) if m.kind() == LlmErrorKind::InvalidResponse && m.message().contains("tool calls"))
    );
}

#[test]
fn garbage_never_panics() {
    let mut x: u32 = 0x9e37_79b9;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    let alphabet = br#"{}[]":,\ndonemessagecontenttool_callsfunctionname0123 truefalsenull"#;
    for _ in 0..300 {
        let len = (next() % 200) as usize;
        let body: Vec<u8> = (0..len)
            .map(|_| alphabet[(next() as usize) % alphabet.len()])
            .collect();
        let limits = Limits {
            max_line: (next() % 128) as usize,
            max_total: (next() % 256) as usize,
        };
        let items = events(&body, (next() % 13) as usize + 1, limits);
        // At most one error, and it is the last item.
        let errs = items.iter().filter(|i| i.is_err()).count();
        assert!(errs <= 1);
        if errs == 1 {
            assert!(items.last().unwrap().is_err());
        }
    }
}

#[test]
fn transport_error_is_request_failed() {
    let chunks = futures::stream::iter([
        Ok(b"{\"message\":{\"role\":\"assistant\",\"content\":\"a\"},\"done\":false}\n".to_vec()),
        Err(std::io::Error::other("connection reset")),
    ]);
    let items: Vec<_> =
        futures::executor::block_on(text_stream(assemble_events(chunks, BIG)).collect());
    assert_eq!(items.len(), 2);
    assert!(
        matches!(&items[1], Err(m) if m.kind() == LlmErrorKind::Network && m.message().contains("connection reset"))
    );
}

#[test]
fn client_is_an_llm_and_an_embedder() {
    let _: Box<dyn Llm> = Box::new(Ollama::new());
    let _: Box<dyn rune_chain_embed::Embedder> = Box::new(Ollama::new());
}
