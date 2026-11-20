//! Every OpenAI-compatible preset against a loopback mock: the request goes
//! to the preset's path with its auth header, and its documented quirks show
//! up in the body. No test touches the network.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::time::Duration;

use rune_chain_core::testing::http::{MockResponse, MockServer};
use rune_chain_core::{FunctionDefinition, Llm, Message, ResponseFormat, ToolChoice};
use rune_chain_openai::{OpenAi, Provider, collect_events};
use serde_json::{Value, json};

const CHAT_TEXT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/chat_text.json"
));
const STREAM: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/stream.sse"));

/// What each preset must put on the wire.
struct Case {
    provider: Provider,
    url: &'static str,
    key_env: &'static str,
    max_tokens_field: &'static str,
    tool_choice: bool,
    stream_usage: bool,
    /// `response_format.type` sent for a JSON Schema request, if any.
    structured: Option<&'static str>,
}

const CASES: &[Case] = &[
    Case {
        provider: Provider::Xai,
        url: "https://api.x.ai/v1",
        key_env: "XAI_API_KEY",
        max_tokens_field: "max_completion_tokens",
        tool_choice: true,
        stream_usage: true,
        structured: Some("json_schema"),
    },
    Case {
        provider: Provider::Fireworks,
        url: "https://api.fireworks.ai/inference/v1",
        key_env: "FIREWORKS_API_KEY",
        max_tokens_field: "max_tokens",
        tool_choice: true,
        stream_usage: true,
        structured: Some("json_schema"),
    },
    Case {
        provider: Provider::Cerebras,
        url: "https://api.cerebras.ai/v1",
        key_env: "CEREBRAS_API_KEY",
        max_tokens_field: "max_completion_tokens",
        tool_choice: true,
        stream_usage: false,
        structured: Some("json_schema"),
    },
    Case {
        provider: Provider::Moonshot,
        url: "https://api.moonshot.ai/v1",
        key_env: "MOONSHOT_API_KEY",
        max_tokens_field: "max_completion_tokens",
        tool_choice: true,
        stream_usage: true,
        structured: Some("json_schema"),
    },
    Case {
        provider: Provider::Hyperbolic,
        url: "https://api.hyperbolic.ai/inference/v1",
        key_env: "HYPERBOLIC_API_KEY",
        max_tokens_field: "max_tokens",
        tool_choice: true,
        stream_usage: true,
        structured: Some("json_schema"),
    },
    Case {
        provider: Provider::HuggingFace,
        url: "https://router.huggingface.co/v1",
        key_env: "HF_TOKEN",
        max_tokens_field: "max_tokens",
        tool_choice: true,
        stream_usage: false,
        structured: Some("json_object"),
    },
    Case {
        provider: Provider::NvidiaNim,
        url: "https://integrate.api.nvidia.com/v1",
        key_env: "NVIDIA_API_KEY",
        max_tokens_field: "max_tokens",
        tool_choice: false,
        stream_usage: false,
        structured: None,
    },
    Case {
        provider: Provider::SambaNova,
        url: "https://api.sambanova.ai/v1",
        key_env: "SAMBANOVA_API_KEY",
        max_tokens_field: "max_tokens",
        tool_choice: true,
        stream_usage: true,
        structured: Some("json_schema"),
    },
    Case {
        provider: Provider::Cohere,
        url: "https://api.cohere.ai/compatibility/v1",
        key_env: "COHERE_API_KEY",
        max_tokens_field: "max_tokens",
        tool_choice: false,
        stream_usage: false,
        structured: Some("json_object"),
    },
    Case {
        provider: Provider::Groq,
        url: "https://api.groq.com/openai/v1",
        key_env: "GROQ_API_KEY",
        max_tokens_field: "max_completion_tokens",
        tool_choice: true,
        stream_usage: false,
        structured: Some("json_schema"),
    },
    Case {
        provider: Provider::DeepSeek,
        url: "https://api.deepseek.com/v1",
        key_env: "DEEPSEEK_API_KEY",
        max_tokens_field: "max_tokens",
        tool_choice: true,
        stream_usage: true,
        structured: Some("json_object"),
    },
];

/// Split `https://host/a/b` into `/a/b`.
fn path_of(url: &str) -> &str {
    let rest = url.split_once("://").unwrap().1;
    rest.find('/').map_or("", |i| &rest[i..])
}

/// The preset pointed at the mock, keeping the preset's path.
fn preset(case: &Case, server: &MockServer) -> OpenAi {
    OpenAi::for_provider(case.provider, "test-key")
        .model("some-model")
        .base_url(format!("{}{}", server.base_url(), path_of(case.url)))
        .http_client(reqwest::Client::builder().no_proxy().build().unwrap())
        .retry_delay(Duration::ZERO)
        .max_tokens(32)
}

fn tools() -> [FunctionDefinition; 1] {
    [FunctionDefinition::single_input(
        "lookup",
        "Look a thing up.",
    )]
}

#[test]
fn presets_have_documented_urls_and_key_vars() {
    for case in CASES {
        let p = case.provider;
        assert_eq!(p.default_base_url(), Some(case.url), "{p}");
        assert_eq!(p.api_key_env(), Some(case.key_env), "{p}");
        let llm = OpenAi::for_provider(p, "k");
        assert_eq!(
            llm.chat_url().unwrap().as_str(),
            format!("{}/chat/completions", case.url),
            "{p}"
        );
    }
}

#[test]
fn presets_send_path_auth_and_quirks() {
    for case in CASES {
        let p = case.provider;
        let structured_reply = json!({
            "choices": [{ "message": { "role": "assistant", "content": "{\"a\":\"b\"}" } }]
        })
        .to_string();
        let server = MockServer::start([
            MockResponse::json(200, CHAT_TEXT),
            MockResponse::event_stream(STREAM),
            MockResponse::json(200, structured_reply),
        ])
        .unwrap();
        let llm = preset(case, &server);
        let format = ResponseFormat::json_schema(
            "thing",
            json!({
                "type": "object",
                "properties": { "a": { "type": "string" } },
                "required": ["a"],
                "additionalProperties": false
            }),
        );
        tokio_test::block_on(async {
            llm.generate_with_tools(
                &[Message::human("Hi")],
                &tools(),
                Some(ToolChoice::Required),
            )
            .await
            .unwrap();
            let events = llm
                .stream_events(&[Message::human("Hi")], &[], None)
                .await
                .unwrap();
            collect_events(events).await.unwrap();
            llm.generate_structured(&[Message::human("Hi")], &format)
                .await
                .unwrap();
        });

        let requests = server.finish().unwrap();
        assert_eq!(requests.len(), 3, "{p}");
        let want_path = format!("{}/chat/completions", path_of(case.url));
        for req in &requests {
            assert_eq!(req.path, want_path, "{p}");
            assert_eq!(req.header("authorization"), Some("Bearer test-key"), "{p}");
            assert_eq!(req.header("api-key"), None, "{p}");
        }

        let tools_body = requests[0].json().unwrap();
        assert_eq!(tools_body[case.max_tokens_field], 32, "{p}");
        let other = if case.max_tokens_field == "max_tokens" {
            "max_completion_tokens"
        } else {
            "max_tokens"
        };
        assert!(tools_body.get(other).is_none(), "{p}");
        assert_eq!(tools_body["tools"][0]["function"]["name"], "lookup", "{p}");
        if case.tool_choice {
            assert_eq!(tools_body["tool_choice"], "required", "{p}");
        } else {
            assert!(tools_body.get("tool_choice").is_none(), "{p}");
        }

        let stream_body = requests[1].json().unwrap();
        assert_eq!(stream_body["stream"], true, "{p}");
        if case.stream_usage {
            assert_eq!(
                stream_body["stream_options"],
                json!({ "include_usage": true }),
                "{p}"
            );
        } else {
            assert!(stream_body.get("stream_options").is_none(), "{p}");
        }

        let structured_body = requests[2].json().unwrap();
        let sent = structured_body
            .get("response_format")
            .and_then(|f| f.get("type"))
            .and_then(Value::as_str);
        assert_eq!(sent, case.structured, "{p}");
    }
}

#[test]
fn tool_choice_quirk_can_be_turned_back_on() {
    let server = MockServer::start([MockResponse::json(200, CHAT_TEXT)]).unwrap();
    let case = CASES
        .iter()
        .find(|c| c.provider == Provider::Cohere)
        .unwrap();
    let llm = preset(case, &server).quirks(Provider::Cohere.quirks().with_tool_choice(true));
    tokio_test::block_on(llm.generate_with_tools(
        &[Message::human("Hi")],
        &tools(),
        Some(ToolChoice::None),
    ))
    .unwrap();
    let body = server.finish().unwrap()[0].json().unwrap();
    assert_eq!(body["tool_choice"], "none");
}
