use std::sync::Mutex;

use async_trait::async_trait;
use futures::StreamExt;
use serde_json::{Value, json};

use crate::{
    Chain, ChainError, ContentPart, FunctionDefinition, GenerateResult, ImageData, Llm, LlmError,
    LlmErrorKind, Memory, Message, MessageContent, PromptArgs, Role, StreamData, TokenUsage, Tool,
    ToolCall, ToolChoice, ToolError, prompt_args,
};

// ── Message / Role ────────────────────────────────────────────────────────────

#[test]
fn role_serializes_lowercase_and_matches_display() {
    for (role, name) in [
        (Role::System, "system"),
        (Role::Human, "human"),
        (Role::Ai, "ai"),
        (Role::Tool, "tool"),
    ] {
        assert_eq!(serde_json::to_value(&role).unwrap(), json!(name));
        assert_eq!(role.to_string(), name);
        let back: Role = serde_json::from_value(json!(name)).unwrap();
        assert_eq!(back, role);
    }
}

#[test]
fn role_rejects_unknown_name() {
    assert!(serde_json::from_value::<Role>(json!("assistant")).is_err());
}

#[test]
fn text_message_serializes_without_tool_fields() {
    let msg = Message::human("hi");
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(v, json!({ "role": "human", "content": "hi" }));
}

#[test]
fn message_deserializes_with_missing_optional_fields() {
    let msg: Message = serde_json::from_value(json!({ "role": "ai", "content": "ok" })).unwrap();
    assert_eq!(msg, Message::ai("ok"));
    assert_eq!(msg.tool_calls, Vec::new());
    assert!(msg.tool_call_id.is_none());
}

#[test]
fn multimodal_message_round_trips() {
    let msg = Message::human(MessageContent::Parts(vec![
        ContentPart::text("what is this?"),
        ContentPart::image_url("https://example.com/cat.png"),
        ContentPart::image_base64("image/png", "iVBORw0KGgo="),
    ]));
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(
        v["content"],
        json!([
            { "type": "text", "text": "what is this?" },
            { "type": "image", "image": { "type": "url", "url": "https://example.com/cat.png" } },
            { "type": "image", "image": {
                "type": "base64", "mime_type": "image/png", "data": "iVBORw0KGgo="
            } },
        ])
    );
    let back: Message = serde_json::from_value(v).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn tool_messages_carry_call_metadata() {
    let call = ToolCall::new("call_1", "upper", r#"{"input":"x"}"#);
    let ai = Message::ai_with_tool_calls("", vec![call.clone()]);
    assert_eq!(ai.role, Role::Ai);
    assert_eq!(ai.tool_calls, vec![call]);

    let result = Message::tool_result("call_1", "X");
    assert_eq!(result.role, Role::Tool);
    assert_eq!(result.tool_call_id.as_deref(), Some("call_1"));
    let v = serde_json::to_value(&result).unwrap();
    assert_eq!(v["tool_call_id"], "call_1");
    assert!(v.get("tool_calls").is_none());
}

#[test]
fn message_content_text_accessors() {
    let text: MessageContent = "plain".into();
    assert!(text.is_text());
    assert_eq!(text.as_text(), "plain");
    assert_eq!(text, "plain");
    assert_eq!(text, String::from("plain"));

    let parts = MessageContent::Parts(vec![
        ContentPart::text("a"),
        ContentPart::image_url("u"),
        ContentPart::text("b"),
    ]);
    assert!(!parts.is_text());
    assert_eq!(parts.as_text(), "");
    assert_eq!(parts.text_content(), "a b");
    assert_eq!(parts.to_string(), "a b");
}

#[test]
fn image_data_tags() {
    let url: ImageData = serde_json::from_value(json!({ "type": "url", "url": "u" })).unwrap();
    assert_eq!(url, ImageData::Url { url: "u".into() });
    assert!(serde_json::from_value::<ImageData>(json!({ "type": "file", "path": "p" })).is_err());
}

// ── ToolCall / FunctionDefinition / ToolChoice ────────────────────────────────

#[test]
fn tool_call_arg_parses_json_arguments() {
    let call = ToolCall::new("id", "add", r#"{"a": 2, "b": "three"}"#);
    assert_eq!(call.arg("a"), Some(json!(2)));
    assert_eq!(call.arg("b"), Some(json!("three")));
    assert_eq!(call.arg("c"), None);
}

#[test]
fn tool_call_arg_tolerates_invalid_json() {
    let call = ToolCall::new("id", "add", "not json");
    assert_eq!(call.arg("a"), None);
    assert_eq!(call.input(), None);
}

#[test]
fn tool_call_input_stringifies_non_string_values() {
    assert_eq!(
        ToolCall::new("i", "t", r#"{"input":"hello"}"#).input(),
        Some("hello".into())
    );
    assert_eq!(
        ToolCall::new("i", "t", r#"{"input":42}"#).input(),
        Some("42".into())
    );
    assert_eq!(
        ToolCall::new("i", "t", r#"{"input":{"k":1}}"#).input(),
        Some(r#"{"k":1}"#.into())
    );
}

#[test]
fn single_input_definition_schema() {
    let def = FunctionDefinition::single_input("upper", "Upper-case text.");
    assert_eq!(def.name, "upper");
    assert_eq!(def.description, "Upper-case text.");
    assert_eq!(def.parameters["type"], "object");
    assert_eq!(def.parameters["required"], json!(["input"]));
    assert_eq!(def.parameters["properties"]["input"]["type"], "string");
}

#[test]
fn tool_choice_serialization() {
    assert_eq!(
        serde_json::to_value(ToolChoice::Auto).unwrap(),
        json!("auto")
    );
    assert_eq!(
        serde_json::to_value(ToolChoice::None).unwrap(),
        json!("none")
    );
    assert_eq!(
        serde_json::to_value(ToolChoice::Required).unwrap(),
        json!("required")
    );
    assert_eq!(
        serde_json::to_value(ToolChoice::Tool("x".into())).unwrap(),
        json!({ "tool": "x" })
    );
}

// ── GenerateResult / TokenUsage / StreamData ──────────────────────────────────

#[test]
fn token_usage_combine_sums_fields() {
    let a = TokenUsage::new(1, 2)
        .with_cache_read_tokens(1)
        .with_reasoning_tokens(2);
    let sum = a.combine(&TokenUsage::default()).combine(&a);
    assert_eq!(sum.cache_read_tokens, 2);
    assert_eq!(sum.cache_creation_tokens, 0);
    assert_eq!(sum.reasoning_tokens, 4);
    assert_eq!(sum.prompt_tokens, 2);
    assert_eq!(sum.completion_tokens, 4);
    assert_eq!(sum.total_tokens, 6);
}

#[test]
fn generate_result_serialization_omits_empty_tool_calls() {
    let r = GenerateResult::from_text("4");
    assert!(!r.wants_tool_calls());
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v, json!({ "generation": "4", "tokens": null }));

    let back: GenerateResult = serde_json::from_value(json!({
        "generation": "",
        "tokens": { "prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3 },
        "tool_calls": [{ "id": "c", "name": "n", "arguments": "{}" }],
    }))
    .unwrap();
    assert!(back.wants_tool_calls());
    assert_eq!(back.tokens.unwrap().total_tokens, 3);
}

#[test]
fn stream_data_constructors() {
    let c = StreamData::chunk("tok");
    assert_eq!(c.content, "tok");
    assert!(!c.is_finished);
    assert!(StreamData::done().is_finished);
}

// ── prompt_args! ──────────────────────────────────────────────────────────────

#[test]
fn prompt_args_macro_converts_values() {
    let args: PromptArgs = prompt_args! {
        "s" => "text",
        "n" => 3,
        "b" => true,
        "list" => ["a", "b"],
    };
    assert_eq!(args.len(), 4);
    assert_eq!(args["s"], json!("text"));
    assert_eq!(args["n"], json!(3));
    assert_eq!(args["b"], json!(true));
    assert_eq!(args["list"], json!(["a", "b"]));
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[test]
fn error_display_and_conversions() {
    let llm = LlmError::provider("rate limited");
    assert_eq!(llm.to_string(), "provider error: rate limited");
    let chain: ChainError = llm.into();
    assert!(matches!(chain, ChainError::LlmError(_)));
    assert_eq!(chain.to_string(), "LLM error: provider error: rate limited");

    let tool: ChainError = ToolError::InvalidInput("bad".into()).into();
    assert_eq!(tool.to_string(), "tool error: invalid input: bad");
    assert_eq!(
        ChainError::MissingVariable("name".into()).to_string(),
        "missing prompt variable: name"
    );
    assert_eq!(ChainError::Other("x".into()).to_string(), "x");
}

// ── Trait defaults ────────────────────────────────────────────────────────────

struct Upper;

#[async_trait]
impl Chain for Upper {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let text = input
            .get("input")
            .and_then(Value::as_str)
            .ok_or_else(|| ChainError::MissingVariable("input".into()))?;
        Ok(GenerateResult::from_text(text.to_uppercase()))
    }
}

struct Named;

#[async_trait]
impl Chain for Named {
    async fn call(&self, _input: PromptArgs) -> Result<GenerateResult, ChainError> {
        Ok(GenerateResult::from_text("named"))
    }
    fn output_keys(&self) -> Vec<String> {
        vec!["answer".into()]
    }
}

#[tokio::test]
async fn chain_invoke_returns_generation() {
    assert_eq!(
        Upper
            .invoke(prompt_args! { "input" => "abc" })
            .await
            .unwrap(),
        "ABC"
    );
}

#[tokio::test]
async fn chain_errors_propagate() {
    let err = Upper.invoke(PromptArgs::new()).await.unwrap_err();
    assert!(matches!(err, ChainError::MissingVariable(ref v) if v == "input"));
}

#[tokio::test]
async fn chain_execute_uses_default_and_custom_output_keys() {
    let map = Upper
        .execute(prompt_args! { "input" => "x" })
        .await
        .unwrap();
    assert_eq!(map["output"], "X");
    assert_eq!(map["generate_result"]["generation"], "X");
    assert_eq!(Upper.input_keys(), Vec::<String>::new());

    let map = Named.execute(PromptArgs::new()).await.unwrap();
    assert_eq!(map["answer"], "named");
    assert!(map.contains_key("generate_result"));
}

#[tokio::test]
async fn chain_stream_is_unsupported_by_default() {
    let boxed: Box<dyn Chain> = Upper.into();
    assert!(matches!(
        boxed.stream(PromptArgs::new()).await,
        Err(ChainError::Other(_))
    ));
}

struct FixedLlm;

#[async_trait]
impl Llm for FixedLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text(format!(
            "{} turns",
            messages.len()
        )))
    }
}

#[tokio::test]
async fn llm_defaults_report_unsupported() {
    let llm = FixedLlm;
    let msgs = [Message::system("s"), Message::human("h")];
    assert_eq!(llm.generate(&msgs).await.unwrap().generation, "2 turns");
    assert!(matches!(
        llm.generate_with_tools(&msgs, &[], None).await,
        Err(e) if e.kind() == LlmErrorKind::Unsupported
    ));
    assert!(matches!(llm.stream(&msgs).await, Err(e) if e.kind() == LlmErrorKind::Unsupported));
}

struct Reverse;

#[async_trait]
impl Tool for Reverse {
    fn name(&self) -> &'static str {
        "reverse"
    }
    fn description(&self) -> &'static str {
        "Reverses a string."
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        if input.is_empty() {
            return Err(ToolError::InvalidInput("empty".into()));
        }
        Ok(input.chars().rev().collect())
    }
}

#[tokio::test]
async fn tool_default_schema_and_definition() {
    let def = Reverse.function_definition();
    assert_eq!(def.name, "reverse");
    assert_eq!(def.description, "Reverses a string.");
    assert_eq!(def.parameters, Reverse.schema());
    assert_eq!(def.parameters["required"], json!(["input"]));
    assert_eq!(Reverse.run("abc").await.unwrap(), "cba");
    assert!(matches!(
        Reverse.run("").await,
        Err(ToolError::InvalidInput(_))
    ));
}

#[derive(Default)]
struct VecMemory(Mutex<Vec<Message>>);

#[async_trait]
impl Memory for VecMemory {
    async fn messages(&self) -> Result<Vec<Message>, ChainError> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn add(&self, message: Message) -> Result<(), ChainError> {
        self.0.lock().unwrap().push(message);
        Ok(())
    }
    async fn clear(&self) -> Result<(), ChainError> {
        self.0.lock().unwrap().clear();
        Ok(())
    }
}

#[tokio::test]
async fn memory_trait_object_is_usable() {
    let memory: Box<dyn Memory> = Box::<VecMemory>::default();
    memory.add(Message::human("q")).await.unwrap();
    memory.add(Message::ai("a")).await.unwrap();
    assert_eq!(
        memory.messages().await.unwrap(),
        vec![Message::human("q"), Message::ai("a")]
    );
    memory.clear().await.unwrap();
    assert_eq!(memory.messages().await.unwrap(), Vec::new());
}

#[tokio::test]
async fn stream_items_collect() {
    let s = futures::stream::iter(vec![StreamData::chunk("a"), StreamData::done()]);
    let all: Vec<StreamData> = s.collect().await;
    assert_eq!(all.len(), 2);
    assert!(all[1].is_finished);
}

// ── 0.1.3 additions ───────────────────────────────────────────────────────────

mod additions {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use serde_json::json;

    use crate::{
        Chain, ChainError, ChainExt, FinishReason, FunctionDefinition, GenerateResult, ImageData,
        ImageError, Llm, LlmError, LlmErrorKind, LlmExt, MAX_TOOL_ARGUMENTS_BYTES, Message,
        PromptArgs, ReasoningBlock, ResponseFormat, TokenUsage, Tool, ToolCall, ToolError,
    };

    fn weather_def() -> FunctionDefinition {
        FunctionDefinition::new(
            "weather",
            "Weather for a city.",
            json!({
                "type": "object",
                "properties": {
                    "city": { "type": "string" },
                    "days": { "type": ["integer", "null"] },
                    "unit": { "type": "string", "enum": ["c", "f"] }
                },
                "required": ["city"],
                "additionalProperties": false
            }),
        )
    }

    fn invalid(call: &ToolCall) -> String {
        match call.validate(&weather_def()) {
            Err(ToolError::InvalidInput(msg)) => msg,
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_conforming_arguments() {
        let call = ToolCall::new("1", "weather", r#"{"city":"Oslo","days":3,"unit":"c"}"#);
        let args = call.validate(&weather_def()).unwrap();
        assert_eq!(args["days"], 3);
        let nullable = ToolCall::new("1", "weather", r#"{"city":"Oslo","days":null}"#);
        assert!(nullable.validate(&weather_def()).is_ok());
    }

    #[test]
    fn validate_rejects_each_kind_of_mistake() {
        assert!(invalid(&ToolCall::new("1", "other", "{}")).contains("`other`"));
        assert!(invalid(&ToolCall::new("1", "weather", "{}")).contains("`city`"));
        assert!(invalid(&ToolCall::new("1", "weather", r#"{"city":1}"#)).contains("string"));
        assert!(
            invalid(&ToolCall::new("1", "weather", r#"{"city":"x","days":1.5}"#)).contains("days")
        );
        assert!(
            invalid(&ToolCall::new("1", "weather", r#"{"city":"x","unit":"k"}"#))
                .contains("one of")
        );
        assert!(
            invalid(&ToolCall::new("1", "weather", r#"{"city":"x","evil":1}"#)).contains("evil")
        );
        assert!(invalid(&ToolCall::new("1", "weather", "[]")).contains("object"));
    }

    #[test]
    fn argument_errors_do_not_echo_input() {
        let secret = "sk-SECRET-TOKEN";
        let call = ToolCall::new("1", "weather", format!("{{\"city\": \"{secret}\" oops"));
        let msg = call
            .parse_arguments::<serde_json::Value>()
            .unwrap_err()
            .to_string();
        assert!(!msg.contains(secret), "{msg}");
    }

    #[test]
    fn oversized_arguments_are_rejected() {
        let big = format!("{{\"input\":\"{}\"}}", "a".repeat(MAX_TOOL_ARGUMENTS_BYTES));
        let call = ToolCall::new("1", "echo", big);
        assert!(call.parse_arguments::<serde_json::Value>().is_err());
        // The legacy accessor is unchanged.
        assert!(call.input().is_some());
    }

    #[test]
    fn empty_arguments_parse_as_empty_object() {
        let call = ToolCall::new("1", "now", "  ");
        assert!(call.arguments_object().unwrap().is_empty());
    }

    #[test]
    fn tool_name_validity() {
        let name = |n: &str| FunctionDefinition::single_input(n, "d").has_valid_name();
        assert!(name("a-b_C9"));
        assert!(!name(""));
        assert!(!name("a.b"));
        assert!(!name(&"a".repeat(65)));
        assert!(name(&"a".repeat(64)));
    }

    #[test]
    fn image_debug_redacts_payload() {
        let img = ImageData::base64("image/png", "QUJD".repeat(1000));
        let dbg = format!("{:?}", Message::human_with_image("hi", img));
        assert!(!dbg.contains("QUJD"), "{dbg}");
        assert!(dbg.contains("4000 base64 chars"));
        let long_url = ImageData::url(format!("https://x.io/{}", "q".repeat(300)));
        assert!(!format!("{long_url:?}").contains("qqqq"));
    }

    #[test]
    fn image_validation() {
        assert_eq!(
            ImageData::base64("image/png", "QUJD").decoded_len(),
            Some(3)
        );
        assert_eq!(
            ImageData::base64("image/png", "QQ==").decoded_len(),
            Some(1)
        );
        assert!(ImageData::base64("image/png", "QQ==").validate(1).is_ok());
        assert_eq!(
            ImageData::base64("image/png", "QUJD").validate(2),
            Err(ImageError::TooLarge { size: 3, limit: 2 })
        );
        for bad in ["QUJ", "QU=D", "QUJ*", "Q==="] {
            assert_eq!(
                ImageData::base64("image/png", bad).validate(100),
                Err(ImageError::InvalidBase64),
                "{bad}"
            );
        }
        for mime in ["", "image/", "png", "image/png\r\nX: y", "IMAGE/JPEG"] {
            let ok = ImageData::base64(mime, "QUJD").validate(100).is_ok();
            assert_eq!(ok, mime == "IMAGE/JPEG", "{mime:?}");
        }
        for (url, ok) in [
            ("https://example.com/a.png", true),
            ("HTTP://example.com/a.png", true),
            ("data:image/png;base64,QUJD", true),
            ("data:text/html;base64,QUJD", false),
            ("data:image/png;base64", false),
            ("https://", false),
            ("https:///etc", false),
            ("javascript:alert(1)", false),
            ("ftp://example.com/a.png", false),
            ("https://example.com/a b.png", false),
        ] {
            assert_eq!(ImageData::url(url).validate(100).is_ok(), ok, "{url}");
        }
        let huge = format!("data:image/png;base64,{}", "A".repeat(1000));
        assert!(matches!(
            ImageData::url(huge).validate(100),
            Err(ImageError::TooLarge { .. })
        ));
    }

    #[test]
    fn generate_result_builders_and_message() {
        let usage = TokenUsage::new(u32::MAX, 5);
        assert_eq!(usage.total_tokens, u32::MAX);
        let r = GenerateResult::from_text("t")
            .with_tokens(TokenUsage::new(1, 2))
            .with_tool_calls(vec![ToolCall::new("c", "n", "{}")]);
        let msg = r.to_message();
        assert_eq!(msg.text(), "t");
        assert!(msg.has_tool_calls());
        let r = GenerateResult::from_text("4")
            .with_finish_reason(FinishReason::Stop)
            .with_reasoning(vec![ReasoningBlock::new("2+2").with_signature("sig")]);
        assert!(!r.is_truncated());
        assert_eq!(r.reasoning_text(), "2+2");
        let msg = r.to_message();
        assert_eq!(msg.text(), "4");
        assert_eq!(msg.reasoning[0].signature.as_deref(), Some("sig"));
    }

    struct Fails(&'static str, Arc<AtomicUsize>);
    #[async_trait]
    impl Chain for Fails {
        async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Err(ChainError::Other(self.0.into()))
        }
        fn input_keys(&self) -> Vec<String> {
            vec!["q".into()]
        }
    }

    #[tokio::test]
    async fn chain_fallbacks_return_last_error_or_first_success() {
        let n = Arc::new(AtomicUsize::new(0));
        let all_fail = Fails("a", n.clone()).with_fallbacks([
            Box::new(Fails("b", n.clone())) as Box<dyn Chain>,
            Box::new(Fails("c", n.clone())),
        ]);
        assert_eq!(all_fail.input_keys(), ["q"]);
        let err = all_fail.call(PromptArgs::new()).await.unwrap_err();
        assert_eq!(err.to_string(), "c");
        assert_eq!(n.load(Ordering::SeqCst), 3);
    }

    struct Echo;
    #[async_trait]
    impl Chain for Echo {
        async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
            Ok(GenerateResult::from_text(input["x"].as_str().unwrap_or(""))
                .with_tokens(TokenUsage::new(1, 1)))
        }
    }

    #[tokio::test]
    async fn map_output_keeps_usage_and_arc_chain_works() {
        let chain: Arc<dyn Chain> = Arc::new(Echo.map_output(|s| s.repeat(2)));
        let r = chain
            .call(crate::prompt_args! { "x" => "ab" })
            .await
            .unwrap();
        assert_eq!(r.generation, "abab");
        assert!(r.tokens.is_some());
        // Arc<dyn Chain> is itself a Chain and composes further.
        let wrapped = Arc::clone(&chain).map_output(|s| s.to_uppercase());
        assert_eq!(
            wrapped
                .invoke(crate::prompt_args! { "x" => "a" })
                .await
                .unwrap(),
            "AA"
        );
    }

    struct Model(Result<&'static str, &'static str>);
    #[async_trait]
    impl Llm for Model {
        async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
            match self.0 {
                Ok(text) => Ok(GenerateResult::from_text(format!(
                    "{text}:{}",
                    messages.len()
                ))),
                Err(e) => Err(LlmError::provider(e)),
            }
        }
    }

    #[tokio::test]
    async fn llm_fallbacks_and_structured_default() {
        let llm = Model(Err("down")).with_fallbacks([
            Arc::new(Model(Err("also down"))) as Arc<dyn Llm>,
            Arc::new(Model(Ok("up"))),
        ]);
        let msgs = [Message::human("hi")];
        assert_eq!(llm.generate(&msgs).await.unwrap().generation, "up:1");
        // Structured output adds one system message for JSON formats only.
        let out = llm
            .generate_structured(&msgs, &ResponseFormat::JsonObject)
            .await
            .unwrap();
        assert_eq!(out.generation, "up:2");
        let out = llm
            .generate_structured(&msgs, &ResponseFormat::Text)
            .await
            .unwrap();
        assert_eq!(out.generation, "up:1");
        // Every fallback failing yields the last error.
        let none = Model(Err("x")).with_fallbacks([Arc::new(Model(Err("y"))) as Arc<dyn Llm>]);
        assert!(
            none.generate(&msgs)
                .await
                .unwrap_err()
                .to_string()
                .contains('y')
        );
        // Tool calling falls through unsupported providers too.
        assert!(matches!(
            none.generate_with_tools(&msgs, &[], None).await,
            Err(e) if e.kind() == LlmErrorKind::Unsupported
        ));
    }

    struct Upper;
    #[async_trait]
    impl Tool for Upper {
        fn name(&self) -> &'static str {
            "upper"
        }
        fn description(&self) -> &'static str {
            "Upper-cases."
        }
        async fn run(&self, input: &str) -> Result<String, ToolError> {
            Ok(input.to_uppercase())
        }
    }

    fn takes_tool(_: &impl Tool) {}

    #[tokio::test]
    async fn arc_tool_forwards_metadata() {
        let tool: Arc<dyn Tool> = Arc::new(Upper);
        let tools: Vec<Arc<dyn Tool>> = vec![tool.clone()];
        assert_eq!(tools[0].function_definition().name, "upper");
        assert_eq!(Tool::run(&tool, "a").await.unwrap(), "A");
        takes_tool(&tool);
    }
}

// ── 0.2 additions: serde compatibility ───────────────────────────────────────

#[test]
fn old_json_still_deserialises() {
    let usage: TokenUsage = serde_json::from_value(
        json!({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}),
    )
    .unwrap();
    assert_eq!(usage, TokenUsage::new(1, 2));
    let r: GenerateResult =
        serde_json::from_value(json!({"generation": "x", "tokens": null})).unwrap();
    assert_eq!(r, GenerateResult::from_text("x"));
    let m: Message = serde_json::from_value(json!({"role": "ai", "content": "hi"})).unwrap();
    assert_eq!(m, Message::ai("hi"));
    // Zero breakdowns and empty reasoning are not serialised.
    assert_eq!(
        serde_json::to_value(TokenUsage::new(1, 2)).unwrap(),
        json!({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3})
    );
}

#[test]
fn finish_reason_and_reasoning_round_trip() {
    use crate::{FinishReason, ReasoningBlock};
    for reason in [
        FinishReason::Stop,
        FinishReason::Length,
        FinishReason::ToolCalls,
        FinishReason::ContentFilter,
        FinishReason::Refusal,
        FinishReason::Other("pause_turn".into()),
    ] {
        let v = serde_json::to_value(&reason).unwrap();
        assert_eq!(v, json!(reason.as_str()));
        assert_eq!(serde_json::from_value::<FinishReason>(v).unwrap(), reason);
    }
    let r = GenerateResult::from_text("4")
        .with_finish_reason(FinishReason::ToolCalls)
        .with_reasoning(vec![
            ReasoningBlock::new("think").with_signature("sig"),
            ReasoningBlock::redacted("opaque"),
        ])
        .with_tokens(
            TokenUsage::new(10, 5)
                .with_cache_read_tokens(4)
                .with_reasoning_tokens(2),
        );
    let back: GenerateResult = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
    assert_eq!(back.reasoning_text(), "think");
    let msg = back.to_message();
    let back: Message = serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
    assert_eq!(back, msg);
    assert_eq!(back.text(), "4");
    assert!(back.reasoning[1].is_redacted());
}
