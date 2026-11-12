//! Property tests for message / role handling and the core value types.

use proptest::prelude::*;
use rune_chain_core::{
    ContentPart, GenerateResult, ImageData, Message, MessageContent, Role, StreamData, TokenUsage,
    ToolCall, ToolChoice,
};
use serde_json::Value;

fn role() -> impl Strategy<Value = Role> {
    prop_oneof![
        Just(Role::System),
        Just(Role::Human),
        Just(Role::Ai),
        Just(Role::Tool),
    ]
}

fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::collection::vec(any::<char>(), 0..24).prop_map(String::from_iter),
        "[a-z ]{0,16}",
    ]
}

fn part() -> impl Strategy<Value = ContentPart> {
    prop_oneof![
        text().prop_map(ContentPart::text),
        text().prop_map(ContentPart::image_url),
        (text(), text()).prop_map(|(m, d)| ContentPart::image_base64(m, d)),
    ]
}

fn content() -> impl Strategy<Value = MessageContent> {
    prop_oneof![
        text().prop_map(MessageContent::Text),
        prop::collection::vec(part(), 0..5).prop_map(MessageContent::Parts),
    ]
}

fn tool_call() -> impl Strategy<Value = ToolCall> {
    (text(), text(), text()).prop_map(|(id, name, args)| ToolCall::new(id, name, args))
}

fn message() -> impl Strategy<Value = Message> {
    (
        role(),
        content(),
        prop::collection::vec(tool_call(), 0..3),
        prop::option::of(text()),
    )
        .prop_map(|(role, content, tool_calls, tool_call_id)| {
            let msg = Message::new(role, content).with_tool_calls(tool_calls);
            match tool_call_id {
                Some(id) => msg.with_tool_call_id(id),
                None => msg,
            }
        })
}

fn usage() -> impl Strategy<Value = TokenUsage> {
    (
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(|(p, c, t, r, w, z)| {
            TokenUsage::new(p, c)
                .with_total_tokens(t)
                .with_cache_read_tokens(r)
                .with_cache_creation_tokens(w)
                .with_reasoning_tokens(z)
        })
}

proptest! {
    #[test]
    fn role_display_matches_serde_name(role in role()) {
        let json = serde_json::to_value(&role).unwrap();
        let name = role.to_string();
        prop_assert_eq!(json.as_str(), Some(name.as_str()));
        prop_assert_eq!(serde_json::from_value::<Role>(json).unwrap(), role);
    }

    #[test]
    fn role_parse_accepts_only_canonical_names(name in text()) {
        let parsed = serde_json::from_value::<Role>(Value::String(name.clone()));
        let canonical = ["system", "human", "ai", "tool"].contains(&name.as_str());
        prop_assert_eq!(parsed.is_ok(), canonical);
        if let Ok(role) = parsed {
            prop_assert_eq!(role.to_string(), name);
        }
    }

    #[test]
    fn message_json_round_trips(msg in message()) {
        let json = serde_json::to_string(&msg).unwrap();
        prop_assert_eq!(&serde_json::from_str::<Message>(&json).unwrap(), &msg);

        let v: Value = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(v.get("tool_calls").is_some(), !msg.tool_calls.is_empty());
        prop_assert_eq!(v.get("tool_call_id").is_some(), msg.tool_call_id.is_some());
        prop_assert_eq!(v["content"].is_string(), msg.content.is_text());
    }

    #[test]
    fn constructors_set_role_and_metadata(c in text(), id in text(), calls in prop::collection::vec(tool_call(), 0..3)) {
        for (msg, role) in [
            (Message::system(c.as_str()), Role::System),
            (Message::human(c.as_str()), Role::Human),
            (Message::ai(c.as_str()), Role::Ai),
        ] {
            prop_assert_eq!(&msg, &Message::new(role, c.clone()));
            prop_assert!(msg.tool_calls.is_empty() && msg.tool_call_id.is_none());
            prop_assert_eq!(&msg.content, &c);
        }
        let ai = Message::ai_with_tool_calls(c.as_str(), calls.clone());
        prop_assert_eq!(ai.role, Role::Ai);
        prop_assert_eq!(ai.tool_calls, calls);

        let result = Message::tool_result(id.clone(), c.as_str());
        prop_assert_eq!(result.role, Role::Tool);
        prop_assert_eq!(result.tool_call_id, Some(id));
        prop_assert!(result.tool_calls.is_empty());
    }

    #[test]
    fn text_content_joins_text_parts_only(content in content()) {
        match &content {
            MessageContent::Text(s) => {
                prop_assert_eq!(content.as_text(), s.as_str());
                prop_assert_eq!(&content.text_content(), s);
            }
            MessageContent::Parts(parts) => {
                let texts: Vec<&str> = parts
                    .iter()
                    .filter_map(|p| match p {
                        ContentPart::Text { text } => Some(text.as_str()),
                        ContentPart::Image { .. } => None,
                    })
                    .collect();
                prop_assert_eq!(content.as_text(), "");
                prop_assert_eq!(content.text_content(), texts.join(" "));
            }
        }
        prop_assert_eq!(content.to_string(), content.text_content());
    }

    #[test]
    fn image_parts_are_type_tagged(p in part()) {
        let v = serde_json::to_value(&p).unwrap();
        match &p {
            ContentPart::Text { .. } => prop_assert_eq!(&v["type"], "text"),
            ContentPart::Image { image } => {
                prop_assert_eq!(&v["type"], "image");
                let tag = match image {
                    ImageData::Url { .. } => "url",
                    ImageData::Base64 { .. } => "base64",
                };
                prop_assert_eq!(&v["image"]["type"], tag);
            }
        }
        prop_assert_eq!(serde_json::from_value::<ContentPart>(v).unwrap(), p);
    }

    #[test]
    fn deserializers_never_panic(input in text()) {
        let _ = serde_json::from_str::<Message>(&input);
        let _ = serde_json::from_str::<MessageContent>(&input);
        let _ = serde_json::from_str::<ToolChoice>(&input);
        let _ = serde_json::from_str::<GenerateResult>(&input);
        let _ = serde_json::from_str::<StreamData>(&input);
    }

    #[test]
    fn tool_call_args_never_panic(args in text(), key in text()) {
        let call = ToolCall::new("id", "name", args);
        let _ = call.arg(&key);
        let _ = call.input();
    }

    #[test]
    fn tool_call_input_reads_string_argument(s in text()) {
        let args = serde_json::json!({ "input": s }).to_string();
        prop_assert_eq!(ToolCall::new("id", "t", args).input(), Some(s));
    }

    #[test]
    fn token_usage_combine_saturates_and_commutes(a in usage(), b in usage()) {
        let ab = a.combine(&b);
        let ba = b.combine(&a);
        prop_assert_eq!(ab.prompt_tokens, a.prompt_tokens.saturating_add(b.prompt_tokens));
        prop_assert_eq!(ab.completion_tokens, a.completion_tokens.saturating_add(b.completion_tokens));
        prop_assert_eq!(ab.total_tokens, a.total_tokens.saturating_add(b.total_tokens));
        prop_assert_eq!(
            (ab.prompt_tokens, ab.completion_tokens, ab.total_tokens),
            (ba.prompt_tokens, ba.completion_tokens, ba.total_tokens)
        );
        let zero = a.combine(&TokenUsage::default());
        prop_assert_eq!(
            (zero.prompt_tokens, zero.completion_tokens, zero.total_tokens),
            (a.prompt_tokens, a.completion_tokens, a.total_tokens)
        );
    }
}
