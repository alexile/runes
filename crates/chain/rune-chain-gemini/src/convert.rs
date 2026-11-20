//! Translation of rune-chain messages, tools and schemas into Gemini's
//! request shapes.

use rune_chain_core::{
    ContentPart, FunctionDefinition, ImageData, LlmError, Message, MessageContent, ReasoningBlock,
    Role, ToolChoice,
};
use rune_tool_schema::{Dialect, ExportOptions, ToolDescriptor};
use serde_json::{Map, Value};

use crate::response::SYNTHETIC_CALL_ID_PREFIX;
use crate::types::{
    Blob, Content, FileData, FunctionCall, FunctionCallingConfig, FunctionResponse, Part,
    ToolConfig,
};

/// Longest tool description accepted.
const MAX_TOOL_DESCRIPTION_CHARS: usize = 32 * 1024;

/// System messages as `systemInstruction`, the rest as `contents` with
/// Gemini's role names (`user` / `model`) and consecutive same-role turns
/// merged.
///
/// # Errors
///
/// A tool message whose `tool_call_id` matches no earlier tool call (the
/// function name is needed for the `functionResponse`).
pub fn build_contents(messages: &[Message]) -> Result<(Option<Content>, Vec<Content>), LlmError> {
    let mut system: Vec<Part> = Vec::new();
    let mut contents: Vec<Content> = Vec::new();
    for (i, msg) in messages.iter().enumerate() {
        let (role, parts) = match msg.role {
            Role::System => {
                let text = msg.content.text_content();
                if !text.is_empty() {
                    system.push(Part::text(text));
                }
                continue;
            }
            Role::Human => ("user", content_parts(&msg.content)),
            Role::Ai => ("model", model_parts(msg)),
            Role::Tool => ("user", vec![function_response(msg, &messages[..i])?]),
        };
        if parts.is_empty() {
            continue;
        }
        match contents.last_mut() {
            Some(last) if last.role.as_deref() == Some(role) => last.parts.extend(parts),
            _ => contents.push(Content {
                role: Some(role.to_string()),
                parts,
            }),
        }
    }
    let system = (!system.is_empty()).then_some(Content {
        role: None,
        parts: system,
    });
    Ok((system, contents))
}

fn content_parts(content: &MessageContent) -> Vec<Part> {
    match content {
        MessageContent::Text(text) if text.is_empty() => Vec::new(),
        MessageContent::Text(text) => vec![Part::text(text.clone())],
        MessageContent::Parts(parts) => parts
            .iter()
            .filter_map(|p| match p {
                ContentPart::Text { text } if text.is_empty() => None,
                ContentPart::Text { text } => Some(Part::text(text.clone())),
                ContentPart::Image { image } => Some(image_part(image)),
            })
            .collect(),
    }
}

/// An image as `inlineData` (base64 and `data:` URLs) or `fileData`
/// (anything else, with the MIME type guessed from the extension).
fn image_part(image: &ImageData) -> Part {
    match image {
        ImageData::Base64 { mime_type, data } => Part {
            inline_data: Some(Blob {
                mime_type: mime_type.clone(),
                data: data.clone(),
            }),
            ..Part::default()
        },
        ImageData::Url { url } => {
            if let Some(blob) = data_url(url) {
                return Part {
                    inline_data: Some(blob),
                    ..Part::default()
                };
            }
            Part {
                file_data: Some(FileData {
                    mime_type: mime_from_extension(url).map(str::to_string),
                    file_uri: url.clone(),
                }),
                ..Part::default()
            }
        }
    }
}

/// `data:<mime>;base64,<payload>` as a blob.
fn data_url(url: &str) -> Option<Blob> {
    let rest = url
        .get(..5)
        .filter(|p| p.eq_ignore_ascii_case("data:"))
        .map(|_| &url[5..])?;
    let (header, payload) = rest.split_once(',')?;
    let mut fields = header.split(';');
    let mime = fields.next()?;
    if !fields.any(|f| f.eq_ignore_ascii_case("base64")) {
        return None;
    }
    Some(Blob {
        mime_type: mime.to_string(),
        data: payload.to_string(),
    })
}

fn mime_from_extension(url: &str) -> Option<&'static str> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let ext = path.rsplit_once('.')?.1;
    let known = [
        ("png", "image/png"),
        ("jpg", "image/jpeg"),
        ("jpeg", "image/jpeg"),
        ("webp", "image/webp"),
        ("gif", "image/gif"),
        ("heic", "image/heic"),
        ("heif", "image/heif"),
    ];
    known
        .iter()
        .find(|(e, _)| e.eq_ignore_ascii_case(ext))
        .map(|(_, m)| *m)
}

/// Tool-call arguments as the JSON object the API expects. Empty arguments
/// mean "no arguments"; anything that is not an object is sent as `{}`.
fn call_args(arguments: &str) -> Value {
    match serde_json::from_str::<Value>(arguments) {
        Ok(obj @ Value::Object(_)) => obj,
        _ => Value::Object(Map::new()),
    }
}

/// The API id of a call, or `None` for an id this crate made up.
fn api_call_id(id: &str) -> Option<String> {
    (!id.is_empty() && !id.starts_with(SYNTHETIC_CALL_ID_PREFIX)).then(|| id.to_string())
}

/// An assistant turn: signed thoughts, text, then function calls. A
/// signature that came on a text or function-call part (a reasoning block
/// with empty text) goes back on the first function call, or on the last
/// text part when there is none. Unsigned reasoning (summaries, or another
/// provider's) is not sent back.
fn model_parts(msg: &Message) -> Vec<Part> {
    let mut parts: Vec<Part> = Vec::new();
    let mut loose_signature: Option<&str> = None;
    for block in &msg.reasoning {
        match block {
            ReasoningBlock {
                redacted: None,
                signature: Some(sig),
                text,
                ..
            } if !text.is_empty() => parts.push(Part {
                text: Some(text.clone()),
                thought: true,
                thought_signature: Some(sig.clone()),
                ..Part::default()
            }),
            ReasoningBlock {
                redacted: None,
                signature: Some(sig),
                ..
            } if loose_signature.is_none() => loose_signature = Some(sig),
            _ => {}
        }
    }
    let mut text_parts = content_parts(&msg.content);
    let mut calls: Vec<Part> = msg
        .tool_calls
        .iter()
        .map(|tc| Part {
            function_call: Some(FunctionCall {
                id: api_call_id(&tc.id),
                name: tc.name.clone(),
                args: call_args(&tc.arguments),
            }),
            ..Part::default()
        })
        .collect();
    if let Some(sig) = loose_signature {
        let target = calls
            .first_mut()
            .or_else(|| text_parts.iter_mut().rev().find(|p| p.text.is_some()));
        if let Some(part) = target {
            part.thought_signature = Some(sig.to_string());
        }
    }
    parts.append(&mut text_parts);
    parts.append(&mut calls);
    parts
}

/// A tool result as a `functionResponse`. The name comes from the call it
/// answers; a result that parses as a JSON object is sent as is, anything
/// else as `{"result": <text>}`.
fn function_response(msg: &Message, earlier: &[Message]) -> Result<Part, LlmError> {
    let Some(id) = msg.tool_call_id.as_deref() else {
        return Err(LlmError::other(
            "tool message without tool_call_id: the API needs the call it answers",
        ));
    };
    let name = earlier
        .iter()
        .rev()
        .flat_map(|m| m.tool_calls.iter())
        .find(|tc| tc.id == id)
        .map(|tc| tc.name.clone())
        .ok_or_else(|| {
            LlmError::other(format!(
                "tool result `{id}` answers no earlier tool call in the conversation"
            ))
        })?;
    let text = msg.content.text_content();
    let response = match serde_json::from_str::<Value>(&text) {
        Ok(obj @ Value::Object(_)) => obj,
        _ => serde_json::json!({ "result": text }),
    };
    Ok(Part {
        function_response: Some(FunctionResponse {
            id: api_call_id(id),
            name,
            response,
        }),
        ..Part::default()
    })
}

/// A function declaration in Gemini's schema subset, via
/// [`rune_tool_schema`]'s Gemini dialect: `$ref`s are inlined (with depth
/// and size caps), type lists become `nullable` / `anyOf`, and keywords
/// Gemini rejects (`additionalProperties`, `const`, …) are rewritten or
/// removed. A schema that cannot be expressed fails locally.
pub fn function_declaration(def: &FunctionDefinition) -> Result<Value, LlmError> {
    let tool_err = |e: &dyn std::fmt::Display| LlmError::other(format!("tool `{}`: {e}", def.name));
    let schema = match &def.parameters {
        Value::Null => rune_tool_schema::empty_object_schema(),
        Value::Object(map) if map.is_empty() => rune_tool_schema::empty_object_schema(),
        other => other.clone(),
    };
    // The descriptor wants a description; the declaration does not.
    let placeholder = def.description.trim().is_empty();
    let description = if placeholder {
        def.name.as_str()
    } else {
        def.description.as_str()
    };
    let exported = ToolDescriptor::new(def.name.clone(), description)
        .with_input_schema(schema)
        .export_with(
            Dialect::Gemini,
            &ExportOptions::default().with_max_description_chars(MAX_TOOL_DESCRIPTION_CHARS),
        )
        .map_err(|e| tool_err(&e))?;
    let mut declaration = exported.definition;
    if placeholder && let Value::Object(map) = &mut declaration {
        map.remove("description");
    }
    Ok(declaration)
}

/// Convert a JSON Schema for `responseSchema`. `None` when the schema puts
/// no constraint Gemini can express on top of JSON mode (an object without
/// properties).
///
/// # Errors
///
/// A schema Gemini cannot express (recursive `$ref`s, tuple `items`, …).
pub fn response_schema(schema: &Value) -> Result<Option<Value>, LlmError> {
    let is_object = schema.get("type").and_then(Value::as_str) == Some("object");
    // Tool export wants an object root; wrap anything else as a property,
    // hoisting definitions so `$ref`s still resolve.
    let (root, wrapped) = if is_object {
        (schema.clone(), false)
    } else {
        let mut inner = schema.clone();
        let mut wrapper = Map::new();
        wrapper.insert("type".into(), "object".into());
        if let Value::Object(map) = &mut inner {
            for key in ["$defs", "definitions"] {
                if let Some(defs) = map.remove(key) {
                    wrapper.insert(key.into(), defs);
                }
            }
        }
        wrapper.insert(
            "properties".into(),
            Value::Object(Map::from_iter([("value".to_string(), inner)])),
        );
        (Value::Object(wrapper), true)
    };
    let exported = ToolDescriptor::new("response", "Structured response.")
        .with_input_schema(root)
        .export(Dialect::Gemini)
        .map_err(|e| LlmError::other(format!("response schema: {e}")))?;
    let Some(params) = exported.definition.get("parameters") else {
        return Ok(None);
    };
    Ok(Some(if wrapped {
        params["properties"]["value"].clone()
    } else {
        params.clone()
    }))
}

/// `toolConfig` for a tool choice. A named tool must be one of the tools.
pub fn tool_config(
    choice: Option<&ToolChoice>,
    tools: &[FunctionDefinition],
) -> Result<Option<ToolConfig>, LlmError> {
    let Some(choice) = choice else {
        return Ok(None);
    };
    if tools.is_empty() {
        return Ok(None);
    }
    let (mode, allowed) = match choice {
        ToolChoice::Auto => ("AUTO", Vec::new()),
        ToolChoice::None => ("NONE", Vec::new()),
        ToolChoice::Required => ("ANY", Vec::new()),
        ToolChoice::Tool(name) => {
            if !tools.iter().any(|t| &t.name == name) {
                return Err(LlmError::other(format!(
                    "tool choice names `{name}`, which is not among the tools"
                )));
            }
            ("ANY", vec![name.clone()])
        }
    };
    Ok(Some(ToolConfig {
        function_calling_config: FunctionCallingConfig {
            mode,
            allowed_function_names: allowed,
        },
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use rune_chain_core::ToolCall;
    use serde_json::json;

    use super::*;

    fn to_json(contents: &[Content]) -> Value {
        serde_json::to_value(contents).unwrap()
    }

    #[test]
    fn roles_system_and_merging() {
        let (system, contents) = build_contents(&[
            Message::system("Be terse."),
            Message::human("Hi"),
            Message::human("Again"),
            Message::ai(""),
            Message::ai("Hello"),
            Message::system("Second rule."),
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_value(system.unwrap()).unwrap(),
            json!({ "parts": [{ "text": "Be terse." }, { "text": "Second rule." }] })
        );
        assert_eq!(
            to_json(&contents),
            json!([
                { "role": "user", "parts": [{ "text": "Hi" }, { "text": "Again" }] },
                { "role": "model", "parts": [{ "text": "Hello" }] },
            ])
        );
        assert_eq!(build_contents(&[]).unwrap(), (None, vec![]));
    }

    #[test]
    fn tool_round_trip() {
        let calls = vec![
            ToolCall::new("gemini_call_r1_0", "get_weather", r#"{"city":"Paris"}"#),
            ToolCall::new("api-7", "get_time", ""),
        ];
        let ai = Message::ai_with_tool_calls("Checking.", calls).with_reasoning(vec![
            ReasoningBlock::new("unsigned summary"),
            ReasoningBlock::new("signed thought").with_signature("VEhP"),
            ReasoningBlock::default().with_signature("RkM="),
        ]);
        let (_, contents) = build_contents(&[
            Message::human("Weather and time in Paris?"),
            ai,
            Message::tool_result("gemini_call_r1_0", r#"{"temp_c": 21}"#),
            Message::tool_result("api-7", "12:00"),
            Message::human("Thanks"),
        ])
        .unwrap();
        assert_eq!(
            to_json(&contents),
            json!([
                { "role": "user", "parts": [{ "text": "Weather and time in Paris?" }] },
                { "role": "model", "parts": [
                    { "text": "signed thought", "thought": true, "thoughtSignature": "VEhP" },
                    { "text": "Checking." },
                    { "functionCall": { "name": "get_weather", "args": { "city": "Paris" } },
                      "thoughtSignature": "RkM=" },
                    { "functionCall": { "id": "api-7", "name": "get_time", "args": {} } },
                ]},
                { "role": "user", "parts": [
                    { "functionResponse": { "name": "get_weather", "response": { "temp_c": 21 } } },
                    { "functionResponse": { "id": "api-7", "name": "get_time",
                                            "response": { "result": "12:00" } } },
                    { "text": "Thanks" },
                ]},
            ])
        );
    }

    #[test]
    fn loose_signature_without_calls_goes_on_last_text() {
        let ai = Message::ai("Done.")
            .with_reasoning(vec![ReasoningBlock::default().with_signature("U0k=")]);
        let (_, contents) = build_contents(&[Message::human("x"), ai]).unwrap();
        assert_eq!(
            contents[1].parts[0].thought_signature.as_deref(),
            Some("U0k=")
        );
    }

    #[test]
    fn orphan_tool_results_fail() {
        assert!(build_contents(&[Message::tool_result("nope", "x")]).is_err());
        let mut no_id = Message::tool_result("x", "y");
        no_id.tool_call_id = None;
        assert!(build_contents(&[no_id]).is_err());
    }

    #[test]
    fn images() {
        let (_, contents) = build_contents(&[
            Message::human_with_image(
                "What is this?",
                ImageData::base64("image/png", "iVBORw0KGgo="),
            ),
            Message::human_with_image(
                "And this?",
                ImageData::url("https://example.com/cat.JPG?x=1"),
            ),
            Message::human_with_image(
                "And this?",
                ImageData::url("data:image/webp;base64,UklGRg=="),
            ),
            Message::human_with_image("And this?", ImageData::url("https://example.com/img")),
        ])
        .unwrap();
        let parts = to_json(&contents)[0]["parts"].clone();
        assert_eq!(
            parts[1],
            json!({ "inlineData": { "mimeType": "image/png", "data": "iVBORw0KGgo=" } })
        );
        assert_eq!(
            parts[3],
            json!({ "fileData": { "mimeType": "image/jpeg", "fileUri": "https://example.com/cat.JPG?x=1" } })
        );
        assert_eq!(
            parts[5],
            json!({ "inlineData": { "mimeType": "image/webp", "data": "UklGRg==" } })
        );
        assert_eq!(
            parts[7],
            json!({ "fileData": { "fileUri": "https://example.com/img" } })
        );
    }

    #[test]
    fn declarations_use_the_gemini_subset() {
        let def = FunctionDefinition::new(
            "search",
            "Search the index.",
            json!({
                "type": "object",
                "$defs": { "Filter": { "type": "object", "properties": {
                    "field": { "type": "string", "const": "title" },
                    "limit": { "type": ["integer", "null"] }
                }, "additionalProperties": false } },
                "properties": {
                    "q": { "type": "string" },
                    "filter": { "$ref": "#/$defs/Filter" },
                    "mode": { "oneOf": [{ "type": "string" }, { "type": "number" }] }
                },
                "required": ["q"],
                "additionalProperties": false
            }),
        );
        let decl = function_declaration(&def).unwrap();
        assert_eq!(
            decl,
            json!({
                "name": "search",
                "description": "Search the index.",
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "q": { "type": "STRING" },
                        "filter": { "type": "OBJECT", "properties": {
                            "field": { "type": "STRING", "enum": ["title"] },
                            "limit": { "type": "INTEGER", "nullable": true }
                        }},
                        "mode": { "anyOf": [{ "type": "STRING" }, { "type": "NUMBER" }] }
                    },
                    "required": ["q"]
                }
            })
        );
    }

    #[test]
    fn declarations_without_arguments_or_description() {
        let def =
            FunctionDefinition::new("ping", "", json!({ "type": "object", "properties": {} }));
        assert_eq!(
            function_declaration(&def).unwrap(),
            json!({ "name": "ping" })
        );
        let def = FunctionDefinition::new("ping", "Ping.", Value::Null);
        assert_eq!(
            function_declaration(&def).unwrap(),
            json!({ "name": "ping", "description": "Ping." })
        );
    }

    #[test]
    fn unexpressible_schemas_fail_locally() {
        let recursive = json!({
            "type": "object",
            "$defs": { "Node": { "type": "object", "properties": {
                "child": { "$ref": "#/$defs/Node" } } } },
            "properties": { "root": { "$ref": "#/$defs/Node" } }
        });
        let err = function_declaration(&FunctionDefinition::new("t", "d", recursive.clone()))
            .unwrap_err();
        assert!(err.message().contains("recursive"), "{err}");
        assert!(response_schema(&recursive).is_err());
        // Names Gemini refuses.
        let def = FunctionDefinition::new("1st", "d", json!({ "type": "object" }));
        assert!(function_declaration(&def).is_err());
    }

    #[test]
    fn deep_schemas_are_bounded() {
        let mut schema = json!({ "type": "string" });
        for _ in 0..500 {
            schema = json!({ "type": "object", "properties": { "x": schema } });
        }
        assert!(function_declaration(&FunctionDefinition::new("t", "d", schema)).is_err());
    }

    #[test]
    fn response_schemas() {
        let schema = json!({
            "type": "object",
            "properties": { "name": { "type": "string" } },
            "required": ["name"],
            "additionalProperties": false
        });
        assert_eq!(
            response_schema(&schema).unwrap(),
            Some(json!({
                "type": "OBJECT",
                "properties": { "name": { "type": "STRING" } },
                "required": ["name"]
            }))
        );
        let list = json!({
            "type": "array",
            "items": { "$ref": "#/$defs/City" },
            "$defs": { "City": { "type": "string" } }
        });
        assert_eq!(
            response_schema(&list).unwrap(),
            Some(json!({ "type": "ARRAY", "items": { "type": "STRING" } }))
        );
        assert_eq!(response_schema(&json!({ "type": "object" })).unwrap(), None);
    }

    #[test]
    fn tool_choices() {
        let tools = [FunctionDefinition::single_input("f", "d")];
        let wire = |c: ToolChoice| {
            serde_json::to_value(tool_config(Some(&c), &tools).unwrap().unwrap()).unwrap()
        };
        assert_eq!(
            wire(ToolChoice::Auto),
            json!({ "functionCallingConfig": { "mode": "AUTO" } })
        );
        assert_eq!(
            wire(ToolChoice::Required),
            json!({ "functionCallingConfig": { "mode": "ANY" } })
        );
        assert_eq!(
            wire(ToolChoice::None),
            json!({ "functionCallingConfig": { "mode": "NONE" } })
        );
        assert_eq!(
            wire(ToolChoice::Tool("f".into())),
            json!({ "functionCallingConfig": { "mode": "ANY", "allowedFunctionNames": ["f"] } })
        );
        assert!(tool_config(Some(&ToolChoice::Tool("g".into())), &tools).is_err());
        assert!(tool_config(Some(&ToolChoice::Auto), &[]).unwrap().is_none());
        assert!(tool_config(None, &tools).unwrap().is_none());
    }
}
