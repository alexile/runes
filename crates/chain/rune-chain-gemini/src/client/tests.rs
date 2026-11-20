#![allow(clippy::unwrap_used, reason = "tests")]

use rune_chain_core::{ImageData, LlmErrorKind};
use serde_json::json;

use super::*;
use crate::{HarmBlockThreshold, HarmCategory, ThinkingLevel};

fn body(llm: &Gemini, messages: &[Message]) -> serde_json::Value {
    serde_json::to_value(llm.request_body(messages, &[], None).unwrap()).unwrap()
}

#[test]
fn minimal_body() {
    let llm = Gemini::new("k");
    assert_eq!(
        body(&llm, &[Message::human("Hi")]),
        json!({ "contents": [{ "role": "user", "parts": [{ "text": "Hi" }] }] })
    );
}

#[test]
fn generation_config_and_safety() {
    let llm = Gemini::new("k")
        .model(models::GEMINI_2_5_FLASH)
        .temperature(0.5)
        .top_p(0.9)
        .top_k(40)
        .max_output_tokens(256)
        .stop_sequences(["END"])
        .seed(7)
        .thinking(Thinking::budget(1024).with_thoughts())
        .safety(HarmCategory::Harassment, HarmBlockThreshold::BlockNone)
        .safety(HarmCategory::Harassment, HarmBlockThreshold::BlockOnlyHigh)
        .cached_content("cachedContents/abc");
    assert_eq!(
        body(&llm, &[Message::human("Hi")]),
        json!({
            "contents": [{ "role": "user", "parts": [{ "text": "Hi" }] }],
            "safetySettings": [
                { "category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_ONLY_HIGH" }
            ],
            "generationConfig": {
                "temperature": 0.5,
                "topP": 0.9,
                "topK": 40,
                "maxOutputTokens": 256,
                "stopSequences": ["END"],
                "seed": 7,
                "thinkingConfig": { "thinkingBudget": 1024, "includeThoughts": true }
            },
            "cachedContent": "cachedContents/abc"
        })
    );
}

#[test]
fn preflight_rejects_bad_settings_locally() {
    let msgs = [Message::human("Hi")];
    let err = |llm: Gemini| llm.preflight(&msgs).unwrap_err();
    assert!(
        err(Gemini::new("k").temperature(3.0))
            .message()
            .contains("temperature")
    );
    assert!(
        err(Gemini::new("k").temperature(f32::NAN))
            .message()
            .contains("temperature")
    );
    assert!(err(Gemini::new("k").top_p(1.5)).message().contains("top_p"));
    assert!(err(Gemini::new("k").top_k(0)).message().contains("top_k"));
    assert!(
        err(Gemini::new("k").max_output_tokens(0))
            .message()
            .contains("max_output")
    );
    assert!(
        err(Gemini::new("k").stop_sequences(["a", "b", "c", "d", "e", "f"]))
            .message()
            .contains("stop sequences")
    );
    assert!(
        err(Gemini::new("k").model("../../x"))
            .message()
            .contains("model id")
    );
    assert!(
        err(Gemini::new("k").base_url("http://example.com"))
            .message()
            .contains("HTTP")
    );

    // Thinking settings known models reject.
    let pro = Gemini::new("k").model(models::GEMINI_2_5_PRO);
    assert!(
        err(pro.clone().thinking(Thinking::off()))
            .message()
            .contains("cannot turn thinking off")
    );
    assert!(
        err(pro.clone().thinking(Thinking::budget(64)))
            .message()
            .contains("128..=32768")
    );
    assert!(
        err(pro.thinking(Thinking::level(ThinkingLevel::Low)))
            .message()
            .contains("level")
    );
    assert!(
        err(Gemini::new("k")
            .model(models::GEMINI_2_0_FLASH)
            .thinking(Thinking::dynamic()))
        .message()
        .contains("does not think")
    );
    let g3 = Gemini::new("k").model(models::GEMINI_3_PRO_PREVIEW);
    assert!(
        err(g3.clone().thinking(Thinking::level(ThinkingLevel::Minimal)))
            .message()
            .contains("minimal")
    );
    assert!(
        g3.thinking(Thinking::level(ThinkingLevel::Low))
            .preflight(&msgs)
            .is_ok()
    );
    // Unknown models are not checked.
    assert!(
        Gemini::new("k")
            .model("gemini-next")
            .thinking(Thinking::off())
            .preflight(&msgs)
            .is_ok()
    );

    // Malformed images and empty conversations.
    let bad = Message::human_with_image("x", ImageData::url("file:///etc/passwd"));
    assert!(Gemini::new("k").preflight(&[bad]).is_err());
    assert!(Gemini::new("k").preflight(&[]).is_err());
    assert!(
        Gemini::new("k")
            .preflight(&[Message::system("only")])
            .is_err()
    );
}

#[test]
fn debug_never_shows_secrets() {
    let llm = Gemini::new("AIzaSy-very-secret-key");
    let shown = format!("{llm:?}");
    assert!(!shown.contains("very-secret"), "{shown}");
    assert!(shown.contains("REDACTED"));
    let vertex = Gemini::vertex_ai("proj", "global", "ya29.secret-token").unwrap();
    assert!(!format!("{vertex:?}").contains("secret-token"));
    assert_eq!(
        vertex.base_url_str(),
        "https://aiplatform.googleapis.com/v1/projects/proj/locations/global/publishers/google"
    );
    assert!(Gemini::vertex_ai("Bad/Project", "us", "t").is_err());
    assert!(Gemini::vertex_ai("p", "us central", "t").is_err());
}

#[test]
fn model_prefix_is_dropped() {
    let llm = Gemini::new("k").model("models/gemini-2.5-pro");
    assert_eq!(llm.model_id(), "gemini-2.5-pro");
    assert_eq!(llm.model_info().unwrap().id, models::GEMINI_2_5_PRO);
    assert_eq!(Gemini::new("k").model_id(), models::DEFAULT_MODEL);
}

#[test]
fn structured_output_needs_a_complete_answer() {
    let mut r = GeminiResponse {
        finish_reason: Some("SAFETY".into()),
        ..GeminiResponse::default()
    };
    assert_eq!(
        check_structured(&r).unwrap_err().kind(),
        LlmErrorKind::Provider
    );
    r.finish_reason = Some("MAX_TOKENS".into());
    assert_eq!(
        check_structured(&r).unwrap_err().kind(),
        LlmErrorKind::InvalidResponse
    );
    r.finish_reason = Some("STOP".into());
    assert!(check_structured(&r).is_ok());
}
