//! Typed extraction: parsing, schema validation and re-asking, offline.

#![allow(clippy::unwrap_used, reason = "test code")]

use std::sync::Arc;

use rune_chain::output_parser::{Mode, StructuredError};
use rune_chain::prelude::*;
use rune_chain::testing::{FakeLlm, FakeMethod, FakeReply};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, PartialEq, Deserialize, JsonSchema)]
struct Contact {
    /// Full name.
    name: String,
    /// Age in years.
    age: u32,
    /// Email address, if given.
    email: Option<String>,
}

#[tokio::test]
async fn extracts_a_typed_value() {
    let llm = Arc::new(FakeLlm::with_replies([
        r#"Sure: {"name": "Ada Lovelace", "age": 36, "email": "ada@example.com"}"#,
    ]));
    let extractor = ExtractorBuilder::<_, Contact>::new(Arc::clone(&llm))
        .build()
        .unwrap();
    let contact = extractor
        .extract("Ada Lovelace, 36, ada@example.com")
        .await
        .unwrap();
    assert_eq!(
        contact,
        Contact {
            name: "Ada Lovelace".into(),
            age: 36,
            email: Some("ada@example.com".into()),
        }
    );

    let req = llm.last_request().unwrap();
    assert_eq!(req.method, FakeMethod::GenerateStructured);
    assert_eq!(req.prompt().unwrap(), "Ada Lovelace, 36, ada@example.com");
    assert!(req.system().unwrap().contains("JSON"));
    let format = req.format.unwrap();
    assert!(format.is_json());
    assert_eq!(extractor.schema()["properties"]["age"]["type"], "integer");
}

#[tokio::test]
async fn reasks_with_the_error_until_the_answer_fits() {
    let llm = Arc::new(FakeLlm::with_replies([
        "I could not find anything.",
        r#"{"name": "Ada", "age": -4}"#,
        r#"{"name": "Ada", "age": 36}"#,
    ]));
    let extractor = ExtractorBuilder::<_, Contact>::new(Arc::clone(&llm))
        .max_retries(3)
        .build()
        .unwrap();
    let out = extractor.extract_with_details("Ada, 36").await.unwrap();
    assert_eq!(out.value.age, 36);
    assert_eq!(out.attempts, 3);

    // The last re-ask carries the rejected answer and what was wrong.
    let last = llm.last_request().unwrap();
    let n = last.messages.len();
    assert_eq!(last.messages[n - 2].role, Role::Ai);
    assert!(last.messages[n - 2].text().contains("-4"));
    assert_eq!(last.messages[n - 1].role, Role::Human);
}

#[tokio::test]
async fn validators_trigger_a_reask() {
    let llm = Arc::new(FakeLlm::with_replies([
        r#"{"name": "Ada", "age": 250}"#,
        r#"{"name": "Ada", "age": 36}"#,
    ]));
    let extractor = ExtractorBuilder::<_, Contact>::new(Arc::clone(&llm))
        .validator(|c: &Contact| {
            if c.age < 150 {
                Ok(())
            } else {
                Err(format!("age {} is implausible", c.age))
            }
        })
        .build()
        .unwrap();
    let out = extractor.extract_with_details("Ada, 36").await.unwrap();
    assert_eq!(out.attempts, 2);
    let feedback = llm.last_request().unwrap().prompt().unwrap();
    assert!(feedback.contains("implausible"), "{feedback}");
}

#[tokio::test]
async fn gives_up_after_the_retry_budget() {
    let llm = FakeLlm::from_fn(|_| Ok(GenerateResult::from_text("no json here")));
    let extractor = ExtractorBuilder::<_, Contact>::new(llm)
        .max_retries(1)
        .build()
        .unwrap();
    let err = extractor.extract("?").await.unwrap_err();
    assert!(
        matches!(err, StructuredError::RetriesExhausted { attempts: 2, .. }),
        "{err}"
    );
}

#[tokio::test]
async fn transport_errors_are_not_retried() {
    let llm = Arc::new(FakeLlm::with_replies([FakeReply::timeout()]));
    let extractor = ExtractorBuilder::<_, Contact>::new(Arc::clone(&llm))
        .build()
        .unwrap();
    assert!(matches!(
        extractor.extract("x").await,
        Err(StructuredError::Llm(_))
    ));
    assert_eq!(llm.call_count(), 1);
}

#[tokio::test]
async fn prompt_mode_preamble_and_context() {
    let llm = Arc::new(FakeLlm::with_replies([r#"{"name": "Bo", "age": 5}"#]));
    let extractor = ExtractorBuilder::<_, Contact>::new(Arc::clone(&llm))
        .mode(Mode::Prompt)
        .preamble("Pull out the contact.")
        .context("Ages are in years.")
        .build()
        .unwrap();
    extractor.extract("Bo is five").await.unwrap();
    let req = llm.last_request().unwrap();
    assert_eq!(req.method, FakeMethod::Generate);
    let system = req.system().unwrap();
    assert!(system.starts_with("Pull out the contact."));
    assert!(system.contains("Ages are in years."));
}

#[tokio::test]
async fn extracts_from_a_conversation() {
    let llm = Arc::new(FakeLlm::with_replies([r#"{"name": "Ada", "age": 36}"#]));
    let extractor = ExtractorBuilder::<_, Contact>::new(Arc::clone(&llm))
        .build()
        .unwrap();
    let out = extractor
        .extract_from_messages(&[
            Message::human("I'm Ada."),
            Message::ai("Hi Ada, how old are you?"),
            Message::human("36."),
        ])
        .await
        .unwrap();
    assert_eq!(out.value.name, "Ada");
    assert_eq!(llm.last_request().unwrap().messages.len(), 4);
}
