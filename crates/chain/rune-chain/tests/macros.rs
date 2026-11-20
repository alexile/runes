//! `#[tool]` through the facade: the generated code only needs what
//! `rune_chain` re-exports.

#![cfg(feature = "macros")]
#![allow(
    clippy::unwrap_used,
    clippy::unused_async,
    clippy::needless_pass_by_value,
    reason = "test code: async and owned arguments are part of what is tested"
)]

use std::sync::Arc;

use rune_chain::prelude::*;
use rune_chain::testing::{FakeLlm, FakeReply};
use rune_chain::{ToolCall, ToolError};

/// Add two integers.
#[tool(crate = "rune_chain")]
fn add(
    /// The first number.
    a: i64,
    /// The second number.
    b: i64,
) -> Result<i64, ToolError> {
    a.checked_add(b)
        .ok_or_else(|| ToolError::InvalidInput("overflow".into()))
}

/// Greet someone.
#[tool(crate = "rune_chain", name = "greet")]
async fn greeting(
    /// Who to greet.
    name: &str,
) -> String {
    format!("Hello, {name}!")
}

/// Uses the default path resolution.
#[tool]
fn shout(
    /// Text to shout.
    text: String,
) -> String {
    text.to_uppercase()
}

#[tokio::test]
async fn tool_fns_work_through_the_facade() {
    assert_eq!(Add.name(), "add");
    assert_eq!(Add.description(), "Add two integers.");
    assert_eq!(Add.schema()["properties"]["a"]["type"], "integer");
    assert_eq!(Add.run(r#"{"a": 2, "b": 40}"#).await.unwrap(), "42");
    assert!(Add.run(r#"{"a": "two", "b": 1}"#).await.is_err());
    assert!(
        Add.run(&format!(r#"{{"a": {}, "b": 1}}"#, i64::MAX))
            .await
            .is_err()
    );
    assert_eq!(Greeting.name(), "greet");
    assert_eq!(
        Greeting.run(r#"{"name": "Ada"}"#).await.unwrap(),
        "Hello, Ada!"
    );
    assert_eq!(Shout.run(r#"{"text": "hi"}"#).await.unwrap(), "HI");
}

#[tokio::test]
async fn tool_fns_plug_into_an_agent() {
    let llm = Arc::new(FakeLlm::with_replies([
        FakeReply::tool_calls([
            ToolCall::new("c1", "add", r#"{"a": 2, "b": 40}"#),
            ToolCall::new("c2", "greet", r#"{"name": "Ada"}"#),
        ]),
        FakeReply::text("42, and hello Ada."),
    ]));
    let agent = AgentBuilder::new(Arc::clone(&llm))
        .tool(Add)
        .tool(Greeting)
        .build();
    let res = agent
        .prompt_with_details("2+40, then greet Ada")
        .await
        .unwrap();
    assert_eq!(res.output, "42, and hello Ada.");
    let outputs: Vec<_> = res.tool_calls.iter().map(|c| c.output.as_str()).collect();
    assert_eq!(outputs, ["42", "Hello, Ada!"]);
    assert_eq!(llm.requests()[0].tool_names(), ["add", "greet"]);
}

#[cfg(feature = "embed")]
#[test]
fn embed_derive_is_reachable() {
    use rune_chain::embed::Embed;

    #[derive(Embed)]
    #[embed(crate = "rune_chain::embed")]
    struct Note {
        #[embed]
        body: String,
        #[allow(dead_code, reason = "not embedded")]
        id: u32,
    }

    let note = Note {
        body: "hello".into(),
        id: 1,
    };
    let texts = note.texts();
    assert_eq!(texts, ["hello"]);
}
