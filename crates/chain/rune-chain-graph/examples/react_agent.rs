//! The prebuilt tool-calling agent, run offline against a scripted model.
//!
//! Run with `cargo run -p rune-chain-graph --example react_agent`. Swap
//! `FakeLlm` for any provider (`rune-chain-openai`, `rune-chain-anthropic`,
//! ...) to use a real model.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use rune_chain_core::testing::{FakeLlm, FakeReply};
use rune_chain_core::{Message, Tool, ToolCall, ToolError};
use rune_chain_graph::{Event, MessagesState, RunConfig, ToolExecutor, create_react_agent};

struct Weather;

#[async_trait]
impl Tool for Weather {
    fn name(&self) -> &'static str {
        "weather"
    }
    fn description(&self) -> &'static str {
        "Current weather for a city."
    }
    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": { "city": { "type": "string" } },
            "required": ["city"]
        })
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let args: serde_json::Value =
            serde_json::from_str(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;
        let city = args["city"].as_str().unwrap_or("?");
        Ok(format!("{city}: 18°C, light rain"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The model first asks for the tool, then answers from its result.
    let llm = FakeLlm::with_replies([
        FakeReply::tool_calls([ToolCall::new("call_1", "weather", r#"{"city":"Lisbon"}"#)]),
        FakeReply::text("It is 18°C with light rain in Lisbon. Take an umbrella."),
    ]);
    let agent = create_react_agent(Arc::new(llm), ToolExecutor::new().tool(Weather))?;

    println!("{}", agent.draw_mermaid());

    let input = MessagesState::new(vec![Message::human("Do I need an umbrella in Lisbon?")]);
    let mut events = agent.stream(input, &RunConfig::default());
    while let Some(event) = events.next().await {
        match event? {
            Event::Update { step, node, update } => {
                for m in update.messages.unwrap_or_default() {
                    let text = if m.tool_calls.is_empty() {
                        m.text()
                    } else {
                        format!("calls {}", m.tool_calls[0].name)
                    };
                    println!("[{step}] {node}: {text}");
                }
            }
            Event::Done(out) => println!("answer: {}", out.state.last_text()),
            _ => {}
        }
    }
    Ok(())
}
