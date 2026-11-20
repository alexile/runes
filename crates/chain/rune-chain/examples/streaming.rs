//! Stream answers token by token: a poet with memory, then an agent with a
//! tool, whose tool calls show up in the stream as they happen.
//!
//! Run with `ANTHROPIC_API_KEY=... cargo run -p rune-chain --features anthropic --example streaming`.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use std::io::Write as _;

use futures::StreamExt;
use rune_chain::anthropic;
use rune_chain::memory::WindowedMemory;
use rune_chain::prelude::*;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
struct WordsArgs {
    /// The text to count.
    text: String,
}

struct CountWords;

#[async_trait::async_trait]
impl TypedTool for CountWords {
    type Args = WordsArgs;
    type Output = usize;
    fn name(&self) -> &'static str {
        "count_words"
    }
    fn description(&self) -> &'static str {
        "Count the words in a text."
    }
    async fn call(&self, args: WordsArgs) -> Result<usize, ToolError> {
        Ok(args.text.split_whitespace().count())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = anthropic::Client::from_env()?;
    let poet = client
        .agent(anthropic::models::CLAUDE_SONNET_5_5)
        .preamble("You write short poems.")
        .memory(WindowedMemory::new(20))
        .max_tokens(400)
        .build();

    for prompt in [
        "A haiku about Rust's borrow checker.",
        "Now the same as a limerick.",
    ] {
        let mut stream = poet.stream_prompt(prompt).await?;
        while let Some(chunk) = stream.next().await {
            print!("{}", chunk?.content);
            std::io::stdout().flush()?;
        }
        println!("\n");
    }

    // With tools, every turn streams; `stream_events` also reports the calls.
    let editor = client
        .agent(anthropic::models::CLAUDE_SONNET_5_5)
        .preamble("You edit poems. Check word counts with the tool, never by hand.")
        .typed_tool(CountWords)
        .max_tokens(600)
        .build();
    let mut stream = editor
        .stream_events("Write a four-line poem about ferris the crab, then tell me its word count.")
        .await?;
    while let Some(item) = stream.next().await {
        match item? {
            AgentStreamItem::Text(text) => print!("{text}"),
            AgentStreamItem::ToolCall { name, .. } => println!("\n[calling {name}]"),
            AgentStreamItem::ToolResult { invocation, .. } => {
                println!("[{} -> {}]", invocation.name, invocation.output);
            }
            AgentStreamItem::Final(response) => {
                println!("\n\n{} turn(s), usage {:?}", response.turns, response.usage);
            }
            _ => {}
        }
        std::io::stdout().flush()?;
    }
    Ok(())
}
