//! Stream an answer token by token, with conversation memory.
//!
//! Run with `ANTHROPIC_API_KEY=... cargo run -p rune-chain --features anthropic --example streaming`.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use std::io::Write as _;

use futures::StreamExt;
use rune_chain::anthropic;
use rune_chain::memory::WindowedMemory;
use rune_chain::prelude::*;

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
    Ok(())
}
