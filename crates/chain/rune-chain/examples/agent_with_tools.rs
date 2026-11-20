//! An agent with two typed tools and a sub-agent as a third tool.
//!
//! Run with `OPENAI_API_KEY=... cargo run -p rune-chain --example agent_with_tools`.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use rune_chain::openai;
use rune_chain::prelude::*;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
struct MathArgs {
    /// Left operand.
    x: f64,
    /// Right operand.
    y: f64,
}

struct Add;

#[async_trait::async_trait]
impl TypedTool for Add {
    type Args = MathArgs;
    type Output = f64;
    fn name(&self) -> &'static str {
        "add"
    }
    fn description(&self) -> &'static str {
        "Add x and y."
    }
    async fn call(&self, args: MathArgs) -> Result<f64, ToolError> {
        Ok(args.x + args.y)
    }
}

struct Multiply;

#[async_trait::async_trait]
impl TypedTool for Multiply {
    type Args = MathArgs;
    type Output = f64;
    fn name(&self) -> &'static str {
        "multiply"
    }
    fn description(&self) -> &'static str {
        "Multiply x by y."
    }
    async fn call(&self, args: MathArgs) -> Result<f64, ToolError> {
        Ok(args.x * args.y)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = openai::Client::from_env()?;

    // A specialist that other agents can call like any tool.
    let explainer = client
        .agent("gpt-4o-mini")
        .preamble("Explain a calculation to a ten-year-old in one sentence.")
        .name("explainer")
        .description("Explains a finished calculation in plain words.")
        .build();

    let calculator = client
        .agent("gpt-4o-mini")
        .preamble("You are a calculator. Use the tools for every operation, then ask the explainer to explain the result.")
        .typed_tool(Add)
        .typed_tool(Multiply)
        .tool(explainer)
        .temperature(0.0)
        .max_turns(6)
        .build();

    let answer = calculator
        .prompt_with_details("What is (3 + 4) * 6?")
        .await?;
    for call in &answer.tool_calls {
        println!("{}({}) -> {}", call.name, call.arguments, call.output);
    }
    println!("\n{}", answer.output);
    Ok(())
}
