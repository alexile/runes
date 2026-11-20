//! Tools from plain functions with `#[tool]`.
//!
//! Run with `OPENAI_API_KEY=... cargo run -p rune-chain --example tool_macro`.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use rune_chain::{ToolError, openai, prelude::*};

/// Convert a temperature from Celsius to Fahrenheit.
#[tool]
fn celsius_to_fahrenheit(
    /// Degrees Celsius.
    celsius: f64,
) -> f64 {
    celsius.mul_add(9.0 / 5.0, 32.0)
}

/// Current temperature in a city, in Celsius.
#[tool]
fn current_temperature(
    /// City name, like "Oslo".
    city: &str,
) -> Result<f64, ToolError> {
    match city.to_lowercase().as_str() {
        "oslo" => Ok(-3.5),
        "lisbon" => Ok(19.0),
        _ => Err(ToolError::InvalidInput(format!("no data for {city}"))),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let agent = openai::Client::from_env()?
        .agent("gpt-4o-mini")
        .preamble("Answer weather questions with the tools.")
        .tool(CurrentTemperature)
        .tool(CelsiusToFahrenheit)
        .build();

    println!(
        "{}",
        agent
            .prompt("How warm is it in Lisbon, in Fahrenheit?")
            .await?
    );
    Ok(())
}
