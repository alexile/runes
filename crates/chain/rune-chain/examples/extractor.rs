//! Typed extraction: free text in, a validated struct out.
//!
//! Run with `OPENAI_API_KEY=... cargo run -p rune-chain --example extractor`.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use rune_chain::openai;
use rune_chain::prelude::*;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
struct Invoice {
    /// Who the invoice is from.
    vendor: String,
    /// Total amount due, in the invoice currency.
    total: f64,
    /// ISO 4217 currency code, e.g. "EUR".
    currency: String,
    /// Line items.
    items: Vec<Item>,
}

#[derive(Deserialize, JsonSchema)]
struct Item {
    description: String,
    quantity: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = openai::Client::from_env()?;
    let extractor = client
        .extractor::<Invoice>("gpt-4o-mini")
        .validator(|inv: &Invoice| {
            if inv.total >= 0.0 {
                Ok(())
            } else {
                Err("total must not be negative".into())
            }
        })
        .build()?;

    let invoice = extractor
        .extract("Acme GmbH billed us 3 anvils and 1 rocket skate, 1,249.50 EUR in total.")
        .await?;
    println!(
        "{}: {:.2} {}",
        invoice.vendor, invoice.total, invoice.currency
    );
    for item in &invoice.items {
        println!("  {} x {}", item.quantity, item.description);
    }
    Ok(())
}
