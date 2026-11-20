//! Retrieval-augmented agent: the three most relevant notes are added to
//! every prompt.
//!
//! Run with `OPENAI_API_KEY=... cargo run -p rune-chain --features retrieval --example rag`.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use rune_chain::openai;
use rune_chain::prelude::*;
use rune_chain::vectorstore::InMemoryVectorStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = openai::Client::from_env()?;

    let index = EmbeddingIndex::new(
        client.embedding_model("text-embedding-3-small"),
        InMemoryVectorStore::default(),
    );
    index
        .add_documents([
            (
                "glarb",
                "A glarb is a small, blue, furry creature that hums when it is happy.",
            ),
            (
                "flurn",
                "A flurn is a tool used by glarb herders to brush their fur.",
            ),
            (
                "zorp",
                "Zorp is the season when glarbs migrate to the northern hills.",
            ),
            ("tea", "Hibiscus tea is red and slightly sour."),
        ])
        .await?;

    let agent = client
        .agent("gpt-4o-mini")
        .preamble("Answer using only the reference documents. Say so when they do not cover the question.")
        .dynamic_context(3, index)
        .build();

    let answer = agent
        .prompt_with_details("What would a glarb herder carry during zorp?")
        .await?;
    println!("{}\n", answer.output);
    for doc in &answer.documents {
        println!("source {} (score {:.2})", doc.metadata["id"], doc.score);
    }
    Ok(())
}
