//! Map-reduce: split work into a dynamic number of parallel tasks with
//! `SendTo`, then combine their results in one step.
//!
//! Run with `cargo run -p rune-chain-graph --example map_reduce`.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use std::sync::Arc;

use rune_chain_core::Llm;
use rune_chain_core::testing::FakeLlm;
use rune_chain_core::{GenerateResult, Message};
use rune_chain_graph::{
    Append, END, GraphError, Replace, RunConfig, START, SendTo, StateGraph, state,
};
use serde::{Deserialize, Serialize};

state! {
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct Digest => DigestUpdate {
        documents: Vec<String> = Replace,
        // Set privately on each map task by `SendTo`.
        document: String = Replace,
        summaries: Vec<String> = Append,
        digest: String = Replace,
    }
}

#[tokio::main]
async fn main() -> Result<(), GraphError> {
    // A stand-in model that "summarises" by keeping the first sentence.
    let llm: Arc<dyn Llm> = Arc::new(FakeLlm::from_fn(|req| {
        let text = req.prompt().unwrap_or_default();
        let first = text
            .split(". ")
            .next()
            .unwrap_or_default()
            .trim_end_matches('.');
        Ok(GenerateResult::from_text(format!("{first}.")))
    }));

    let mut graph = StateGraph::<Digest>::new();
    let model = Arc::clone(&llm);
    graph
        .add_node("summarise", move |s: Arc<Digest>, _| {
            let model = Arc::clone(&model);
            async move {
                let reply = model
                    .generate(&[Message::human(s.document.as_str())])
                    .await?;
                Ok(DigestUpdate::default().summaries(vec![reply.generation]))
            }
        })
        .add_node("combine", |s: Arc<Digest>, _| async move {
            // Map results arrive in document order, however long each took.
            Ok(DigestUpdate::default().digest(s.summaries.join("\n")))
        })
        .add_conditional_edges(
            START,
            |s: &Digest| {
                s.documents
                    .iter()
                    .map(|d| SendTo::new("summarise", DigestUpdate::default().document(d.clone())))
                    .collect::<Vec<_>>()
            },
            ["summarise"],
        )
        .add_edge("summarise", "combine")
        .add_edge("combine", END);
    let app = graph.compile()?;

    let input = Digest {
        documents: vec![
            "Let chains landed in Rust 2024. They make nested matches flatter.".into(),
            "The graph runs map tasks in parallel. Results merge in task order.".into(),
            "Checkpoints make runs resumable. They also allow time travel.".into(),
        ],
        ..Digest::default()
    };
    let out = app.invoke(input, &RunConfig::default()).await?;
    println!("{}", out.state.digest);
    Ok(())
}
