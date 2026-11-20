//! Human-in-the-loop: a node pauses with `interrupt`, a person answers, and
//! the run resumes from its checkpoint.
//!
//! Run with `cargo run -p rune-chain-graph --example human_approval`.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use std::sync::Arc;

use rune_chain_graph::{
    Append, Command, CompileOptions, END, GraphError, InMemoryCheckpointer, Replace, RunConfig,
    START, StateGraph, state,
};
use serde::{Deserialize, Serialize};

state! {
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct Refund => RefundUpdate {
        customer: String = Replace,
        amount: u32 = Replace,
        decision: String = Replace,
        log: Vec<String> = Append,
    }
}

#[derive(Debug, Deserialize)]
struct Review {
    approve: bool,
    amount: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<(), GraphError> {
    let mut graph = StateGraph::<Refund>::new();
    graph
        .add_node("propose", |s: Arc<Refund>, _| async move {
            Ok(RefundUpdate::default()
                .log(vec![format!("proposed {} for {}", s.amount, s.customer)]))
        })
        .add_node("review", |s: Arc<Refund>, ctx| async move {
            // Pauses the run the first time; returns the answer on resume.
            let review: Review = ctx.interrupt(serde_json::json!({
                "question": "Approve this refund?",
                "customer": s.customer,
                "amount": s.amount,
            }))?;
            let amount = review.amount.unwrap_or(s.amount);
            let decision = if review.approve {
                "approved"
            } else {
                "rejected"
            };
            Ok(RefundUpdate::default()
                .amount(amount)
                .decision(decision.into())
                .log(vec![format!("{decision} at {amount}")]))
        })
        .add_node("pay", |s: Arc<Refund>, _| async move {
            Ok(RefundUpdate::default().log(vec![format!("paid {} to {}", s.amount, s.customer)]))
        })
        .add_edge(START, "propose")
        .add_edge("propose", "review")
        .add_conditional_edges(
            "review",
            |s: &Refund| if s.decision == "approved" { "pay" } else { END },
            ["pay", END],
        )
        .add_edge("pay", END);

    let app = graph.compile_with(
        CompileOptions::default().checkpointer(Arc::new(InMemoryCheckpointer::new())),
    )?;
    let config = RunConfig::thread("refund-1042");

    let request = Refund {
        customer: "ada".into(),
        amount: 120,
        ..Refund::default()
    };
    let paused = app.invoke(request, &config).await?;
    if let Some(interrupt) = &paused.interrupt {
        println!("waiting on a person: {}", interrupt.value);
    }

    // Later, possibly in another process sharing the checkpointer:
    let done = app
        .invoke(
            Command::resume(serde_json::json!({ "approve": true, "amount": 100 })),
            &config,
        )
        .await?;
    for line in &done.state.log {
        println!("{line}");
    }

    for snapshot in app.get_state_history(&config, 10).await? {
        println!(
            "checkpoint {} step {} next {:?}",
            snapshot.checkpoint_id, snapshot.step, snapshot.next
        );
    }
    Ok(())
}
