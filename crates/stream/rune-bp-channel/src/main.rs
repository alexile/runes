//! `rune-bp-channel` command-line tool: bounded channel wrapper with configurable backpressure policy: drop-oldest, drop-newest, block.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, ValueEnum};
use rune_bp_channel::{BackpressurePolicy, PushOutcome, channel};
use std::io::{self, BufRead};
use std::process::ExitCode;
use std::thread;

#[derive(Copy, Clone, ValueEnum)]
enum Policy {
    DropOldest,
    DropNewest,
    Block,
}

impl From<Policy> for BackpressurePolicy {
    fn from(policy: Policy) -> Self {
        match policy {
            Policy::DropOldest => Self::DropOldest,
            Policy::DropNewest => Self::DropNewest,
            Policy::Block => Self::Block,
        }
    }
}

/// Feed stdin lines through a bounded channel and report what happened to each one.
#[derive(Parser)]
#[command(name = "rune-bp-channel")]
struct Args {
    /// Maximum number of buffered lines.
    #[arg(long, default_value_t = 4)]
    capacity: usize,

    /// Backpressure policy applied once the buffer is full.
    #[arg(long, value_enum, default_value = "block")]
    policy: Policy,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let lines: Vec<String> = io::stdin().lock().lines().map_while(Result::ok).collect();

    let (tx, rx) = channel::<String>(args.capacity, args.policy.into());

    let producer = thread::spawn(move || {
        let mut accepted = 0usize;
        let mut dropped = 0usize;
        for line in lines {
            match tx.send(line) {
                PushOutcome::Accepted | PushOutcome::BlockedThenAccepted => accepted += 1,
                PushOutcome::DroppedOldest(_) | PushOutcome::DroppedNewest(_) => dropped += 1,
            }
        }
        (accepted, dropped)
    });

    let mut received = Vec::new();
    while let Some(item) = rx.recv() {
        received.push(item);
    }

    let Ok((accepted, dropped)) = producer.join() else {
        eprintln!("error: producer thread panicked");
        return ExitCode::FAILURE;
    };

    for item in &received {
        println!("{item}");
    }
    eprintln!(
        "{accepted} accepted, {dropped} dropped, {} received",
        received.len()
    );
    ExitCode::SUCCESS
}
