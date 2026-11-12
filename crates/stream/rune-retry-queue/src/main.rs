//! `rune-retry-queue` command-line tool: dead-letter queue with configurable backoff retry for failed sink writes.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, ValueEnum};
use rune_retry_queue::BackoffPolicy;
use std::time::Duration;

/// Print the retry-delay schedule a backoff policy would produce.
#[derive(Parser)]
#[command(name = "rune-retry-queue")]
struct Args {
    /// Backoff policy to preview.
    #[arg(long, value_enum, default_value_t = Policy::Fixed)]
    policy: Policy,

    /// Base delay in milliseconds (used as-is for `fixed`, as attempt-0 delay for `exponential`).
    #[arg(long, default_value_t = 1_000)]
    delay_ms: u64,

    /// Growth factor per attempt (exponential only).
    #[arg(long, default_value_t = 2.0)]
    factor: f64,

    /// Cap on the computed delay, in milliseconds (exponential only).
    #[arg(long, default_value_t = 30_000)]
    max_delay_ms: u64,

    /// Number of attempts to preview.
    #[arg(long, default_value_t = 5)]
    max_attempts: u32,
}

#[derive(Clone, ValueEnum)]
enum Policy {
    Fixed,
    Exponential,
}

fn main() {
    let args = Args::parse();

    let backoff = match args.policy {
        Policy::Fixed => BackoffPolicy::Fixed(Duration::from_millis(args.delay_ms)),
        Policy::Exponential => BackoffPolicy::Exponential {
            base: Duration::from_millis(args.delay_ms),
            factor: args.factor,
            max: Duration::from_millis(args.max_delay_ms),
        },
    };

    for attempt in 0..args.max_attempts {
        println!("attempt {attempt}: {:?}", backoff.delay_for(attempt));
    }
}
