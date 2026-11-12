//! `rune-changepoint` command-line tool: cUSUM-style changepoint detection over a numeric series.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_changepoint::detect;

/// Detect CUSUM changepoints in a list of numbers.
#[derive(Parser)]
#[command(name = "rune-changepoint")]
struct Args {
    /// Expected baseline value of the series.
    #[arg(long, default_value_t = 0.0)]
    target: f64,
    /// Cumulative sum threshold that signals a changepoint.
    #[arg(long, default_value_t = 5.0)]
    threshold: f64,
    /// Drift allowance subtracted from each increment.
    #[arg(long, default_value_t = 0.5)]
    drift: f64,
    /// Input values, in order.
    values: Vec<f64>,
}

fn main() {
    let args = Args::parse();
    let changes = detect(&args.values, args.target, args.threshold, args.drift);

    for (index, direction) in changes {
        println!("{index}: {direction:?}");
    }
}
