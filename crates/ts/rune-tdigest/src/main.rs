//! `rune-tdigest` command-line tool: streaming quantile/percentile estimator (t-digest-style) for large or unbounded series.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_tdigest::TDigest;
use std::process::ExitCode;

/// Estimate a quantile from a comma-separated list of values.
#[derive(Parser)]
#[command(name = "rune-tdigest")]
struct Args {
    /// Comma-separated numeric values.
    #[arg(long)]
    values: String,
    /// Quantile to estimate, in 0.0..=1.0.
    #[arg(long)]
    quantile: f64,
    /// Compression (target centroid count).
    #[arg(long, default_value_t = 100.0)]
    compression: f64,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let mut digest = TDigest::new(args.compression);
    for token in args.values.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        match token.parse::<f64>() {
            Ok(v) => digest.add(v),
            Err(err) => {
                eprintln!("rune-tdigest: could not parse '{token}': {err}");
                return ExitCode::FAILURE;
            }
        }
    }

    if digest.count() == 0 {
        eprintln!("rune-tdigest: no values provided");
        return ExitCode::FAILURE;
    }

    println!("{}", digest.quantile(args.quantile));
    ExitCode::SUCCESS
}
