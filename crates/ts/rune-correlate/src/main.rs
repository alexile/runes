//! `rune-correlate` command-line tool: cross-correlation and lag detection between two numeric series.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_correlate::best_lag;
use std::process::ExitCode;

/// Find the lag at which two comma-separated numeric series correlate best.
#[derive(Parser)]
#[command(name = "rune-correlate")]
struct Args {
    /// First series, comma-separated, e.g. `1,2,3,4`.
    #[arg(long)]
    a: String,
    /// Second series, comma-separated.
    #[arg(long)]
    b: String,
    /// Maximum lag (in either direction) to search.
    #[arg(long, default_value_t = 5)]
    max_lag: usize,
}

fn parse_series(s: &str) -> Result<Vec<f64>, String> {
    s.split(',')
        .map(|part| {
            part.trim()
                .parse::<f64>()
                .map_err(|_| format!("invalid number: {part}"))
        })
        .collect()
}

fn main() -> ExitCode {
    let args = Args::parse();
    let (a, b) = match (parse_series(&args.a), parse_series(&args.b)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (lag, corr) = best_lag(&a, &b, args.max_lag);
    println!("best lag: {lag} (correlation: {corr:.4})");
    ExitCode::SUCCESS
}
