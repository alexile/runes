//! `rune-season-decomp` command-line tool: simple additive/multiplicative seasonal decomposition.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_season_decomp::{DecompMode, decompose};
use std::process::ExitCode;

/// Decompose a numeric series into trend, seasonal, and residual components.
#[derive(Parser)]
#[command(name = "rune-season-decomp")]
struct Args {
    /// Comma-separated numeric series, e.g. "10,20,10,20".
    #[arg(long)]
    series: String,
    /// Length of one seasonal cycle, in samples.
    #[arg(long)]
    period: usize,
    /// Decomposition mode: "additive" or "multiplicative".
    #[arg(long, default_value = "additive")]
    mode: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let series: Result<Vec<f64>, _> = args
        .series
        .split(',')
        .map(|v| v.trim().parse::<f64>())
        .collect();
    let series = match series {
        Ok(s) => s,
        Err(err) => {
            eprintln!("rune-season-decomp: invalid series: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mode = match args.mode.as_str() {
        "additive" => DecompMode::Additive,
        "multiplicative" => DecompMode::Multiplicative,
        other => {
            eprintln!(
                "rune-season-decomp: unknown mode '{other}', expected additive or multiplicative"
            );
            return ExitCode::FAILURE;
        }
    };

    let result = decompose(&series, args.period, mode);
    let line = serde_json::json!({
        "trend": result.trend,
        "seasonal": result.seasonal,
        "residual": result.residual,
    });
    println!("{line}");
    ExitCode::SUCCESS
}
