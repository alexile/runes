//! `rune-bin` command-line tool: fixed and adaptive histogram binning for numeric distributions.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_bin::{adaptive_bins, fixed_bins};
use std::fs;
use std::process::ExitCode;

/// Build a histogram from a file of newline-separated numbers.
#[derive(Parser)]
#[command(name = "rune-bin")]
struct Args {
    /// File with one numeric value per line.
    path: String,
    /// Number of bins.
    #[arg(long, default_value_t = 10)]
    bins: usize,
    /// Use equal-frequency (quantile) binning instead of equal-width.
    #[arg(long)]
    adaptive: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let contents = match fs::read_to_string(&args.path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("rune-bin: {}: {err}", args.path);
            return ExitCode::FAILURE;
        }
    };

    let data: Result<Vec<f64>, _> = contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::parse::<f64>)
        .collect();

    let data = match data {
        Ok(d) if !d.is_empty() => d,
        Ok(_) => {
            eprintln!("rune-bin: no data points found in {}", args.path);
            return ExitCode::FAILURE;
        }
        Err(err) => {
            eprintln!("rune-bin: could not parse a value: {err}");
            return ExitCode::FAILURE;
        }
    };

    let hist = if args.adaptive {
        adaptive_bins(&data, args.bins)
    } else {
        fixed_bins(&data, args.bins)
    };

    for i in 0..hist.counts.len() {
        println!(
            "[{:.4}, {:.4}): {}",
            hist.bin_edges[i],
            hist.bin_edges[i + 1],
            hist.counts[i]
        );
    }

    ExitCode::SUCCESS
}
