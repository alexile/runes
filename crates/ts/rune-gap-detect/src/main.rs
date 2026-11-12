//! `rune-gap-detect` command-line tool: detect missing/gap intervals in an expected-cadence timestamped series.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_gap_detect::detect_gaps;
use std::fs;
use std::process::ExitCode;

/// Detect gaps in a file of newline-separated millisecond timestamps.
#[derive(Parser)]
#[command(name = "rune-gap-detect")]
struct Args {
    /// File with one timestamp (ms) per line, ascending.
    path: String,
    /// Expected interval between samples, in milliseconds.
    #[arg(long)]
    interval: i64,
    /// Allowed jitter above the expected interval, in milliseconds.
    #[arg(long, default_value_t = 0)]
    tolerance: i64,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let contents = match fs::read_to_string(&args.path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("rune-gap-detect: {}: {err}", args.path);
            return ExitCode::FAILURE;
        }
    };

    let timestamps: Result<Vec<i64>, _> = contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::parse::<i64>)
        .collect();

    let timestamps = match timestamps {
        Ok(t) => t,
        Err(err) => {
            eprintln!("rune-gap-detect: could not parse a timestamp: {err}");
            return ExitCode::FAILURE;
        }
    };

    let gaps = detect_gaps(&timestamps, args.interval, args.tolerance);
    for gap in &gaps {
        println!(
            "{} -> {} ({} missing)",
            gap.start_ms, gap.end_ms, gap.missing_count
        );
    }
    println!("{} gap(s) found", gaps.len());

    ExitCode::SUCCESS
}
