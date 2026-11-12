//! `rune-rate-rule` command-line tool: composable rule trait plus threshold, rate-of-change, and missing-heartbeat rule implementations.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_rate_rule::{Rule, ThresholdRule};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::process::ExitCode;

/// Evaluate a stream of numeric readings (one per line) against a min/max threshold rule.
#[derive(Parser)]
#[command(name = "rune-rate-rule")]
struct Args {
    /// Inclusive lower bound.
    #[arg(long)]
    min: Option<f64>,
    /// Inclusive upper bound.
    #[arg(long)]
    max: Option<f64>,
    /// File of newline-separated numbers, or `-` for stdin.
    path: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let reader: Box<dyn BufRead> = if args.path == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        match File::open(&args.path) {
            Ok(file) => Box::new(BufReader::new(file)),
            Err(err) => {
                eprintln!("rune-rate-rule: {}: {err}", args.path);
                return ExitCode::FAILURE;
            }
        }
    };

    let mut rule = ThresholdRule::new("cli");
    if let Some(min) = args.min {
        rule = rule.min(min);
    }
    if let Some(max) = args.max {
        rule = rule.max(max);
    }

    let mut violations = 0usize;
    for (line_no, line) in reader.lines().enumerate() {
        let line_no = line_no + 1;
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("line {line_no}: read error: {err}");
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: f64 = match trimmed.parse() {
            Ok(value) => value,
            Err(err) => {
                eprintln!("line {line_no}: {err}");
                continue;
            }
        };
        if let Some(violation) = rule.evaluate(&value) {
            println!("line {line_no}: {}", violation.message);
            violations += 1;
        }
    }

    println!("{violations} violation(s)");

    if violations > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
