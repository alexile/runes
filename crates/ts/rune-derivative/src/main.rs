//! `rune-derivative` command-line tool: rate-of-change (derivative) and cumulative (integral) calculation over a series.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_derivative::{cumulative_integral, derivative, integral};
use std::fs;
use std::process::ExitCode;

/// Compute the derivative, integral, and cumulative integral of a `ts_ms,value` CSV series.
#[derive(Parser)]
#[command(name = "rune-derivative")]
struct Args {
    /// CSV file with `ts_ms,value` rows (no header).
    path: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let contents = match fs::read_to_string(&args.path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("rune-derivative: {}: {err}", args.path);
            return ExitCode::FAILURE;
        }
    };

    let mut points = Vec::new();
    for (line_no, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((ts, value)) = line.split_once(',') else {
            eprintln!("line {}: expected `ts_ms,value`", line_no + 1);
            return ExitCode::FAILURE;
        };
        if let (Ok(ts), Ok(value)) = (ts.trim().parse::<i64>(), value.trim().parse::<f64>()) {
            points.push((ts, value));
        } else {
            eprintln!("line {}: could not parse `{line}`", line_no + 1);
            return ExitCode::FAILURE;
        }
    }

    println!("integral: {}", integral(&points));
    println!("derivative points: {}", derivative(&points).len());
    println!(
        "cumulative integral points: {}",
        cumulative_integral(&points).len()
    );

    ExitCode::SUCCESS
}
