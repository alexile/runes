//! `rune-simplify` command-line tool: douglas-Peucker line simplification for coordinate paths.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_simplify::simplify;
use std::process::ExitCode;

/// Simplify a JSON array of `[x, y]` coordinate pairs using Douglas-Peucker.
#[derive(Parser)]
#[command(name = "rune-simplify")]
struct Args {
    /// Path to a JSON file containing an array of `[x, y]` points.
    path: String,

    /// Maximum perpendicular distance tolerance.
    #[arg(long, default_value_t = 1.0)]
    epsilon: f64,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let raw = match std::fs::read_to_string(&args.path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("rune-simplify: {err}");
            return ExitCode::FAILURE;
        }
    };

    let points: Vec<(f64, f64)> = match serde_json::from_str(&raw) {
        Ok(points) => points,
        Err(err) => {
            eprintln!("rune-simplify: invalid input: {err}");
            return ExitCode::FAILURE;
        }
    };

    let simplified = simplify(&points, args.epsilon);
    match serde_json::to_string(&simplified) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("rune-simplify: {err}");
            ExitCode::FAILURE
        }
    }
}
