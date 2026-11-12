//! `rune-schema-sniff` command-line tool: heuristic column/field-type detector for arbitrary CSV/JSON: guesses timestamp/id/value/lat-lon columns, emits a normalized preview with confidence scores.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_schema_sniff::{sniff_csv, sniff_json};
use std::fs;
use std::process::ExitCode;

/// Guess column types for a CSV or JSON-array-of-objects file.
#[derive(Parser)]
#[command(name = "rune-schema-sniff")]
struct Args {
    /// Path to a `.csv` or `.json` file.
    path: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let contents = match fs::read_to_string(&args.path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("rune-schema-sniff: {}: {err}", args.path);
            return ExitCode::FAILURE;
        }
    };

    let is_json = std::path::Path::new(&args.path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));

    let guesses = if is_json {
        let rows: Vec<serde_json::Value> = match serde_json::from_str(&contents) {
            Ok(rows) => rows,
            Err(err) => {
                eprintln!("rune-schema-sniff: {}: {err}", args.path);
                return ExitCode::FAILURE;
            }
        };
        sniff_json(&rows)
    } else {
        let mut lines = contents.lines();
        let headers: Vec<String> = lines.next().map_or_else(Vec::new, |header_line| {
            header_line
                .split(',')
                .map(|h| h.trim().to_string())
                .collect()
        });
        let rows: Vec<Vec<String>> = lines
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                line.split(',')
                    .map(|cell| cell.trim().to_string())
                    .collect()
            })
            .collect();
        sniff_csv(&headers, &rows)
    };

    for guess in &guesses {
        println!(
            "{:<20} {:<10} confidence={:.2}",
            guess.name, guess.guessed_type, guess.confidence
        );
    }

    ExitCode::SUCCESS
}
