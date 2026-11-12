//! `rune-canonical-event` command-line tool: typed event envelope for streaming pipelines — source, timestamp, sequence, kind, payload, and metadata, with a validating builder.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_canonical_event::CanonicalEvent;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::process::ExitCode;

/// Validate a stream of canonical events (one JSON object per line) against the schema.
#[derive(Parser)]
#[command(name = "rune-canonical-event")]
struct Args {
    /// NDJSON file to read, or `-` for stdin.
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
                eprintln!("rune-canonical-event: {}: {err}", args.path);
                return ExitCode::FAILURE;
            }
        }
    };

    let mut valid = 0usize;
    let mut invalid = 0usize;

    for (line_no, line) in reader.lines().enumerate() {
        let line_no = line_no + 1;
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("line {line_no}: read error: {err}");
                invalid += 1;
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<CanonicalEvent>(&line) {
            Ok(event) => match event.validate() {
                Ok(()) => valid += 1,
                Err(err) => {
                    eprintln!("line {line_no}: {err}");
                    invalid += 1;
                }
            },
            Err(err) => {
                eprintln!("line {line_no}: parse error: {err}");
                invalid += 1;
            }
        }
    }

    println!("{valid} valid, {invalid} invalid");

    if invalid > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
