//! `rune-ingest-ndjson` command-line tool: streaming NDJSON reader with a time-compression replay clock (Nx speed).

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_ingest_ndjson::NdjsonReplay;
use std::fs::File;
use std::io::{self, BufReader};
use std::process::ExitCode;

/// Replay an NDJSON event log at a chosen speed multiplier, printing each record
/// as it's emitted.
#[derive(Parser)]
#[command(name = "rune-ingest-ndjson")]
struct Args {
    /// NDJSON file to read, or `-` for stdin.
    path: String,

    /// Field name holding each record's timestamp (milliseconds).
    #[arg(long, default_value = "ts")]
    ts_field: String,

    /// Replay speed multiplier (2.0 = twice as fast as originally recorded).
    #[arg(long, default_value_t = 1.0)]
    speed: f64,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let reader: Box<dyn io::BufRead> = if args.path == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        match File::open(&args.path) {
            Ok(file) => Box::new(BufReader::new(file)),
            Err(err) => {
                eprintln!("rune-ingest-ndjson: {}: {err}", args.path);
                return ExitCode::FAILURE;
            }
        }
    };

    let replay = NdjsonReplay::new(reader, args.ts_field, args.speed);
    let mut any_error = false;

    for record in replay {
        match record {
            Ok(value) => println!("{value}"),
            Err(err) => {
                eprintln!("rune-ingest-ndjson: {err}");
                any_error = true;
            }
        }
    }

    if any_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
