//! `rune-watermark` command-line tool: late-arrival/watermark tracking for out-of-order event streams.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_watermark::{Lateness, WatermarkTracker};
use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;

/// Classify a stream of millisecond timestamps (one per line) as on-time or late
/// against a watermark with the given allowed lateness.
#[derive(Parser)]
#[command(name = "rune-watermark")]
struct Args {
    /// File of newline-separated timestamps (ms), or `-` for stdin.
    path: String,

    /// Allowed lateness in milliseconds.
    #[arg(long, default_value_t = 1_000)]
    allowed_lateness: i64,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let content = if args.path == "-" {
        let mut buf = String::new();
        if let Err(err) = io::stdin().read_to_string(&mut buf) {
            eprintln!("rune-watermark: stdin: {err}");
            return ExitCode::FAILURE;
        }
        buf
    } else {
        match fs::read_to_string(&args.path) {
            Ok(content) => content,
            Err(err) => {
                eprintln!("rune-watermark: {}: {err}", args.path);
                return ExitCode::FAILURE;
            }
        }
    };

    let mut tracker = WatermarkTracker::new(args.allowed_lateness);
    let mut late_count = 0usize;
    let mut total = 0usize;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let ts: i64 = match line.parse() {
            Ok(ts) => ts,
            Err(err) => {
                eprintln!("rune-watermark: bad timestamp '{line}': {err}");
                return ExitCode::FAILURE;
            }
        };

        total += 1;
        match tracker.observe(ts) {
            Lateness::OnTime => println!("{ts}\ton-time"),
            Lateness::Late { by_ms } => {
                println!("{ts}\tlate\t{by_ms}ms");
                late_count += 1;
            }
        }
    }

    eprintln!("{late_count}/{total} events late");
    ExitCode::SUCCESS
}
