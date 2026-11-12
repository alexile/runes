//! `rune-dedupe` command-line tool: idempotency/dedup filter over a keyed, windowed stream.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_dedupe::Dedupe;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::process::ExitCode;
use std::time::{Duration, Instant};

/// Filter duplicate keys (one per line) within a trailing time window.
///
/// Since input is read all at once rather than as a live stream, each line is
/// timestamped by its arrival order using a fixed step, purely to exercise the
/// windowed check deterministically.
#[derive(Parser)]
#[command(name = "rune-dedupe")]
struct Args {
    /// Dedup window in seconds.
    #[arg(long)]
    window_secs: u64,
    /// Milliseconds to advance the simulated clock between lines.
    #[arg(long, default_value_t = 0)]
    step_ms: u64,
    /// File of newline-separated keys, or `-` for stdin.
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
                eprintln!("rune-dedupe: {}: {err}", args.path);
                return ExitCode::FAILURE;
            }
        }
    };

    let mut dedupe = Dedupe::new(Duration::from_secs(args.window_secs));
    let start = Instant::now();
    let mut kept = 0usize;
    let mut dropped = 0usize;

    for (line_no, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("line {}: read error: {err}", line_no + 1);
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let at = start + Duration::from_millis(args.step_ms * line_no as u64);
        if dedupe.check(line.clone(), at) {
            println!("{line}");
            kept += 1;
        } else {
            dropped += 1;
        }
    }

    eprintln!("{kept} kept, {dropped} duplicate(s) dropped");
    ExitCode::SUCCESS
}
