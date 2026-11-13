//! `rune-dedupe` command-line tool: idempotency/dedup filter over a keyed, windowed stream.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_dedupe::{ApproxConfig, Dedupe};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::process::ExitCode;
use std::time::Duration;

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
    /// Remember at most this many keys, evicting the oldest first (exact mode).
    #[arg(long, conflicts_with = "fpr")]
    max_keys: Option<usize>,
    /// Use fixed-memory approximate mode with this false-positive rate.
    #[arg(long)]
    fpr: Option<f64>,
    /// Distinct keys per window to size approximate mode for.
    #[arg(long, default_value_t = 1_000_000, requires = "fpr")]
    expected_keys: usize,
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

    let mut builder = Dedupe::builder(Duration::from_secs(args.window_secs));
    if let Some(max_keys) = args.max_keys {
        builder = builder.max_keys(max_keys);
    }
    if let Some(fpr) = args.fpr {
        builder = builder.approximate(ApproxConfig::new(args.expected_keys, fpr));
    }
    let mut dedupe: Dedupe<String, u64> = match builder.build() {
        Ok(d) => d,
        Err(err) => {
            eprintln!("rune-dedupe: {err}");
            return ExitCode::FAILURE;
        }
    };

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
        let at = args.step_ms.saturating_mul(line_no as u64);
        if dedupe.check(line.clone(), at) {
            println!("{line}");
        }
    }

    let stats = dedupe.stats();
    eprintln!(
        "{} kept, {} duplicate(s) dropped",
        stats.fresh, stats.duplicates
    );
    if stats.evicted_capacity > 0 {
        eprintln!(
            "{} key(s) evicted early by --max-keys",
            stats.evicted_capacity
        );
    }
    ExitCode::SUCCESS
}
