//! `rune-window-agg` command-line tool: tumbling/sliding/session window aggregator over a timestamped stream.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_window_agg::{WindowAggregator, WindowKind};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::process::ExitCode;

/// Aggregate a `ts_ms,value` CSV stream into fixed-size tumbling windows.
#[derive(Parser)]
#[command(name = "rune-window-agg")]
struct Args {
    /// Window size in milliseconds.
    #[arg(long)]
    size_ms: i64,
    /// CSV file of `ts_ms,value` lines, or `-` for stdin.
    path: String,
}

fn print_window(w: rune_window_agg::WindowResult) {
    println!(
        "[{}, {}) count={} sum={} min={} max={}",
        w.start_ms, w.end_ms, w.count, w.sum, w.min, w.max
    );
}

fn main() -> ExitCode {
    let args = Args::parse();

    let reader: Box<dyn BufRead> = if args.path == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        match File::open(&args.path) {
            Ok(file) => Box::new(BufReader::new(file)),
            Err(err) => {
                eprintln!("rune-window-agg: {}: {err}", args.path);
                return ExitCode::FAILURE;
            }
        }
    };

    let mut agg = WindowAggregator::new(WindowKind::Tumbling {
        size_ms: args.size_ms,
    });
    let mut had_error = false;

    for (line_no, line) in reader.lines().enumerate() {
        let line_no = line_no + 1;
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("line {line_no}: read error: {err}");
                had_error = true;
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((ts_str, value_str)) = trimmed.split_once(',') else {
            eprintln!("line {line_no}: expected `ts_ms,value`, got {trimmed:?}");
            had_error = true;
            continue;
        };
        let (Ok(ts_ms), Ok(value)) = (
            ts_str.trim().parse::<i64>(),
            value_str.trim().parse::<f64>(),
        ) else {
            eprintln!("line {line_no}: could not parse `{trimmed}`");
            had_error = true;
            continue;
        };
        for window in agg.push(ts_ms, value) {
            print_window(window);
        }
    }

    for window in agg.flush() {
        print_window(window);
    }

    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
