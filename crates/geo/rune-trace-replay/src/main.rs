//! `rune-trace-replay` command-line tool: replay a recorded position trace at a configurable speed multiplier through any sink.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_trace_replay::{TracePoint, TraceReplay};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::process::ExitCode;

/// Replay a CSV trace of `ts_ms,lat,lon` rows at a configurable speed multiplier.
#[derive(Parser)]
#[command(name = "rune-trace-replay")]
struct Args {
    /// CSV file to read, or `-` for stdin. No header row.
    path: String,
    /// Speed multiplier (1.0 = real time, 10.0 = ten times faster).
    #[arg(long, default_value_t = 1.0)]
    speed: f64,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let reader: Box<dyn BufRead> = if args.path == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        match File::open(&args.path) {
            Ok(file) => Box::new(BufReader::new(file)),
            Err(err) => {
                eprintln!("rune-trace-replay: {}: {err}", args.path);
                return ExitCode::FAILURE;
            }
        }
    };

    let mut points = Vec::new();
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("rune-trace-replay: read error: {err}");
                return ExitCode::FAILURE;
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() != 3 {
            eprintln!("rune-trace-replay: skipping malformed row: {line}");
            continue;
        }
        match (
            fields[0].trim().parse::<i64>(),
            fields[1].trim().parse::<f64>(),
            fields[2].trim().parse::<f64>(),
        ) {
            (Ok(ts_ms), Ok(lat), Ok(lon)) => points.push(TracePoint { ts_ms, lat, lon }),
            _ => eprintln!("rune-trace-replay: skipping malformed row: {line}"),
        }
    }

    for point in TraceReplay::new(points.into_iter(), args.speed) {
        println!("{},{},{}", point.ts_ms, point.lat, point.lon);
    }

    ExitCode::SUCCESS
}
