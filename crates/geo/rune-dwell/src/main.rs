//! `rune-dwell` command-line tool: stop/dwell-time detection from a position stream.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_dwell::DwellDetector;
use std::fs;
use std::process::ExitCode;

/// Detect stop/dwell events from a CSV trace of `ts_ms,lat,lon` rows.
#[derive(Parser)]
#[command(name = "rune-dwell")]
struct Args {
    /// Radius in metres that counts as "still at the same place".
    radius_m: f64,
    /// Minimum dwell duration in milliseconds to count as a stop.
    min_dwell_ms: i64,
    /// Path to a CSV file with `ts_ms,lat,lon` rows (no header).
    path: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let contents = match fs::read_to_string(&args.path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("rune-dwell: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut detector = DwellDetector::new(args.radius_m, args.min_dwell_ms);
    let mut last_ts = 0i64;

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split(',');
        let (Some(ts), Some(lat), Some(lon)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(ts), Ok(lat), Ok(lon)) = (
            ts.trim().parse::<i64>(),
            lat.trim().parse::<f64>(),
            lon.trim().parse::<f64>(),
        ) else {
            continue;
        };
        last_ts = ts;
        if let Some(event) = detector.update(ts, lat, lon) {
            print_event(&event);
        }
    }

    if let Some(event) = detector.flush(last_ts) {
        print_event(&event);
    }

    ExitCode::SUCCESS
}

fn print_event(event: &rune_dwell::DwellEvent) {
    let line = serde_json::json!({
        "start_ms": event.start_ms,
        "end_ms": event.end_ms,
        "lat": event.lat,
        "lon": event.lon,
        "duration_ms": event.duration_ms,
    });
    println!("{line}");
}
