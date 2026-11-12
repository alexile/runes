//! `rune-resample` command-line tool: resample an irregular timestamped series to a fixed interval.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, ValueEnum};
use rune_resample::{FillMethod, resample_with};
use std::process::ExitCode;

#[derive(Clone, Copy, ValueEnum)]
enum Method {
    Linear,
    Previous,
    Next,
}

/// Resample a "ts,value" series onto a fixed-interval grid.
#[derive(Parser)]
#[command(name = "rune-resample")]
struct Args {
    /// Semicolon-separated "`ts_ms,value`" pairs, e.g. "0,0;1000,10;3000,30".
    #[arg(long)]
    points: String,
    /// Grid spacing in milliseconds.
    #[arg(long)]
    interval_ms: i64,
    /// Fill method.
    #[arg(long, value_enum, default_value_t = Method::Linear)]
    method: Method,
}

fn parse_points(spec: &str) -> Option<Vec<(i64, f64)>> {
    spec.split(';')
        .filter(|s| !s.trim().is_empty())
        .map(|pair| {
            let (ts, v) = pair.split_once(',')?;
            Some((ts.trim().parse().ok()?, v.trim().parse().ok()?))
        })
        .collect()
}

fn main() -> ExitCode {
    let args = Args::parse();

    let Some(points) = parse_points(&args.points) else {
        eprintln!("rune-resample: could not parse --points (expected \"ts,value;ts,value;...\")");
        return ExitCode::FAILURE;
    };

    let method = match args.method {
        Method::Linear => FillMethod::Linear,
        Method::Previous => FillMethod::PreviousValue,
        Method::Next => FillMethod::NextValue,
    };

    for (ts, value) in resample_with(&points, args.interval_ms, method) {
        println!("{ts},{value}");
    }

    ExitCode::SUCCESS
}
