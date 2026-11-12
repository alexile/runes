//! `rune-interpolate` command-line tool: linear and spline interpolation for gap-filling irregular series.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, ValueEnum};
use std::process::ExitCode;

#[derive(Clone, Copy, ValueEnum)]
enum Method {
    Linear,
    Cubic,
}

/// Interpolate a value at a given x from a set of "x,y" points.
#[derive(Parser)]
#[command(name = "rune-interpolate")]
struct Args {
    /// Semicolon-separated "x,y" pairs, e.g. "0,0;5,25;10,100".
    #[arg(long)]
    points: String,
    /// The x value to interpolate at.
    #[arg(long)]
    at: f64,
    /// Interpolation method.
    #[arg(long, value_enum, default_value_t = Method::Linear)]
    method: Method,
}

fn parse_points(spec: &str) -> Option<Vec<(f64, f64)>> {
    spec.split(';')
        .filter(|s| !s.trim().is_empty())
        .map(|pair| {
            let (x, y) = pair.split_once(',')?;
            Some((x.trim().parse().ok()?, y.trim().parse().ok()?))
        })
        .collect()
}

fn main() -> ExitCode {
    let args = Args::parse();

    let Some(points) = parse_points(&args.points) else {
        eprintln!("rune-interpolate: could not parse --points (expected \"x,y;x,y;...\")");
        return ExitCode::FAILURE;
    };

    let result = match args.method {
        Method::Linear => rune_interpolate::linear(&points, args.at),
        Method::Cubic => rune_interpolate::cubic_spline(&points, args.at),
    };

    if let Some(value) = result {
        println!("{value}");
        ExitCode::SUCCESS
    } else {
        eprintln!("rune-interpolate: {} is out of range", args.at);
        ExitCode::FAILURE
    }
}
