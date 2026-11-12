//! `rune-lttb` command-line tool: largest-Triangle-Three-Buckets downsampling for chart-ready series.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_lttb::{Point, downsample};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::process::ExitCode;

/// Downsample a CSV series of "x,y" points to a target point count using LTTB.
#[derive(Parser)]
#[command(name = "rune-lttb")]
struct Args {
    /// Target number of output points.
    threshold: usize,
    /// CSV file of "x,y" lines, or `-` for stdin.
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
                eprintln!("rune-lttb: {}: {err}", args.path);
                return ExitCode::FAILURE;
            }
        }
    };

    let mut points = Vec::new();
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("rune-lttb: read error: {err}");
                return ExitCode::FAILURE;
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((x_str, y_str)) = line.split_once(',') else {
            eprintln!("rune-lttb: malformed line: {line}");
            return ExitCode::FAILURE;
        };
        let (Ok(x), Ok(y)) = (x_str.trim().parse::<f64>(), y_str.trim().parse::<f64>()) else {
            eprintln!("rune-lttb: malformed line: {line}");
            return ExitCode::FAILURE;
        };
        points.push(Point { x, y });
    }

    for point in downsample(&points, args.threshold) {
        println!("{},{}", point.x, point.y);
    }

    ExitCode::SUCCESS
}
