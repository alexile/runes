//! `rune-polyline` command-line tool: google polyline algorithm encode/decode.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_polyline::{encode, try_decode};
use std::process::ExitCode;

/// Encode or decode Google polylines.
#[derive(Parser)]
#[command(name = "rune-polyline")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encode a series of `lat,lon` points into a polyline string.
    Encode {
        /// Points as `lat,lon`, e.g. `38.5,-120.2`.
        points: Vec<String>,
    },
    /// Decode a polyline string into `lat,lon` points.
    Decode {
        /// The encoded polyline string.
        polyline: String,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();

    match args.command {
        Command::Encode { points } => {
            let mut parsed = Vec::with_capacity(points.len());
            for p in &points {
                let Some((lat, lon)) = p.split_once(',') else {
                    eprintln!("rune-polyline: invalid point: {p}");
                    return ExitCode::FAILURE;
                };
                if let (Ok(lat), Ok(lon)) = (lat.trim().parse::<f64>(), lon.trim().parse::<f64>()) {
                    parsed.push((lat, lon));
                } else {
                    eprintln!("rune-polyline: invalid point: {p}");
                    return ExitCode::FAILURE;
                }
            }
            println!("{}", encode(&parsed));
        }
        Command::Decode { polyline } => match try_decode(&polyline) {
            Ok(points) => {
                for (lat, lon) in points {
                    println!("{lat},{lon}");
                }
            }
            Err(err) => {
                eprintln!("rune-polyline: {err}");
                return ExitCode::FAILURE;
            }
        },
    }

    ExitCode::SUCCESS
}
