//! `rune-geohash` command-line tool: geohash encode/decode.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_geohash::{decode, encode};
use std::process::ExitCode;

/// Encode/decode geohash strings.
#[derive(Parser)]
#[command(name = "rune-geohash")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encode a coordinate into a geohash string.
    Encode {
        lat: f64,
        lon: f64,
        #[arg(default_value_t = 9)]
        precision: usize,
    },
    /// Decode a geohash string into its center coordinate.
    Decode { hash: String },
}

fn main() -> ExitCode {
    let args = Args::parse();
    match args.command {
        Command::Encode {
            lat,
            lon,
            precision,
        } => {
            println!("{}", encode(lat, lon, precision));
        }
        Command::Decode { hash } => match decode(&hash) {
            Ok((lat, lon)) => println!("{lat:.6} {lon:.6}"),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        },
    }
    ExitCode::SUCCESS
}
