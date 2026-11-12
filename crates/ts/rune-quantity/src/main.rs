//! `rune-quantity` command-line tool: typed physical-quantity/unit system with compile-time-checked conversions (distance, speed, energy, etc.).

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_quantity::{
    Feet, Kilometers, KilometersPerHour, Meters, MetersPerSecond, Miles, MilesPerHour,
};

/// Convert between common physical-quantity units.
#[derive(Parser)]
#[command(name = "rune-quantity")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Kilometers to meters.
    KmToM { value: f64 },
    /// Miles to meters.
    MiToM { value: f64 },
    /// Feet to meters.
    FtToM { value: f64 },
    /// Meters/second to km/h.
    MpsToKmh { value: f64 },
    /// Meters/second to mph.
    MpsToMph { value: f64 },
}

fn main() {
    let args = Args::parse();

    match args.command {
        Command::KmToM { value } => {
            let m: Meters = Kilometers(value).into();
            println!("{m:?}");
        }
        Command::MiToM { value } => {
            let m: Meters = Miles(value).into();
            println!("{m:?}");
        }
        Command::FtToM { value } => {
            let m: Meters = Feet(value).into();
            println!("{m:?}");
        }
        Command::MpsToKmh { value } => {
            let kmh: KilometersPerHour = MetersPerSecond(value).into();
            println!("{kmh:?}");
        }
        Command::MpsToMph { value } => {
            let mph: MilesPerHour = MetersPerSecond(value).into();
            println!("{mph:?}");
        }
    }
}
