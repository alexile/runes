//! `rune-geofence` command-line tool: point-in-polygon / point-in-circle containment, plus enter/exit event detection over a position stream.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_geofence::point_in_circle;

/// Check point-in-circle or point-in-polygon containment.
#[derive(Parser)]
#[command(name = "rune-geofence")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check whether a point falls within a circular fence.
    Circle {
        center_lat: f64,
        center_lon: f64,
        radius_m: f64,
        lat: f64,
        lon: f64,
    },
}

fn main() {
    let args = Args::parse();
    match args.command {
        Command::Circle {
            center_lat,
            center_lon,
            radius_m,
            lat,
            lon,
        } => {
            let inside = point_in_circle(lat, lon, center_lat, center_lon, radius_m);
            println!("{inside}");
        }
    }
}
