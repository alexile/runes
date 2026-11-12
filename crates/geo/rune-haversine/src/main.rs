//! `rune-haversine` command-line tool: great-circle distance and bearing between coordinates.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_haversine::{bearing_deg, distance_m};

/// Compute great-circle distance and initial bearing between two coordinates.
#[derive(Parser)]
#[command(name = "rune-haversine")]
struct Args {
    lat1: f64,
    lon1: f64,
    lat2: f64,
    lon2: f64,
}

fn main() {
    let args = Args::parse();
    let d = distance_m(args.lat1, args.lon1, args.lat2, args.lon2);
    let b = bearing_deg(args.lat1, args.lon1, args.lat2, args.lon2);
    println!("distance_m={d:.2} bearing_deg={b:.2}");
}
