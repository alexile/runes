//! `rune-eta` command-line tool: distance- and speed-profile-based arrival time estimator.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;

/// Estimate travel time (seconds) for a distance at a constant speed.
#[derive(Parser)]
#[command(name = "rune-eta")]
struct Args {
    /// Distance in meters.
    distance_m: f64,
    /// Speed in meters per second.
    speed_mps: f64,
}

fn main() {
    let args = Args::parse();
    if let Some(seconds) = rune_eta::eta_constant_speed(args.distance_m, args.speed_mps) {
        println!("{seconds:.2}s");
    } else {
        eprintln!("rune-eta: speed must be positive");
        std::process::exit(1);
    }
}
