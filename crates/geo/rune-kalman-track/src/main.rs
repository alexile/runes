//! `rune-kalman-track` command-line tool: kalman filter for smoothing noisy position/velocity readings.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_kalman_track::KalmanTrack;
use std::process::ExitCode;

/// Smooth a sequence of noisy `x,y` position measurements with a constant-velocity
/// Kalman filter, printing the filtered position after each measurement.
#[derive(Parser)]
#[command(name = "rune-kalman-track")]
struct Args {
    /// Process noise: how much uncertainty grows per second between measurements.
    #[arg(long, default_value_t = 0.01)]
    process_noise: f64,
    /// Measurement noise: how much a single measurement is trusted.
    #[arg(long, default_value_t = 1.0)]
    measurement_noise: f64,
    /// Seconds elapsed between each measurement.
    #[arg(long, default_value_t = 1.0)]
    dt: f64,
    /// Measurements as `x,y` pairs, e.g. "0.0,0.0" "1.0,0.1".
    measurements: Vec<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    if args.measurements.is_empty() {
        eprintln!("rune-kalman-track: at least one x,y measurement is required");
        return ExitCode::FAILURE;
    }

    let first = match parse_point(&args.measurements[0]) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("rune-kalman-track: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut track = KalmanTrack::new(first.0, first.1, args.process_noise, args.measurement_noise);
    track.update(first.0, first.1);
    print_state(&track);

    for raw in &args.measurements[1..] {
        let (x, y) = match parse_point(raw) {
            Ok(p) => p,
            Err(err) => {
                eprintln!("rune-kalman-track: {err}");
                return ExitCode::FAILURE;
            }
        };
        track.predict(args.dt);
        track.update(x, y);
        print_state(&track);
    }

    ExitCode::SUCCESS
}

fn parse_point(raw: &str) -> Result<(f64, f64), String> {
    let (x, y) = raw
        .split_once(',')
        .ok_or_else(|| format!("invalid point '{raw}', expected x,y"))?;
    let x: f64 = x
        .trim()
        .parse()
        .map_err(|_| format!("invalid x in '{raw}'"))?;
    let y: f64 = y
        .trim()
        .parse()
        .map_err(|_| format!("invalid y in '{raw}'"))?;
    Ok((x, y))
}

fn print_state(track: &KalmanTrack) {
    let (x, y) = track.position();
    let (vx, vy) = track.velocity();
    let line = serde_json::json!({ "x": x, "y": y, "vx": vx, "vy": vy });
    println!("{line}");
}
