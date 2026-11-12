//! `rune-kalman-1d` command-line tool: 1D Kalman filter for smoothing a single noisy scalar signal.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_kalman_1d::Kalman1D;

/// Smooth a series of noisy scalar measurements with a 1D Kalman filter.
#[derive(Parser)]
#[command(name = "rune-kalman-1d")]
struct Args {
    /// Expected per-step drift of the true value.
    #[arg(long, default_value_t = 0.01)]
    process_variance: f64,
    /// Expected measurement noise variance.
    #[arg(long, default_value_t = 1.0)]
    measurement_variance: f64,
    /// Initial state estimate.
    #[arg(long, default_value_t = 0.0)]
    initial_estimate: f64,
    /// Measured values, in order.
    values: Vec<f64>,
}

fn main() {
    let args = Args::parse();

    let mut kalman = Kalman1D::new(
        args.process_variance,
        args.measurement_variance,
        args.initial_estimate,
        1.0,
    );

    let output: Vec<String> = args
        .values
        .iter()
        .map(|&x| format!("{:.4}", kalman.update(x)))
        .collect();

    println!("{}", output.join(" "));
}
