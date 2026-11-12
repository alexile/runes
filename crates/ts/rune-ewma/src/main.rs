//! `rune-ewma` command-line tool: exponentially weighted moving average over a numeric stream.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_ewma::Ewma;

/// Compute a running exponentially weighted moving average over a list of numbers.
#[derive(Parser)]
#[command(name = "rune-ewma")]
struct Args {
    /// Smoothing factor in (0.0, 1.0].
    alpha: f64,
    /// Input values, in order.
    values: Vec<f64>,
}

fn main() {
    let args = Args::parse();
    let mut ewma = Ewma::new(args.alpha);

    for x in args.values {
        let value = ewma.update(x);
        println!("{value:.6}");
    }
}
