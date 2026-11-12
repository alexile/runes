//! `rune-lowpass` command-line tool: low-pass/high-pass digital filter for noisy scalar signals.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_lowpass::{HighPassFilter, LowPassFilter};

/// Apply a single-pole low-pass (default) or high-pass filter to a series of values.
#[derive(Parser)]
#[command(name = "rune-lowpass")]
struct Args {
    /// Smoothing factor in (0.0, 1.0].
    #[arg(long, default_value_t = 0.2)]
    alpha: f64,
    /// Apply a high-pass filter instead of low-pass.
    #[arg(long)]
    high_pass: bool,
    /// Input values, in order.
    values: Vec<f64>,
}

fn main() {
    let args = Args::parse();

    let output: Vec<f64> = if args.high_pass {
        let mut filter = HighPassFilter::new(args.alpha);
        args.values.iter().map(|&x| filter.apply(x)).collect()
    } else {
        let mut filter = LowPassFilter::new(args.alpha);
        args.values.iter().map(|&x| filter.apply(x)).collect()
    };

    let rendered: Vec<String> = output.iter().map(|v| format!("{v:.4}")).collect();
    println!("{}", rendered.join(" "));
}
