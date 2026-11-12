//! `rune-zscore` command-line tool: z-score and IQR-based outlier/anomaly detector.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_zscore::{iqr_outliers, zscore_outliers};

/// Detect outliers in a list of numbers using z-score and IQR methods.
#[derive(Parser)]
#[command(name = "rune-zscore")]
struct Args {
    /// Z-score threshold above which a point is flagged.
    #[arg(long, default_value_t = 3.0)]
    threshold: f64,
    /// Input values.
    values: Vec<f64>,
}

fn main() {
    let args = Args::parse();

    let z_flags = zscore_outliers(&args.values, args.threshold);
    let iqr_flags = iqr_outliers(&args.values);

    println!(
        "zscore outliers (threshold={}): {z_flags:?}",
        args.threshold
    );
    println!("iqr outliers: {iqr_flags:?}");
}
