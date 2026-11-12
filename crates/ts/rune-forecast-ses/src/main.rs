//! `rune-forecast-ses` command-line tool: simple and double exponential smoothing forecaster.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_forecast_ses::{DoubleExpSmoothing, SimpleExpSmoothing};

/// Forecast a numeric series with simple or double exponential smoothing.
#[derive(Parser)]
#[command(name = "rune-forecast-ses")]
struct Args {
    /// Level smoothing factor, in (0.0, 1.0].
    #[arg(long, default_value_t = 0.3)]
    alpha: f64,
    /// Trend smoothing factor. If set, uses double exponential smoothing (Holt's method).
    #[arg(long)]
    beta: Option<f64>,
    /// Number of future steps to forecast.
    #[arg(long, default_value_t = 5)]
    steps: usize,
    /// Observed values, in order.
    values: Vec<f64>,
}

fn main() {
    let args = Args::parse();

    if args.values.is_empty() {
        eprintln!("rune-forecast-ses: at least one value is required");
        std::process::exit(1);
    }

    let forecast = if let Some(beta) = args.beta {
        let mut des = DoubleExpSmoothing::new(args.alpha, beta);
        for &x in &args.values {
            des.update(x);
        }
        des.forecast(args.steps)
    } else {
        let mut ses = SimpleExpSmoothing::new(args.alpha);
        for &x in &args.values {
            ses.update(x);
        }
        ses.forecast(args.steps)
    };

    let rendered: Vec<String> = forecast.iter().map(|v| format!("{v:.4}")).collect();
    println!("{}", rendered.join(" "));
}
