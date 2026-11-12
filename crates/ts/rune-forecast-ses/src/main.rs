//! `rune-forecast-ses` command-line tool: exponential smoothing forecasts.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, ValueEnum};
use rune_forecast_ses::{Auto, DoubleExpSmoothing, Fit, Model, Seasonal, SimpleExpSmoothing};

/// Forecast a numeric series with exponential smoothing.
///
/// Without `--model`, smooths with the fixed `--alpha` (and `--beta`). With
/// `--model`, fits the parameters to the data.
#[derive(Parser)]
#[command(name = "rune-forecast-ses")]
struct Args {
    /// Level smoothing factor, in (0.0, 1.0]. Ignored with `--model`.
    #[arg(long, default_value_t = 0.3)]
    alpha: f64,
    /// Trend smoothing factor. If set, uses double exponential smoothing (Holt's method).
    #[arg(long)]
    beta: Option<f64>,
    /// Fit a model instead of using fixed factors.
    #[arg(long, value_enum)]
    model: Option<Kind>,
    /// Seasonal period, for `hw-add`, `hw-mul` and `auto`.
    #[arg(long)]
    period: Option<usize>,
    /// Print prediction intervals at this level (for example 0.95). Needs `--model`.
    #[arg(long)]
    level: Option<f64>,
    /// Number of future steps to forecast.
    #[arg(long, default_value_t = 5)]
    steps: usize,
    /// Observed values, in order.
    values: Vec<f64>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Ses,
    Holt,
    Damped,
    HwAdd,
    HwMul,
    Auto,
}

fn fail(msg: &str) -> ! {
    eprintln!("rune-forecast-ses: {msg}");
    std::process::exit(1);
}

fn fit(kind: Kind, period: Option<usize>, values: &[f64]) -> Result<Fit, rune_forecast_ses::Error> {
    let seasonal = |s| {
        period.map_or_else(
            || fail("--period is required for Holt-Winters"),
            |m| Model::holt_winters(s, m),
        )
    };
    match kind {
        Kind::Ses => Model::ses().fit(values),
        Kind::Holt => Model::holt().fit(values),
        Kind::Damped => Model::damped_holt().fit(values),
        Kind::HwAdd => seasonal(Seasonal::Additive).fit(values),
        Kind::HwMul => seasonal(Seasonal::Multiplicative).fit(values),
        Kind::Auto => period
            .map_or_else(Auto::new, |m| Auto::new().period(m))
            .fit(values),
    }
}

fn main() {
    let args = Args::parse();

    if args.values.is_empty() {
        fail("at least one value is required");
    }

    let Some(kind) = args.model else {
        if args.level.is_some() {
            fail("--level needs --model");
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
        return;
    };

    let fitted = fit(kind, args.period, &args.values).unwrap_or_else(|e| fail(&e.to_string()));
    eprintln!(
        "{} alpha={:.4} beta={:?} gamma={:?} phi={:?} AICc={:.3}",
        fitted.model(),
        fitted.alpha(),
        fitted.beta(),
        fitted.gamma(),
        fitted.phi(),
        fitted.aicc()
    );
    if let Some(level) = args.level {
        let intervals = fitted
            .forecast_intervals(args.steps, level)
            .unwrap_or_else(|e| fail(&e.to_string()));
        for iv in intervals {
            println!("{:.4} {:.4} {:.4}", iv.mean, iv.lower, iv.upper);
        }
    } else {
        let rendered: Vec<String> = fitted
            .forecast(args.steps)
            .iter()
            .map(|v| format!("{v:.4}"))
            .collect();
        println!("{}", rendered.join(" "));
    }
}
