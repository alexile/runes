//! `rune-season-decomp` command-line tool: classical, STL and MSTL seasonal decomposition.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_season_decomp::{DecompMode, Mstl, Stl, decompose};
use std::process::ExitCode;

/// Decompose a numeric series into trend, seasonal, and residual components.
#[derive(Parser)]
#[command(name = "rune-season-decomp")]
struct Args {
    /// Comma-separated numeric series, e.g. "10,20,10,20".
    #[arg(long)]
    series: String,
    /// Length of one seasonal cycle, in samples. For `--method mstl`, a
    /// comma-separated list of periods, e.g. "24,168".
    #[arg(long)]
    period: String,
    /// Decomposition method: "classical", "stl" or "mstl".
    #[arg(long, default_value = "classical")]
    method: String,
    /// Classical decomposition mode: "additive" or "multiplicative".
    #[arg(long, default_value = "additive")]
    mode: String,
    /// STL seasonal window (odd, at least 7), or "periodic".
    #[arg(long, default_value = "7")]
    seasonal_window: String,
    /// Use robust STL so outliers end up in the remainder.
    #[arg(long)]
    robust: bool,
}

fn parse_list<T: std::str::FromStr>(text: &str) -> Result<Vec<T>, T::Err> {
    text.split(',').map(|v| v.trim().parse::<T>()).collect()
}

fn run(args: &Args) -> Result<serde_json::Value, String> {
    let series: Vec<f64> =
        parse_list(&args.series).map_err(|err| format!("invalid series: {err}"))?;
    let periods: Vec<usize> =
        parse_list(&args.period).map_err(|err| format!("invalid period: {err}"))?;
    let single_period = || match periods.as_slice() {
        [p] => Ok(*p),
        _ => Err(format!("method '{}' takes exactly one period", args.method)),
    };

    match args.method.as_str() {
        "classical" => {
            let mode = match args.mode.as_str() {
                "additive" => DecompMode::Additive,
                "multiplicative" => DecompMode::Multiplicative,
                other => {
                    return Err(format!(
                        "unknown mode '{other}', expected additive or multiplicative"
                    ));
                }
            };
            let result = decompose(&series, single_period()?, mode);
            Ok(serde_json::json!({
                "trend": result.trend,
                "seasonal": result.seasonal,
                "residual": result.residual,
            }))
        }
        "stl" => {
            let period = single_period()?;
            let stl = if args.seasonal_window == "periodic" {
                Stl::periodic(period)
            } else {
                let window = args
                    .seasonal_window
                    .parse()
                    .map_err(|err| format!("invalid seasonal window: {err}"))?;
                Stl::new(period, window)
            };
            let fit = stl
                .robust(args.robust)
                .fit(&series)
                .map_err(|err| err.to_string())?;
            Ok(serde_json::json!({
                "trend": fit.trend,
                "seasonal": fit.seasonal,
                "residual": fit.remainder,
                "weights": fit.weights,
                "trend_strength": fit.trend_strength(),
                "seasonal_strength": fit.seasonal_strength(),
            }))
        }
        "mstl" => {
            let fit = Mstl::new(&periods)
                .robust(args.robust)
                .fit(&series)
                .map_err(|err| err.to_string())?;
            Ok(serde_json::json!({
                "periods": fit.periods,
                "trend": fit.trend,
                "seasonal": fit.seasonal,
                "residual": fit.remainder,
                "trend_strength": fit.trend_strength(),
                "seasonal_strength": fit.seasonal_strengths(),
            }))
        }
        other => Err(format!(
            "unknown method '{other}', expected classical, stl or mstl"
        )),
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("rune-season-decomp: {err}");
            ExitCode::FAILURE
        }
    }
}
