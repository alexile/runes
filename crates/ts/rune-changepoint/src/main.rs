//! `rune-changepoint` command-line tool: change-point detection over a numeric series.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, ValueEnum};
use rune_changepoint::{
    BinSeg, Bocpd, Cost, L2, NormalGammaPrior, NormalMeanVar, Pelt, Penalty, Poisson, detect,
};

/// Detect change points in a list of numbers.
///
/// The default method is CUSUM, which prints `index: direction` lines. The
/// other methods print the index where each new segment starts.
#[derive(Parser)]
#[command(name = "rune-changepoint")]
struct Args {
    /// Detection method.
    #[arg(long, value_enum, default_value_t = Method::Cusum)]
    method: Method,
    /// CUSUM: expected baseline value of the series.
    #[arg(long, default_value_t = 0.0)]
    target: f64,
    /// CUSUM: cumulative sum threshold that signals a changepoint.
    #[arg(long, default_value_t = 5.0)]
    threshold: f64,
    /// CUSUM: drift allowance subtracted from each increment.
    #[arg(long, default_value_t = 0.5)]
    drift: f64,
    /// PELT / binary segmentation: segment cost.
    #[arg(long, value_enum, default_value_t = CostKind::L2)]
    cost: CostKind,
    /// PELT / binary segmentation: `bic`, `mbic` or a number.
    #[arg(long, default_value = "bic")]
    penalty: String,
    /// PELT / binary segmentation: minimum segment length.
    #[arg(long, default_value_t = 2)]
    min_size: usize,
    /// BOCPD: expected number of observations between changes.
    #[arg(long, default_value_t = 100.0)]
    expected_run: f64,
    /// Input values, in order.
    #[arg(allow_negative_numbers = true)]
    values: Vec<f64>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Method {
    Cusum,
    Pelt,
    Binseg,
    Bocpd,
}

#[derive(Clone, Copy, ValueEnum)]
enum CostKind {
    /// Mean shift, noise variance estimated from the data.
    L2,
    /// Mean and variance change.
    Normal,
    /// Rate change in counts.
    Poisson,
}

fn fail(msg: &str) -> ! {
    eprintln!("rune-changepoint: {msg}");
    std::process::exit(1);
}

fn segment(args: &Args, penalty: Penalty, cost: &dyn Cost) -> Vec<usize> {
    let result = match args.method {
        Method::Pelt => Pelt::new()
            .penalty(penalty)
            .min_size(args.min_size)
            .detect(cost),
        _ => BinSeg::new()
            .penalty(penalty)
            .min_size(args.min_size)
            .detect(cost),
    };
    result.unwrap_or_else(|e| fail(&e.to_string()))
}

fn main() {
    let args = Args::parse();

    let cps = match args.method {
        Method::Cusum => {
            for (index, direction) in detect(&args.values, args.target, args.threshold, args.drift)
            {
                println!("{index}: {direction:?}");
            }
            return;
        }
        Method::Bocpd => Bocpd::new(args.expected_run, NormalGammaPrior::default())
            .and_then(|mut det| det.detect(&args.values))
            .unwrap_or_else(|e| fail(&e.to_string())),
        Method::Pelt | Method::Binseg => {
            let penalty = match args.penalty.as_str() {
                "bic" => Penalty::Bic,
                "mbic" => Penalty::Mbic,
                other => Penalty::Manual(
                    other
                        .parse()
                        .unwrap_or_else(|_| fail("--penalty must be bic, mbic or a number")),
                ),
            };
            let built: Result<Box<dyn Cost>, _> = match args.cost {
                CostKind::L2 => L2::with_estimated_variance(&args.values).map(|c| Box::new(c) as _),
                CostKind::Normal => NormalMeanVar::new(&args.values).map(|c| Box::new(c) as _),
                CostKind::Poisson => Poisson::new(&args.values).map(|c| Box::new(c) as _),
            };
            let cost = built.unwrap_or_else(|e| fail(&e.to_string()));
            segment(&args, penalty, cost.as_ref())
        }
    };
    for index in cps {
        println!("{index}");
    }
}
