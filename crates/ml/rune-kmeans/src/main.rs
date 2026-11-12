//! `rune-kmeans` command-line tool: k-Means++ clustering — partition points into k clusters with smart initialisation.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_kmeans::{KMeans, Metric};

#[derive(Parser)]
#[command(
    name = "rune-kmeans",
    about = "K-Means++ clustering for numeric tabular data"
)]
struct Cli {
    /// Input file: one point per line, space or comma separated numbers.
    /// Use `-` to read from stdin.
    file: PathBuf,

    /// Number of clusters.
    #[arg(long, short = 'k')]
    k: usize,

    /// Maximum iterations per restart.
    #[arg(long, default_value_t = 300)]
    max_iter: usize,

    /// Convergence tolerance: stop when max centroid movement drops below this value.
    #[arg(long, default_value_t = 1e-4)]
    tol: f64,

    /// Number of independent restarts; the run with lowest inertia is kept.
    #[arg(long, default_value_t = 10)]
    n_init: usize,

    /// Distance metric: euclidean or manhattan.
    #[arg(long, default_value = "euclidean")]
    metric: String,

    /// PRNG seed for reproducible output.
    #[arg(long, default_value_t = 42)]
    seed: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let metric = match cli.metric.to_lowercase().as_str() {
        "euclidean" => Metric::Euclidean,
        "manhattan" => Metric::Manhattan,
        other => {
            eprintln!("error: unknown metric '{other}' — use euclidean or manhattan");
            return ExitCode::FAILURE;
        }
    };

    let points = match read_points(&cli.file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if points.is_empty() {
        eprintln!("error: no data points found");
        return ExitCode::FAILURE;
    }

    if cli.k == 0 {
        eprintln!("error: k must be at least 1");
        return ExitCode::FAILURE;
    }

    if cli.k > points.len() {
        eprintln!(
            "error: k ({}) must not exceed the number of points ({})",
            cli.k,
            points.len()
        );
        return ExitCode::FAILURE;
    }

    let result = KMeans::new(cli.k)
        .max_iter(cli.max_iter)
        .tol(cli.tol)
        .n_init(cli.n_init)
        .metric(metric)
        .random_seed(cli.seed)
        .fit(&points);

    for &label in &result.labels {
        println!("{label}");
    }

    eprintln!(
        "# {} points → {} clusters, inertia={:.3}",
        points.len(),
        cli.k,
        result.inertia
    );

    ExitCode::SUCCESS
}

fn read_points(path: &PathBuf) -> io::Result<Vec<Vec<f64>>> {
    let reader: Box<dyn BufRead> = if path.to_str() == Some("-") {
        Box::new(io::BufReader::new(io::stdin()))
    } else {
        Box::new(io::BufReader::new(std::fs::File::open(path)?))
    };

    let mut points = Vec::new();
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let coords: Result<Vec<f64>, _> = trimmed
            .split(|c: char| c == ',' || c.is_ascii_whitespace())
            .filter(|s| !s.is_empty())
            .map(str::parse::<f64>)
            .collect();
        match coords {
            Ok(c) if !c.is_empty() => points.push(c),
            Ok(_) => {}
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("line {}: could not parse as numbers", line_num + 1),
                ));
            }
        }
    }
    Ok(points)
}
