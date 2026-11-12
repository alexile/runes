//! `rune-hdbscan` command-line tool: hDBSCAN clustering — hierarchical density-based clustering with automatic noise detection.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_hdbscan::{Hdbscan, Metric};

#[derive(Parser)]
#[command(
    name = "rune-hdbscan",
    about = "HDBSCAN clustering of numeric tabular data"
)]
struct Cli {
    /// Input file with one point per line, space or comma separated.
    /// Use `-` to read from stdin.
    file: PathBuf,

    /// Minimum number of points to form a cluster.
    #[arg(long, default_value_t = 5)]
    min_cluster_size: usize,

    /// Core distance neighbourhood size (defaults to min-cluster-size).
    #[arg(long)]
    min_samples: Option<usize>,

    /// Distance metric: euclidean, manhattan, cosine.
    #[arg(long, default_value = "euclidean")]
    metric: String,

    /// Print membership probabilities alongside labels.
    #[arg(long)]
    probs: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let metric = match cli.metric.to_lowercase().as_str() {
        "euclidean" => Metric::Euclidean,
        "manhattan" => Metric::Manhattan,
        "cosine" => Metric::Cosine,
        other => {
            eprintln!("error: unknown metric '{other}' — use euclidean, manhattan, or cosine");
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

    let mut hdb = Hdbscan::new(cli.min_cluster_size).metric(metric);
    if let Some(ms) = cli.min_samples {
        hdb = hdb.min_samples(ms);
    }

    let result = hdb.fit(&points);

    for (&label, &prob) in result.labels.iter().zip(&result.probabilities) {
        if cli.probs {
            println!("{label}\t{prob:.6}");
        } else {
            println!("{label}");
        }
    }

    eprintln!(
        "# {} points → {} cluster(s), {} noise",
        points.len(),
        result.num_clusters,
        result.labels.iter().filter(|&&l| l < 0).count(),
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
