//! `rune-umap` command-line tool: UMAP dimensionality reduction — project high-dimensional data into 2D or nD embeddings.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_umap::{Metric, Umap};

#[derive(Parser)]
#[command(
    name = "rune-umap",
    about = "UMAP dimensionality reduction for numeric tabular data"
)]
struct Cli {
    /// Input file: one point per line, space or comma separated numbers.
    /// Use `-` to read from stdin.
    file: PathBuf,

    /// Number of nearest neighbours for graph construction.
    #[arg(long, default_value_t = 15)]
    n_neighbors: usize,

    /// Number of output dimensions.
    #[arg(long, default_value_t = 2)]
    n_components: usize,

    /// Minimum distance between embedded points (controls clumping).
    #[arg(long, default_value_t = 0.1)]
    min_dist: f64,

    /// Scale of the embedded space.
    #[arg(long, default_value_t = 1.0)]
    spread: f64,

    /// Number of SGD epochs (default: 500 for ≤10 000 points, 200 otherwise).
    #[arg(long)]
    n_epochs: Option<usize>,

    /// Initial learning rate.
    #[arg(long, default_value_t = 1.0)]
    learning_rate: f64,

    /// Distance metric: euclidean, manhattan, cosine, correlation.
    #[arg(long, default_value = "euclidean")]
    metric: Metric,

    /// PRNG seed for reproducible output.
    #[arg(long, default_value_t = 42)]
    seed: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let points = match read_points(&cli.file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut umap = Umap::new()
        .n_neighbors(cli.n_neighbors)
        .n_components(cli.n_components)
        .min_dist(cli.min_dist)
        .spread(cli.spread)
        .learning_rate(cli.learning_rate)
        .metric(cli.metric)
        .random_seed(cli.seed);

    if let Some(n) = cli.n_epochs {
        umap = umap.n_epochs(n);
    }

    let result = match umap.try_fit(&points) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    for row in &result.embedding {
        let formatted: Vec<String> = row.iter().map(|x| format!("{x:.6}")).collect();
        println!("{}", formatted.join("\t"));
    }

    eprintln!(
        "# {} points → {}D embedding",
        points.len(),
        cli.n_components
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
