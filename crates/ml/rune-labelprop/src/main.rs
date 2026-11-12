//! `rune-labelprop` command-line tool: label propagation — semi-supervised node classification via iterative neighbourhood smoothing.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_labelprop::LabelProp;

#[derive(Parser)]
#[command(
    name = "rune-labelprop",
    about = "Semi-supervised node classification via label propagation"
)]
struct Cli {
    /// Edge list file: one edge per line as `u v weight` or `u v` (weight defaults to 1.0).
    /// Use `-` to read from stdin.
    #[arg(long)]
    edges: PathBuf,

    /// Labels file: one integer label per line. Use -1 for unknown nodes.
    /// Line N sets the label for node N (0-indexed).
    #[arg(long)]
    labels: PathBuf,

    /// Maximum propagation iterations.
    #[arg(long, default_value_t = 100)]
    max_iter: usize,

    /// Convergence tolerance — stops when max label change falls below this value.
    #[arg(long, default_value_t = 1e-4)]
    tol: f64,
}

#[allow(
    clippy::cast_sign_loss,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
fn main() -> ExitCode {
    let cli = Cli::parse();

    let seed_labels = match read_labels(&cli.labels) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error reading labels: {e}");
            return ExitCode::FAILURE;
        }
    };

    let n_nodes = seed_labels.len();
    if n_nodes == 0 {
        eprintln!("error: labels file is empty");
        return ExitCode::FAILURE;
    }

    let edges = match read_edges(&cli.edges) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error reading edges: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = LabelProp::new()
        .max_iter(cli.max_iter)
        .tol(cli.tol)
        .propagate(n_nodes, &edges, &seed_labels);

    for label in &result.labels {
        println!("{label}");
    }

    let labelled_count = result.labels.iter().filter(|&&l| l >= 0).count();
    let unknown_count = result.labels.iter().filter(|&&l| l < 0).count();
    let n_classes = result
        .labels
        .iter()
        .filter(|&&l| l >= 0)
        .map(|&l| l as usize)
        .max()
        .map_or(0, |m| m + 1);

    eprintln!(
        "# {n_nodes} nodes → {n_classes} classes labelled {labelled_count}, unknown {unknown_count} (iters={}, converged={})",
        result.iterations, result.converged,
    );

    ExitCode::SUCCESS
}

fn read_labels(path: &PathBuf) -> io::Result<Vec<i32>> {
    let reader = open_reader(path)?;
    let mut labels = Vec::new();
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match trimmed.parse::<i32>() {
            Ok(label) => labels.push(label),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "line {}: expected an integer label, got '{trimmed}'",
                        line_num + 1
                    ),
                ));
            }
        }
    }
    Ok(labels)
}

fn read_edges(path: &PathBuf) -> io::Result<Vec<(usize, usize, f64)>> {
    let reader = open_reader(path)?;
    let mut edges = Vec::new();
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed
            .split(|c: char| c.is_ascii_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
            .collect();

        let parse_error = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "line {}: expected `u v [weight]`, got '{trimmed}'",
                    line_num + 1
                ),
            )
        };

        if parts.len() < 2 {
            return Err(parse_error());
        }
        let u: usize = parts[0].parse().map_err(|_| parse_error())?;
        let v: usize = parts[1].parse().map_err(|_| parse_error())?;
        let weight: f64 = if parts.len() >= 3 {
            parts[2].parse().map_err(|_| parse_error())?
        } else {
            1.0
        };
        edges.push((u, v, weight));
    }
    Ok(edges)
}

fn open_reader(path: &PathBuf) -> io::Result<Box<dyn BufRead>> {
    if path.to_str() == Some("-") {
        Ok(Box::new(io::BufReader::new(io::stdin())))
    } else {
        Ok(Box::new(io::BufReader::new(std::fs::File::open(path)?)))
    }
}
