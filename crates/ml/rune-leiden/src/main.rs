//! `rune-leiden` command-line tool: Leiden or Louvain community detection on a
//! weighted edge list.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use rune_leiden::{Leiden, Louvain, Quality};

#[derive(Parser)]
#[command(
    name = "rune-leiden",
    about = "Leiden or Louvain community detection on a weighted edge list"
)]
struct Cli {
    /// Input file: one edge per line as `u v [weight]` (weight defaults to 1.0).
    /// Use `-` to read from stdin.
    file: PathBuf,

    /// Resolution parameter γ — higher values produce more, smaller communities.
    #[arg(long, default_value_t = 1.0)]
    resolution: f64,

    /// PRNG seed for deterministic output.
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Maximum number of outer (aggregation) iterations.
    #[arg(long, default_value_t = 100)]
    max_iter: usize,

    /// Algorithm to run.
    #[arg(long, value_enum, default_value_t = AlgorithmArg::Leiden)]
    algorithm: AlgorithmArg,

    /// Objective to maximise. With `cpm`, the resolution is a density threshold.
    #[arg(long, value_enum, default_value_t = QualityArg::Modularity)]
    quality: QualityArg,
}

#[derive(Clone, Copy, ValueEnum)]
enum AlgorithmArg {
    Leiden,
    Louvain,
}

#[derive(Clone, Copy, ValueEnum)]
enum QualityArg {
    Modularity,
    Cpm,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let (n_nodes, edges) = match read_edges(&cli.file) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if n_nodes == 0 {
        eprintln!("error: no edges found in input");
        return ExitCode::FAILURE;
    }

    let quality = match cli.quality {
        QualityArg::Modularity => Quality::Modularity,
        QualityArg::Cpm => Quality::Cpm,
    };
    let fitted = match cli.algorithm {
        AlgorithmArg::Leiden => Leiden::new()
            .resolution(cli.resolution)
            .max_iter(cli.max_iter)
            .random_seed(cli.seed)
            .quality(quality)
            .try_fit(n_nodes, &edges),
        AlgorithmArg::Louvain => Louvain::new()
            .resolution(cli.resolution)
            .max_levels(cli.max_iter)
            .random_seed(cli.seed)
            .quality(quality)
            .try_fit(n_nodes, &edges),
    };
    let result = match fitted {
        Ok(result) => result,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    for community in &result.communities {
        println!("{community}");
    }

    eprintln!(
        "# {} nodes → {} communities  modularity {:.6}",
        n_nodes, result.n_communities, result.modularity,
    );

    ExitCode::SUCCESS
}

type EdgeList = Vec<(usize, usize, f64)>;

fn read_edges(path: &PathBuf) -> io::Result<(usize, EdgeList)> {
    let reader: Box<dyn BufRead> = if path.to_str() == Some("-") {
        Box::new(io::BufReader::new(io::stdin()))
    } else {
        Box::new(io::BufReader::new(std::fs::File::open(path)?))
    };

    let mut edges: Vec<(usize, usize, f64)> = Vec::new();
    let mut max_node = 0usize;

    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let tokens: Vec<&str> = trimmed
            .split(|c: char| c.is_ascii_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
            .collect();

        if tokens.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "line {}: expected at least 2 fields (u v [weight])",
                    line_num + 1
                ),
            ));
        }

        let u: usize = tokens[0].parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "line {}: cannot parse node index '{}'",
                    line_num + 1,
                    tokens[0]
                ),
            )
        })?;
        let v: usize = tokens[1].parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "line {}: cannot parse node index '{}'",
                    line_num + 1,
                    tokens[1]
                ),
            )
        })?;
        let weight: f64 = if tokens.len() >= 3 {
            tokens[2].parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("line {}: cannot parse weight '{}'", line_num + 1, tokens[2]),
                )
            })?
        } else {
            1.0
        };

        max_node = max_node.max(u).max(v);
        edges.push((u, v, weight));
    }

    Ok((max_node + 1, edges))
}
