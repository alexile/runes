//! `rune-node2vec` command-line tool: node2Vec — graph node embeddings via biased random walks and skip-gram.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_node2vec::Node2Vec;

#[derive(Parser)]
#[command(
    name = "rune-node2vec",
    about = "Node2Vec graph node embeddings via biased random walks and skip-gram"
)]
struct Cli {
    /// Input file: one edge per line, format `u v` (0-based node indices).
    /// Use `-` to read from stdin.
    file: PathBuf,

    /// Embedding dimensionality.
    #[arg(long, default_value_t = 128)]
    dim: usize,

    /// Number of nodes per walk.
    #[arg(long, default_value_t = 80)]
    walk_length: usize,

    /// Number of walks per node.
    #[arg(long, default_value_t = 10)]
    num_walks: usize,

    /// Context window half-width for skip-gram.
    #[arg(long, default_value_t = 10)]
    window: usize,

    /// Return parameter p (high = less backtracking).
    #[arg(long, default_value_t = 1.0)]
    p: f64,

    /// In-out parameter q (low = DFS-like exploration).
    #[arg(long, default_value_t = 1.0)]
    q: f64,

    /// Number of training epochs.
    #[arg(long, default_value_t = 1)]
    epochs: usize,

    /// Initial SGD learning rate.
    #[arg(long, default_value_t = 0.025)]
    lr: f64,

    /// Negative samples per positive pair.
    #[arg(long, default_value_t = 5)]
    neg_samples: usize,

    /// PRNG seed for reproducible output.
    #[arg(long, default_value_t = 42)]
    seed: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let (n_nodes, edges) = match read_edges(&cli.file) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if n_nodes == 0 {
        eprintln!("error: no edges found");
        return ExitCode::FAILURE;
    }

    let result = Node2Vec::new()
        .embedding_dim(cli.dim)
        .walk_length(cli.walk_length)
        .num_walks(cli.num_walks)
        .window_size(cli.window)
        .p(cli.p)
        .q(cli.q)
        .n_epochs(cli.epochs)
        .learning_rate(cli.lr)
        .neg_samples(cli.neg_samples)
        .random_seed(cli.seed)
        .fit(n_nodes, &edges);

    for embedding in &result.embeddings {
        let formatted: Vec<String> = embedding.iter().map(|x| format!("{x:.6}")).collect();
        println!("{}", formatted.join("\t"));
    }

    eprintln!("# {n_nodes} nodes → {}-dim embeddings", cli.dim);

    ExitCode::SUCCESS
}

/// Reads an edge list and returns the inferred node count plus the edge pairs.
///
/// Each non-empty, non-comment line must contain exactly two non-negative integers.
/// The node count is `max_node_index + 1`.
fn read_edges(path: &PathBuf) -> io::Result<(usize, Vec<(usize, usize)>)> {
    let reader: Box<dyn BufRead> = if path.to_str() == Some("-") {
        Box::new(io::BufReader::new(io::stdin()))
    } else {
        Box::new(io::BufReader::new(std::fs::File::open(path)?))
    };

    let mut edges: Vec<(usize, usize)> = Vec::new();
    let mut max_node = 0usize;

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

        if parts.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "line {}: expected two node indices, got {}",
                    line_num + 1,
                    parts.len()
                ),
            ));
        }

        let u = parts[0].parse::<usize>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "line {}: '{}' is not a valid node index",
                    line_num + 1,
                    parts[0]
                ),
            )
        })?;
        let v = parts[1].parse::<usize>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "line {}: '{}' is not a valid node index",
                    line_num + 1,
                    parts[1]
                ),
            )
        })?;

        max_node = max_node.max(u).max(v);
        edges.push((u, v));
    }

    let n_nodes = if edges.is_empty() { 0 } else { max_node + 1 };
    Ok((n_nodes, edges))
}
