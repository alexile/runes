//! `rune-pagerank` command-line tool: pageRank — score graph nodes by importance via random-walk convergence.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_pagerank::PageRank;

type ParsedEdges = (usize, Vec<(usize, usize, f64)>);

#[derive(Parser)]
#[command(
    name = "rune-pagerank",
    about = "Score graph nodes by importance using the PageRank algorithm"
)]
struct Cli {
    /// Edge list file: one edge per line, format `from to [weight]`.
    /// Fields may be space or comma separated. Use `-` to read from stdin.
    file: PathBuf,

    /// Damping factor — probability the surfer follows an edge (default: 0.85).
    #[arg(long, default_value_t = 0.85)]
    damping: f64,

    /// Maximum number of power-iteration steps.
    #[arg(long, default_value_t = 100)]
    max_iter: usize,

    /// Convergence tolerance: stop when max score delta drops below this value.
    #[arg(long, default_value_t = 1e-6)]
    tol: f64,
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
        eprintln!("error: no edges found");
        return ExitCode::FAILURE;
    }

    let result = PageRank::new()
        .damping(cli.damping)
        .max_iter(cli.max_iter)
        .tol(cli.tol)
        .rank(n_nodes, &edges);

    for (node, score) in result.scores.iter().enumerate() {
        println!("{node}\t{score:.6}");
    }

    let status = if result.converged {
        "converged"
    } else {
        "max_iter reached"
    };
    eprintln!(
        "# {n_nodes} nodes → {status} in {} iterations",
        result.iterations
    );

    ExitCode::SUCCESS
}

fn read_edges(path: &PathBuf) -> io::Result<ParsedEdges> {
    let reader: Box<dyn BufRead> = if path.to_str() == Some("-") {
        Box::new(io::BufReader::new(io::stdin()))
    } else {
        Box::new(io::BufReader::new(std::fs::File::open(path)?))
    };

    let mut edges: Vec<(usize, usize, f64)> = Vec::new();
    let mut max_node: Option<usize> = None;

    for (line_number, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = trimmed
            .split(|c: char| c == ',' || c.is_ascii_whitespace())
            .filter(|s| !s.is_empty())
            .collect();

        if fields.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: expected at least 2 fields", line_number + 1),
            ));
        }

        let from = parse_node(fields[0], line_number)?;
        let to = parse_node(fields[1], line_number)?;
        let weight = if fields.len() >= 3 {
            parse_weight(fields[2], line_number)?
        } else {
            1.0
        };

        max_node = Some(max_node.map_or_else(|| from.max(to), |m: usize| m.max(from).max(to)));
        edges.push((from, to, weight));
    }

    let n_nodes = max_node.map_or(0, |m| m + 1);
    Ok((n_nodes, edges))
}

fn parse_node(s: &str, line_number: usize) -> io::Result<usize> {
    s.parse::<usize>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "line {}: '{}' is not a valid node index",
                line_number + 1,
                s
            ),
        )
    })
}

fn parse_weight(s: &str, line_number: usize) -> io::Result<f64> {
    let weight: f64 = s.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("line {}: '{}' is not a valid weight", line_number + 1, s),
        )
    })?;
    if weight <= 0.0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "line {}: weight must be positive, got {}",
                line_number + 1,
                weight
            ),
        ));
    }
    Ok(weight)
}
