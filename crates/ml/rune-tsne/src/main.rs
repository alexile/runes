//! `rune-tsne` command-line tool: t-SNE dimensionality reduction — map high-dimensional data into 2D or 3D for visualisation.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_tsne::Tsne;

#[derive(Parser)]
#[command(
    name = "rune-tsne",
    about = "t-SNE dimensionality reduction for numeric tabular data"
)]
struct Cli {
    /// Input file: one point per line, space or comma separated numbers.
    /// Use `-` to read from stdin.
    file: PathBuf,

    /// Target perplexity (loosely: number of effective neighbours).
    #[arg(long, default_value_t = 30.0)]
    perplexity: f64,

    /// Number of gradient-descent iterations.
    #[arg(long, default_value_t = 1000)]
    n_iter: usize,

    /// Learning rate for the momentum SGD update (default: `max(n_points / 48, 50)`).
    #[arg(long)]
    learning_rate: Option<f64>,

    /// Number of output dimensions.
    #[arg(long, default_value_t = 2)]
    n_components: usize,

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

    let mut tsne = Tsne::new()
        .n_components(cli.n_components)
        .perplexity(cli.perplexity)
        .n_iter(cli.n_iter)
        .random_seed(cli.seed);
    if let Some(lr) = cli.learning_rate {
        tsne = tsne.learning_rate(lr);
    }
    let result = tsne.fit(&points);
    let result = match result {
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
