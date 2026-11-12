//! `rune-pca` command-line tool: project numeric tabular data onto its principal components.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use rune_pca::{Components, Pca, Solver};

/// Principal component analysis for numeric tabular data.
#[derive(Parser)]
#[command(name = "rune-pca", version, about)]
struct Cli {
    /// Input file: one sample per line, space or comma separated numbers.
    /// Use `-` to read from stdin.
    file: PathBuf,
    /// Number of components to keep (default: all).
    #[arg(long, short = 'k', conflicts_with = "variance")]
    n_components: Option<usize>,
    /// Keep the fewest components explaining this fraction of the variance.
    #[arg(long)]
    variance: Option<f64>,
    /// Decomposition algorithm.
    #[arg(long, value_enum, default_value_t = SolverArg::Auto)]
    solver: SolverArg,
    /// Scale each output component to unit variance.
    #[arg(long)]
    whiten: bool,
    /// Seed for the randomized solver.
    #[arg(long, default_value_t = 0)]
    seed: u64,
}

#[derive(Clone, Copy, ValueEnum)]
enum SolverArg {
    Auto,
    Covariance,
    Svd,
    Randomized,
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
    let components = match (cli.n_components, cli.variance) {
        (Some(k), _) => Components::Count(k),
        (None, Some(r)) => Components::VarianceRatio(r),
        (None, None) => Components::All,
    };
    let solver = match cli.solver {
        SolverArg::Auto => Solver::Auto,
        SolverArg::Covariance => Solver::Covariance,
        SolverArg::Svd => Solver::Svd,
        SolverArg::Randomized => Solver::Randomized,
    };
    let pca = Pca::default()
        .with_components(components)
        .with_solver(solver)
        .with_whiten(cli.whiten)
        .with_seed(cli.seed);
    let (model, projected) = match pca.fit_transform(&points) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    for row in &projected {
        let formatted: Vec<String> = row.iter().map(|x| format!("{x:.6}")).collect();
        println!("{}", formatted.join("\t"));
    }
    let ratios: Vec<String> = model
        .explained_variance_ratio()
        .iter()
        .map(|r| format!("{r:.4}"))
        .collect();
    eprintln!(
        "# {} samples × {} features → {} components; explained variance ratio: {}",
        model.n_samples(),
        model.n_features(),
        model.n_components(),
        ratios.join(" ")
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
