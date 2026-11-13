//! `rune-tsne` command-line tool: t-SNE dimensionality reduction — map high-dimensional data into 2D or 3D for visualisation.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, BufRead};
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use rune_tsne::{Init, Method, Tsne};

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

    /// Learning rate (default: `n_points / (4 · early_exaggeration)`).
    #[arg(long)]
    learning_rate: Option<f64>,

    /// Number of output dimensions.
    #[arg(long, default_value_t = 2)]
    n_components: usize,

    /// Gradient method.
    #[arg(long, value_enum, default_value_t = MethodArg::Auto)]
    method: MethodArg,

    /// Barnes-Hut accuracy/speed trade-off in [0, 1] (0 = exact).
    #[arg(long, default_value_t = 0.5)]
    theta: f64,

    /// Initialisation.
    #[arg(long, value_enum, default_value_t = InitArg::Pca)]
    init: InitArg,

    /// Factor applied to the affinities during early exaggeration.
    #[arg(long, default_value_t = 12.0)]
    early_exaggeration: f64,

    /// PRNG seed for reproducible output.
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Print the KL divergence to stderr every this many iterations (0 = never).
    #[arg(long, default_value_t = 0)]
    report_every: usize,
}

#[derive(Clone, Copy, ValueEnum)]
enum MethodArg {
    Auto,
    Exact,
    BarnesHut,
}

#[derive(Clone, Copy, ValueEnum)]
enum InitArg {
    Pca,
    Random,
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
        .method(match cli.method {
            MethodArg::Auto => Method::Auto,
            MethodArg::Exact => Method::Exact,
            MethodArg::BarnesHut => Method::BarnesHut,
        })
        .theta(cli.theta)
        .init(match cli.init {
            InitArg::Pca => Init::Pca,
            InitArg::Random => Init::Random,
        })
        .early_exaggeration(cli.early_exaggeration)
        .random_seed(cli.seed);
    if let Some(lr) = cli.learning_rate {
        tsne = tsne.learning_rate(lr);
    }
    let every = cli.report_every;
    let result = if every == 0 {
        tsne.try_fit(&points)
    } else {
        tsne.try_fit_with(&points, |it| {
            if (it.iteration + 1) % every == 0 {
                eprintln!(
                    "iteration {:>5}  KL {:.6}  |grad| {:.3e}",
                    it.iteration + 1,
                    it.kl_divergence,
                    it.gradient_norm
                );
            }
            ControlFlow::Continue(())
        })
    };
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
        "# {} points → {}D embedding ({:?}, KL {:.6})",
        points.len(),
        cli.n_components,
        result.method,
        result.kl_divergence
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
