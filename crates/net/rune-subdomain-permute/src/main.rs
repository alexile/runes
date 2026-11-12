//! `rune-subdomain-permute` command-line tool: reads known host names and
//! prints permutation candidates, one per line.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::{self, BufRead, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_subdomain_permute::{DEFAULT_PATTERNS, Options, Payloads, Permutator, Seed};

/// Pattern-based subdomain permutation (alterx class).
///
/// Reads seed host names (one per line) from the arguments or, if none,
/// from standard input, and prints candidates one per line.
#[derive(Parser)]
#[command(name = "rune-subdomain-permute", version, about)]
struct Cli {
    /// Seed host names. Read from stdin when none are given.
    seeds: Vec<String>,
    /// A pattern such as `{{word}}-{{sub}}.{{suffix}}`. Repeatable;
    /// replaces the default patterns.
    #[arg(short, long = "pattern")]
    patterns: Vec<String>,
    /// A payload list as NAME=FILE (one value per line). Repeatable;
    /// replaces the built-in list of that name.
    #[arg(short = 'P', long = "payload", value_name = "NAME=FILE")]
    payloads: Vec<String>,
    /// Add tokens seen in the seeds to the `word` list.
    #[arg(long)]
    enrich: bool,
    /// Number mutation range (0 disables).
    #[arg(long, default_value_t = 1)]
    number_delta: u32,
    /// Stop after this many candidates.
    #[arg(short, long)]
    limit: Option<usize>,
    /// Print an upper bound on the candidate count and exit.
    #[arg(long)]
    estimate: bool,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let mut payloads = Payloads::builtin();
    for spec in &cli.payloads {
        let (name, file) = spec
            .split_once('=')
            .ok_or_else(|| format!("--payload {spec:?}: expected NAME=FILE"))?;
        let text = std::fs::read_to_string(PathBuf::from(file))?;
        payloads.insert(name, text.lines())?;
    }
    let mut options = Options::default()
        .with_enrich(cli.enrich)
        .with_number_delta(cli.number_delta);
    if let Some(limit) = cli.limit {
        options = options.with_limit(limit);
    }
    let patterns: Vec<String> = if cli.patterns.is_empty() {
        DEFAULT_PATTERNS.iter().map(|p| (*p).to_owned()).collect()
    } else {
        cli.patterns
    };
    let permutator = Permutator::new(patterns, payloads, options)?;

    let lines: Vec<String> = if cli.seeds.is_empty() {
        io::stdin().lock().lines().collect::<Result<_, _>>()?
    } else {
        cli.seeds
    };
    let mut seeds = Vec::new();
    for line in lines.iter().map(|l| l.trim()).filter(|l| !l.is_empty()) {
        match Seed::parse(line) {
            Ok(seed) => seeds.push(seed),
            Err(err) => eprintln!("skipping: {err}"),
        }
    }

    let mut out = BufWriter::new(io::stdout().lock());
    if cli.estimate {
        writeln!(out, "{}", permutator.estimate(&seeds))?;
    } else {
        for candidate in permutator.permute(&seeds) {
            writeln!(out, "{candidate}")?;
        }
    }
    out.flush()?;
    Ok(())
}
