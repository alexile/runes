//! `rune-fuzzyhash` command-line tool: TLSH and ssdeep digests of files.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rune_fuzzyhash::{Error, Ssdeep, Tlsh};

/// TLSH and ssdeep fuzzy hashes.
#[derive(Parser)]
#[command(name = "rune-fuzzyhash", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print `tlsh<TAB>ssdeep<TAB>path` for each file (`-` when the input
    /// cannot be hashed).
    Hash {
        /// Files to hash.
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Compare two digests of the same kind: TLSH prints a distance
    /// (lower is closer), ssdeep a 0-100 score (higher is closer).
    Compare {
        /// First digest.
        a: String,
        /// Second digest.
        b: String,
    },
}

fn compare(a: &str, b: &str) -> Result<String, Error> {
    if let (Ok(x), Ok(y)) = (a.parse::<Tlsh>(), b.parse::<Tlsh>()) {
        return Ok(x.distance(&y).to_string());
    }
    Ok(a.parse::<Ssdeep>()?
        .compare(&b.parse::<Ssdeep>()?)
        .to_string())
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Hash { files } => {
            let mut status = ExitCode::SUCCESS;
            for path in files {
                match std::fs::read(&path) {
                    Ok(data) => {
                        let tlsh =
                            Tlsh::hash(&data).map_or_else(|_| "-".to_owned(), |t| t.to_string());
                        let ssdeep =
                            Ssdeep::hash(&data).map_or_else(|_| "-".to_owned(), |s| s.to_string());
                        println!("{tlsh}\t{ssdeep}\t{}", path.display());
                    }
                    Err(err) => {
                        eprintln!("error: {}: {err}", path.display());
                        status = ExitCode::FAILURE;
                    }
                }
            }
            status
        }
        Command::Compare { a, b } => match compare(&a, &b) {
            Ok(out) => {
                println!("{out}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        },
    }
}
