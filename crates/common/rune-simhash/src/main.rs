//! `rune-simhash` command-line tool: fingerprint files and group near-duplicates.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_simhash::{ClusterOptions, Clusterer, ShingleOptions, SimHash, TokenKind};

/// Fingerprint files with `SimHash` and group near-duplicates.
///
/// Prints one line per file: cluster id, fingerprint, path.
#[derive(Parser)]
#[command(name = "rune-simhash", version, about)]
struct Cli {
    /// Files to fingerprint.
    #[arg(required = true)]
    files: Vec<PathBuf>,
    /// Minimum similarity (1 - hamming/64) to join a cluster.
    #[arg(long, default_value_t = 0.8)]
    threshold: f64,
    /// Tokens per shingle.
    #[arg(long, default_value_t = 3)]
    shingle: usize,
    /// Shingle characters instead of words.
    #[arg(long)]
    chars: bool,
    /// Strip HTML tags, scripts and styles first.
    #[arg(long)]
    html: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let kind = if cli.chars {
        TokenKind::Chars
    } else {
        TokenKind::Words
    };
    let opts = ShingleOptions::default()
        .with_kind(kind)
        .with_size(cli.shingle)
        .with_strip_html(cli.html);
    let mut clusters = match Clusterer::new(ClusterOptions::default().with_threshold(cli.threshold))
    {
        Ok(c) => c,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let mut status = ExitCode::SUCCESS;
    for path in &cli.files {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("error: {}: {err}", path.display());
                status = ExitCode::FAILURE;
                continue;
            }
        };
        match SimHash::from_text(&String::from_utf8_lossy(&bytes), &opts) {
            Ok(fp) => {
                let a = clusters.assign(fp);
                println!("{}\t{fp}\t{}", a.cluster, path.display());
            }
            Err(err) => {
                eprintln!("error: {err}");
                return ExitCode::FAILURE;
            }
        }
    }
    status
}
