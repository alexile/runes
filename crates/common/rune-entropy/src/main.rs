//! `rune-entropy` command-line tool: shannon entropy calculator for files and byte streams — useful for detecting encrypted, packed, or compressed data.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_entropy::{block_entropy, classify, entropy, file_entropy};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "rune-entropy",
    about = "Shannon entropy calculator — detects encrypted, packed, or compressed data",
    version
)]
struct Cli {
    /// Files to analyse. Use '-' to read from stdin.
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Split each file into fixed-size blocks and print per-block entropy.
    #[arg(short = 'b', long, value_name = "BYTES")]
    block_size: Option<usize>,
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
fn progress_bar(score: f64) -> String {
    let filled = (score / 8.0 * 20.0).round() as usize;
    let empty = 20usize.saturating_sub(filled);
    format!("[{}{}]", "#".repeat(filled), ".".repeat(empty))
}

fn read_stdin() -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn is_stdin(path: &Path) -> bool {
    path.as_os_str() == "-"
}

fn print_block_analysis(bytes: &[u8], block_size: usize, source_name: &str) {
    println!("{source_name}");
    let scores = block_entropy(bytes, block_size);
    let total = scores.len();
    let offset_width = format!("{}", (total.saturating_sub(1)) * block_size).len();
    for (i, score) in scores.iter().enumerate() {
        let offset = i * block_size;
        let bar = progress_bar(*score);
        let label = classify(*score);
        println!("  {offset:>offset_width$}  {score:.4}  {bar}  {label}");
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let is_multi = cli.files.len() > 1;

    for path in &cli.files {
        let source_name = if is_stdin(path) {
            "<stdin>".to_string()
        } else {
            path.display().to_string()
        };

        if let Some(block_size) = cli.block_size {
            let result = if is_stdin(path) {
                read_stdin()
            } else {
                std::fs::read(path)
            };
            match result {
                Ok(bytes) => print_block_analysis(&bytes, block_size, &source_name),
                Err(error) => {
                    eprintln!("error: {source_name}: {error}");
                    return ExitCode::FAILURE;
                }
            }
            continue;
        }

        let result = if is_stdin(path) {
            read_stdin().map(|bytes| entropy(&bytes))
        } else {
            file_entropy(path)
        };

        match result {
            Ok(score) => {
                let bar = progress_bar(score);
                let label = classify(score);
                if is_multi {
                    println!("{score:.4}  {bar}  {label:>20}  {source_name}");
                } else {
                    println!("file:     {source_name}");
                    println!("entropy:  {score:.4} / 8.0  {bar}  {label}");
                }
            }
            Err(error) => {
                eprintln!("error: {source_name}: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}
