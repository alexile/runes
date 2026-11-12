//! `rune-multiplex` command-line tool: fan-in merge of N ordered sources into one interleaved, time-ordered stream.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_multiplex::multiplex;
use std::fs;
use std::process::ExitCode;

/// Merge N files of newline-separated, ascending integers into one sorted stream.
#[derive(Parser)]
#[command(name = "rune-multiplex")]
struct Args {
    /// Pre-sorted source files, one integer per line.
    #[arg(required = true)]
    files: Vec<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let mut sources = Vec::with_capacity(args.files.len());

    for path in &args.files {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) => {
                eprintln!("rune-multiplex: {path}: {err}");
                return ExitCode::FAILURE;
            }
        };

        let mut values = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match line.parse::<i64>() {
                Ok(value) => values.push(value),
                Err(err) => {
                    eprintln!("rune-multiplex: {path}: bad integer '{line}': {err}");
                    return ExitCode::FAILURE;
                }
            }
        }
        sources.push(values);
    }

    for value in multiplex(sources, |v| *v) {
        println!("{value}");
    }

    ExitCode::SUCCESS
}
