//! `rune-strings` command-line tool: extract printable strings from binary files — configurable minimum length and encoding.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_strings::{StringsConfig, extract};
use std::{
    io::{self, Read},
    process::ExitCode,
};

/// Extract printable strings from binary files, like the Unix `strings` utility.
#[derive(Parser)]
#[command(name = "rune-strings", version, author)]
struct Cli {
    /// File to scan, or `-` to read from stdin.
    file: Option<String>,

    /// Minimum string length (default: 4).
    #[arg(short = 'n', long = "min-length", default_value_t = 4)]
    min_length: usize,

    /// Print the byte offset of each string before its text.
    #[arg(short = 'o', long = "offset")]
    is_offset: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let data = match read_input(cli.file.as_deref()) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };

    let config = StringsConfig {
        min_length: cli.min_length,
        include_offset: cli.is_offset,
    };

    for extracted in extract(&data, &config) {
        if cli.is_offset {
            println!("{:#010x}: {}", extracted.offset, extracted.text);
        } else {
            println!("{}", extracted.text);
        }
    }

    ExitCode::SUCCESS
}

fn read_input(path: Option<&str>) -> io::Result<Vec<u8>> {
    match path {
        None | Some("-") => {
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            Ok(buffer)
        }
        Some(file_path) => std::fs::read(file_path),
    }
}
