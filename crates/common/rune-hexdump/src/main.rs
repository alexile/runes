//! `rune-hexdump` command-line tool: hex dump with sidebar — inspect binary files like xxd.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_hexdump::{HexdumpConfig, hexdump};
use std::{
    io::{self, Read},
    process::ExitCode,
};

/// Hex dump with sidebar — inspect binary files like xxd.
#[derive(Parser)]
#[command(name = "rune-hexdump", version, author)]
struct Cli {
    /// File to dump, or `-` to read from stdin.
    file: Option<String>,

    /// Number of bytes per row.
    #[arg(long, default_value_t = 16)]
    cols: usize,

    /// Omit the ASCII sidebar.
    #[arg(long)]
    no_ascii: bool,

    /// Use uppercase hex digits.
    #[arg(long)]
    upper: bool,

    /// Omit the byte-offset column.
    #[arg(long)]
    no_offset: bool,
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

    let config = HexdumpConfig {
        bytes_per_row: cli.cols,
        show_offset: !cli.no_offset,
        show_ascii: !cli.no_ascii,
        uppercase: cli.upper,
    };

    print!("{}", hexdump(&data, &config));
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
