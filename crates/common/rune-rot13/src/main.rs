//! `rune-rot13` command-line tool: rOT13 cipher — rotate ASCII letters by 13 positions.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_rot13::rot13_bytes;
use std::{
    io::{self, Read},
    process::ExitCode,
};

/// ROT13 cipher — rotate ASCII letters by 13 positions.
///
/// Pass text as an argument, pipe via stdin, or supply a file with -f.
/// Non-letter characters are passed through unchanged.
#[derive(Parser)]
#[command(name = "rune-rot13", version, author)]
struct Cli {
    /// Text to encode (omit to read from stdin)
    text: Option<String>,

    /// File to encode instead of reading from stdin
    #[arg(short, long, value_name = "FILE")]
    file: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let input = match read_input(cli.text.as_deref(), cli.file.as_deref()) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };

    let output = rot13_bytes(&input);
    print!("{}", String::from_utf8_lossy(&output));

    ExitCode::SUCCESS
}

fn read_input(text: Option<&str>, file: Option<&str>) -> io::Result<Vec<u8>> {
    if let Some(content) = text {
        return Ok(content.as_bytes().to_vec());
    }
    if let Some(path) = file {
        return std::fs::read(path);
    }
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;
    Ok(buffer)
}
