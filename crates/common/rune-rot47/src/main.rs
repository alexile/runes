//! `rune-rot47` command-line tool: rOT47 cipher — rotate printable ASCII characters by 47 positions.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_rot47::rot47_bytes;
use std::{
    io::{self, Read},
    process::ExitCode,
};

/// ROT47 cipher — rotate printable ASCII characters by 47 positions.
///
/// Pass text as an argument, pipe via stdin, or supply a file with -f.
/// Bytes outside the printable ASCII range (33–126) are passed through unchanged.
#[derive(Parser)]
#[command(name = "rune-rot47", version, author)]
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

    let output = rot47_bytes(&input);
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
