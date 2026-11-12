//! `rune-byte-magic` command-line tool: identify file types from magic bytes — pure Rust, no libmagic dependency.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_byte_magic::identify;
use std::{
    io::{self, Read},
    process::ExitCode,
};

/// Identify file types from magic bytes — no libmagic required.
#[derive(Parser)]
#[command(name = "rune-byte-magic", version, author)]
struct Cli {
    /// Files to identify. Use `-` to read from stdin.
    files: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let targets: Vec<String> = if cli.files.is_empty() {
        vec!["-".to_owned()]
    } else {
        cli.files
    };

    let mut success = true;

    for target in &targets {
        match read_header(target) {
            Ok(bytes) => print_result(target, &bytes),
            Err(error) => {
                eprintln!("{target}: {error}");
                success = false;
            }
        }
    }

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_result(label: &str, bytes: &[u8]) {
    let file_type = identify(bytes);
    println!("{label}: {} ({})", file_type.name(), file_type.mime_type());
}

fn read_header(target: &str) -> io::Result<Vec<u8>> {
    if target == "-" {
        let mut buffer = vec![0u8; 512];
        let n = io::stdin().read(&mut buffer)?;
        buffer.truncate(n);
        Ok(buffer)
    } else {
        let mut file = std::fs::File::open(target)?;
        let mut buffer = vec![0u8; 512];
        let n = file.read(&mut buffer)?;
        buffer.truncate(n);
        Ok(buffer)
    }
}
