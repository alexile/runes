//! `rune-hex` command-line tool: hex encoding and decoding for byte slices and files — lowercase, uppercase, and streaming output.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_hex::{decode, encode, encode_upper};
use std::{
    io::{self, Read, Write},
    process::ExitCode,
};

/// Hex encode and decode bytes, files, and stdin.
#[derive(Parser)]
#[command(name = "rune-hex", version, author)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encode bytes to hex
    Encode {
        /// File to encode (omit or use - for stdin)
        file: Option<String>,
        /// Output uppercase hex
        #[arg(short, long)]
        upper: bool,
    },
    /// Decode a hex string to raw bytes
    Decode {
        /// Hex string to decode, or - to read from stdin
        input: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Encode { file, upper } => {
            let data = match read_bytes(file.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let hex = if upper {
                encode_upper(&data)
            } else {
                encode(&data)
            };
            println!("{hex}");
        }

        Command::Decode { input } => {
            let text = match read_text(input.as_deref()) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match decode(text.trim()) {
                Ok(bytes) => {
                    if let Err(e) = io::stdout().write_all(&bytes) {
                        eprintln!("error: {e}");
                        return ExitCode::FAILURE;
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    ExitCode::SUCCESS
}

fn read_bytes(path: Option<&str>) -> io::Result<Vec<u8>> {
    match path {
        None | Some("-") => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
        Some(p) => std::fs::read(p),
    }
}

fn read_text(path: Option<&str>) -> io::Result<String> {
    match path {
        None | Some("-") => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
        Some(s) => Ok(s.to_owned()),
    }
}
