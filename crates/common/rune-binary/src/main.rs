//! `rune-binary` command-line tool: binary representation encoder and decoder — converts bytes to 01010101 bit strings.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_binary::{decode, encode};
use std::{
    io::{self, Read, Write},
    process::ExitCode,
};

/// Encode bytes to binary bit strings and decode binary strings back to bytes.
#[derive(Parser)]
#[command(name = "rune-binary", version, author)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encode bytes to a binary bit string (01010101 format)
    Encode {
        /// File to encode, or - to read from stdin
        file: Option<String>,
    },
    /// Decode a binary string to raw bytes
    Decode {
        /// Binary string to decode, a file path, or - to read from stdin
        input: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Encode { file } => {
            let data = match read_bytes(file.as_deref()) {
                Ok(data) => data,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::FAILURE;
                }
            };
            println!("{}", encode(&data));
        }

        Command::Decode { input } => {
            let text = match read_text(input.as_deref()) {
                Ok(text) => text,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::FAILURE;
                }
            };
            match decode(text.trim()) {
                Ok(bytes) => {
                    if let Err(error) = io::stdout().write_all(&bytes) {
                        eprintln!("error: {error}");
                        return ExitCode::FAILURE;
                    }
                }
                Err(error) => {
                    eprintln!("error: {error}");
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
        Some(s) => {
            if std::path::Path::new(s).exists() {
                std::fs::read_to_string(s)
            } else {
                Ok(s.to_owned())
            }
        }
    }
}
