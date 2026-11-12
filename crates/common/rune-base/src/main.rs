//! `rune-base` command-line tool: encode and decode integers and byte strings in any numeric base with a custom alphabet.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_base::{decode, encode};
use std::{
    io::{self, Read, Write},
    process::ExitCode,
};

/// Encode and decode bytes in any base using a custom alphabet.
#[derive(Parser)]
#[command(name = "rune-base", version, author)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encode bytes to a base-N string
    Encode {
        /// File to encode, or - to read from stdin
        file: Option<String>,
        /// Alphabet defining the base (e.g. "01" for binary, "0123456789abcdef" for hex)
        #[arg(long, short)]
        alphabet: String,
    },
    /// Decode a base-N string back to raw bytes
    Decode {
        /// File containing the encoded string, or - to read from stdin
        file: Option<String>,
        /// Alphabet that was used to encode the input
        #[arg(long, short)]
        alphabet: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Encode { file, alphabet } => {
            let data = match read_bytes(file.as_deref()) {
                Ok(data) => data,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::FAILURE;
                }
            };
            match encode(&data, alphabet.as_bytes()) {
                Ok(encoded) => println!("{encoded}"),
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }

        Command::Decode { file, alphabet } => {
            let text = match read_text(file.as_deref()) {
                Ok(text) => text,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::FAILURE;
                }
            };
            match decode(text.trim(), alphabet.as_bytes()) {
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
        Some(p) => std::fs::read_to_string(p),
    }
}
