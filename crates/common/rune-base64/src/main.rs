//! `rune-base64` command-line tool: base64 encoder and decoder — standard (RFC 4648) and URL-safe variants.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_base64::{decode, encode, encode_no_pad, encode_url, encode_url_no_pad};
use std::{
    io::{self, Read, Write},
    process::ExitCode,
};

/// Base64 encode and decode files, strings, and stdin — standard and URL-safe variants.
#[derive(Parser)]
#[command(name = "rune-base64", version, author)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encode bytes to Base64
    Encode {
        /// File to encode, or - to read from stdin
        file: Option<String>,
        /// Use URL-safe alphabet (- and _ instead of + and /)
        #[arg(long)]
        url: bool,
        /// Omit = padding characters
        #[arg(long)]
        no_pad: bool,
    },
    /// Decode a Base64 string to raw bytes
    Decode {
        /// Base64 string to decode, a file path, or - to read from stdin
        input: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Encode { file, url, no_pad } => {
            let data = match read_bytes(file.as_deref()) {
                Ok(data) => data,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let encoded = match (url, no_pad) {
                (true, true) => encode_url_no_pad(&data),
                (true, false) => encode_url(&data),
                (false, true) => encode_no_pad(&data),
                (false, false) => encode(&data),
            };
            println!("{encoded}");
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
