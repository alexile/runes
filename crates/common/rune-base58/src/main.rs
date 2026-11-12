//! `rune-base58` command-line tool: base58 encode/decode — Bitcoin alphabet and Flickr alphabet, with optional Check encoding.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_base58::{decode, decode_flickr, encode, encode_flickr};
use std::io::{self, Read};
use std::process::ExitCode;

/// Base58 encode and decode (Bitcoin and Flickr alphabets).
#[derive(Parser)]
#[command(name = "rune-base58", version, author)]
struct Args {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Encode bytes to Base58.
    Encode {
        /// Input. Use `-` for stdin.
        #[arg(value_name = "INPUT")]
        input: Option<String>,
        /// Use Flickr alphabet.
        #[arg(long)]
        flickr: bool,
    },
    /// Decode a Base58 string to bytes.
    Decode {
        /// Base58 string. Use `-` for stdin.
        #[arg(value_name = "INPUT")]
        input: Option<String>,
        /// Use Flickr alphabet.
        #[arg(long)]
        flickr: bool,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();

    match args.command {
        Cmd::Encode { input, flickr } => {
            let data = match read_input(input.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let encoded = if flickr {
                encode_flickr(&data)
            } else {
                encode(&data)
            };
            println!("{encoded}");
        }
        Cmd::Decode { input, flickr } => {
            let data = match read_input(input.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let text = String::from_utf8_lossy(&data);
            let result = if flickr {
                decode_flickr(text.trim())
            } else {
                decode(text.trim())
            };
            match result {
                Ok(bytes) => {
                    let _ = io::Write::write_all(&mut io::stdout(), &bytes);
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

fn read_input(input: Option<&str>) -> io::Result<Vec<u8>> {
    match input {
        Some("-") | None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
        Some(s) => Ok(s.as_bytes().to_vec()),
    }
}
