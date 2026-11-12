//! `rune-base32` command-line tool: base32 encode/decode — RFC 4648 standard and hex alphabets, pure Rust.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_base32::{decode, decode_hex, encode, encode_hex, encode_no_pad};
use std::io::{self, Read};
use std::process::ExitCode;

/// Base32 encode and decode (RFC 4648 standard and hex alphabets).
#[derive(Parser)]
#[command(name = "rune-base32", version, author)]
struct Args {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Encode bytes to Base32.
    Encode {
        /// Input text. Use `-` to read stdin.
        #[arg(value_name = "INPUT")]
        input: Option<String>,
        /// Use extended hex alphabet (RFC 4648 §7).
        #[arg(long)]
        hex: bool,
        /// Omit `=` padding characters.
        #[arg(long)]
        no_pad: bool,
    },
    /// Decode a Base32 string to bytes.
    Decode {
        /// Base32 encoded string. Use `-` to read stdin.
        #[arg(value_name = "INPUT")]
        input: Option<String>,
        /// Use extended hex alphabet.
        #[arg(long)]
        hex: bool,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();

    match args.command {
        Cmd::Encode { input, hex, no_pad } => {
            let data = match read_input(input.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let encoded = if hex {
                encode_hex(&data)
            } else if no_pad {
                encode_no_pad(&data)
            } else {
                encode(&data)
            };
            println!("{encoded}");
        }
        Cmd::Decode { input, hex } => {
            let data = match read_input(input.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let text = String::from_utf8_lossy(&data);
            let result = if hex {
                decode_hex(text.trim())
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
