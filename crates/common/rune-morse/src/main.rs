//! `rune-morse` command-line tool: morse code encoder and decoder — ASCII text to dots and dashes and back.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_morse::{decode, encode};
use std::process::ExitCode;

/// Morse code encoder and decoder.
#[derive(Parser)]
#[command(name = "rune-morse", version, author)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encode ASCII text as Morse code
    Encode {
        /// Text to encode (letters and digits only)
        text: String,
    },
    /// Decode Morse code back to text
    Decode {
        /// Morse code to decode (letters separated by spaces, words by " / ")
        morse: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Encode { text } => match encode(&text) {
            Ok(morse) => {
                println!("{morse}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
        Command::Decode { morse } => match decode(&morse) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
    }
}
