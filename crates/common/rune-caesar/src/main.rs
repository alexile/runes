//! `rune-caesar` command-line tool: caesar cipher — shift-based substitution cipher with brute-force decoder.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_caesar::{brute_force, decrypt, encrypt};
use std::process::ExitCode;

/// Caesar cipher — encrypt, decrypt, or brute-force a message.
#[derive(Parser)]
#[command(name = "rune-caesar", version, author)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt text with a Caesar cipher
    Encrypt {
        /// Plaintext to encrypt
        text: String,
        /// Number of positions to shift (0–25)
        #[arg(short, long)]
        shift: u8,
    },
    /// Decrypt text with a Caesar cipher
    Decrypt {
        /// Ciphertext to decrypt
        text: String,
        /// Shift that was used during encryption (0–25)
        #[arg(short, long)]
        shift: u8,
    },
    /// Try all 25 shifts and print every candidate plaintext
    Brute {
        /// Ciphertext to brute-force
        text: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Encrypt { text, shift } => {
            println!("{}", encrypt(&text, shift));
        }
        Command::Decrypt { text, shift } => {
            println!("{}", decrypt(&text, shift));
        }
        Command::Brute { text } => {
            for (shift, plaintext) in brute_force(&text) {
                println!("shift={shift}: {plaintext}");
            }
        }
    }

    ExitCode::SUCCESS
}
