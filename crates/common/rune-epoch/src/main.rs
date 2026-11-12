//! `rune-epoch` command-line tool: unix timestamp conversions — epoch to human-readable and back.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_epoch::{from_utc_string, now_millis, now_secs, to_utc_string};
use std::process::ExitCode;

/// Convert Unix timestamps to human-readable UTC strings and back.
#[derive(Parser)]
#[command(name = "rune-epoch", version, author)]
struct Cli {
    /// Epoch seconds to convert to UTC, or a datetime string to convert to epoch.
    /// Omit to print the current epoch.
    input: Option<String>,

    /// Print the current epoch in milliseconds instead of seconds.
    #[arg(short, long)]
    millis: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.input {
        None => {
            if cli.millis {
                println!("{}", now_millis());
            } else {
                println!("{}", now_secs());
            }
        }
        Some(value) => {
            if let Ok(epoch_secs) = value.parse::<i64>() {
                println!("{}", to_utc_string(epoch_secs));
            } else {
                match from_utc_string(&value) {
                    Ok(epoch_secs) => println!("{epoch_secs}"),
                    Err(error) => {
                        eprintln!("error: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    }

    ExitCode::SUCCESS
}
