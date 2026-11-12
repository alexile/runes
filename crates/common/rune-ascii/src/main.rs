//! `rune-ascii` command-line tool: aSCII table lookup and character conversion — decimal, hex, octal, binary, and char.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_ascii::{parse_input, table};
use std::process::ExitCode;

/// ASCII table lookup and character conversion — decimal, hex, octal, binary, and char.
#[derive(Parser)]
#[command(name = "rune-ascii", version, author)]
struct Cli {
    /// Code point or character to look up.
    ///
    /// Accepts: decimal (65), hex (0x41), octal (0o101), binary (0b01000001),
    /// or a single printable character (A).
    input: Option<String>,

    /// Print the full ASCII table (all 128 code points).
    #[arg(short, long)]
    table: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.table {
        print_table();
        return ExitCode::SUCCESS;
    }

    cli.input.map_or_else(
        || {
            eprintln!("error: provide an input value or use --table");
            ExitCode::FAILURE
        },
        |raw| match parse_input(&raw) {
            None => {
                eprintln!("error: \"{raw}\" is not a valid ASCII code point (0–127)");
                ExitCode::FAILURE
            }
            Some(entry) => {
                println!("Dec:  {}", entry.code);
                println!("Hex:  {}", entry.hex);
                println!("Oct:  {}", entry.octal);
                println!("Bin:  {}", entry.binary);
                println!("Char: {}", entry.character);
                println!("Desc: {}", entry.description);
                ExitCode::SUCCESS
            }
        },
    )
}

fn print_table() {
    println!(
        "{:<5} {:<6} {:<7} {:<10} {:<5} Desc",
        "Dec", "Hex", "Oct", "Bin", "Char"
    );
    println!("{}", "-".repeat(50));
    for entry in table() {
        println!(
            "{:<5} {:<6} {:<7} {:<10} {:<5} {}",
            entry.code, entry.hex, entry.octal, entry.binary, entry.character, entry.description,
        );
    }
}
