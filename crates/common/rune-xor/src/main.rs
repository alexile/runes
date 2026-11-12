//! `rune-xor` command-line tool: xOR cipher for byte streams and files — repeating-key and single-byte modes with English-scored brute-force.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{ArgGroup, Parser};
use rune_xor::{break_repeating_key_xor, brute_force, xor};
use std::fmt::Write as _;
use std::{
    io::{self, Read, Write},
    process::ExitCode,
};

/// XOR cipher for byte streams and files.
///
/// Applies a repeating key or brute-forces an unknown key using English
/// letter-frequency scoring. Pass --break to crack an unknown repeating-key
/// XOR cipher automatically.
#[derive(Parser)]
#[command(name = "rune-xor", version, author)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["key", "hex_key", "brute", "break_key"]),
))]
struct Cli {
    /// File to XOR (omit or use - for stdin)
    file: Option<String>,

    /// XOR key as a UTF-8 string
    #[arg(short, long)]
    key: Option<String>,

    /// XOR key as hex bytes (e.g. deadbeef)
    #[arg(long = "hex-key", value_name = "HEX")]
    hex_key: Option<String>,

    /// Brute-force a single-byte key and show top candidates
    #[arg(short, long)]
    brute: bool,

    /// Crack a repeating-key XOR cipher using Hamming distance key-size detection
    #[arg(long = "break")]
    break_key: bool,

    /// Number of candidates to display (--brute and --break)
    #[arg(short = 'n', long, default_value = "5")]
    top: usize,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let data = match read_input(cli.file.as_deref()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if cli.brute {
        print_brute_force(&data, cli.top);
        return ExitCode::SUCCESS;
    }

    if cli.break_key {
        print_break_candidates(&data, cli.top);
        return ExitCode::SUCCESS;
    }

    let key = if let Some(hex) = cli.hex_key {
        match decode_hex(&hex) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("error: invalid hex key: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else if let Some(key) = cli.key {
        key.into_bytes()
    } else {
        eprintln!("error: one of --key or --hex-key is required");
        return ExitCode::FAILURE;
    };

    if key.is_empty() {
        eprintln!("error: key must not be empty");
        return ExitCode::FAILURE;
    }

    let result = xor(&data, &key);
    if let Err(e) = io::stdout().write_all(&result) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn read_input(path: Option<&str>) -> io::Result<Vec<u8>> {
    match path {
        None | Some("-") => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
        Some(p) => std::fs::read(p),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_start_matches("0x");
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| format!("invalid hex byte '{}'", &s[i..i + 2]))
        })
        .collect()
}

fn bytes_to_printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (32..=126).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

fn key_display(key: &[u8]) -> String {
    let hex: String = key
        .iter()
        .fold(String::with_capacity(key.len() * 2), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        });
    let ascii = bytes_to_printable(key);
    format!("{hex} ({ascii})")
}

fn print_brute_force(data: &[u8], top: usize) {
    let candidates = brute_force(data);
    println!("{:<6} {:<10} Plaintext (first 64 bytes)", "Key", "Score");
    println!("{}", "-".repeat(80));
    for candidate in candidates.iter().take(top) {
        let preview = bytes_to_printable(&candidate.plaintext[..candidate.plaintext.len().min(64)]);
        println!(
            "0x{:02x}   {:<10.2} {}",
            candidate.key, candidate.score, preview
        );
    }
}

fn print_break_candidates(data: &[u8], top: usize) {
    let candidates = break_repeating_key_xor(data);
    if candidates.is_empty() {
        eprintln!("error: ciphertext is empty");
        return;
    }
    println!("{:<30} {:<10} Plaintext (first 64 bytes)", "Key", "Score");
    println!("{}", "-".repeat(92));
    for candidate in candidates.iter().take(top) {
        let preview = bytes_to_printable(&candidate.plaintext[..candidate.plaintext.len().min(64)]);
        let key = key_display(&candidate.key);
        println!("{:<30} {:<10.2} {}", key, candidate.score, preview);
    }
}
