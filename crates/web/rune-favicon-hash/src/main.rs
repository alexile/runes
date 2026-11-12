//! `rune-favicon-hash` command-line tool: print the Shodan-style favicon
//! hash of icon files.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_favicon_hash::{favicon_hash, favicon_hash_base64, shodan_query};

/// Print the Shodan-style favicon hash (signed mmh3 of the MIME base64) of
/// each icon file. Nothing is fetched.
#[derive(Parser)]
#[command(name = "rune-favicon-hash", version, about)]
struct Cli {
    /// Icon files; stdin when omitted or `-`.
    files: Vec<PathBuf>,
    /// Inputs hold base64 text (e.g. a data: URI payload) instead of raw bytes.
    #[arg(long)]
    base64: bool,
    /// Print a Shodan search filter instead of the bare hash.
    #[arg(long)]
    shodan: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let files = if cli.files.is_empty() {
        vec![PathBuf::from("-")]
    } else {
        cli.files.clone()
    };
    let mut status = ExitCode::SUCCESS;
    for file in &files {
        let data = if file.as_os_str() == "-" {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf).map(|_| buf)
        } else {
            std::fs::read(file)
        };
        let data = match data {
            Ok(data) => data,
            Err(err) => {
                eprintln!("error: reading {}: {err}", file.display());
                status = ExitCode::FAILURE;
                continue;
            }
        };
        let hash = if cli.base64 {
            match favicon_hash_base64(&String::from_utf8_lossy(&data)) {
                Ok(hash) => hash,
                Err(err) => {
                    eprintln!("error: {}: {err}", file.display());
                    status = ExitCode::FAILURE;
                    continue;
                }
            }
        } else {
            favicon_hash(&data)
        };
        let value = if cli.shodan {
            shodan_query(hash)
        } else {
            hash.to_string()
        };
        if files.len() > 1 {
            println!("{value}\t{}", file.display());
        } else {
            println!("{value}");
        }
    }
    status
}
