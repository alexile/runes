//! `rune-xxhash` command-line tool: xxHash (xxh32 / xxh64) — extremely fast non-cryptographic hash, pure Rust.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_xxhash::{xxh32, xxh64};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

/// xxHash (xxh32 / xxh64) — extremely fast non-cryptographic hash.
#[derive(Parser)]
#[command(name = "rune-xxhash", version, author)]
struct Args {
    /// Files to hash. Use `-` for stdin.
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Use 32-bit xxh32 instead of the default 64-bit xxh64.
    #[arg(long)]
    x32: bool,

    /// Seed value (u64 for xxh64, truncated to u32 for xxh32).
    #[arg(long, default_value_t = 0)]
    seed: u64,
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
fn main() -> ExitCode {
    let args = Args::parse();

    let inputs: Vec<(String, Vec<u8>)> = if args.files.is_empty() {
        let mut buf = Vec::new();
        if io::stdin().read_to_end(&mut buf).is_err() {
            eprintln!("error: could not read stdin");
            return ExitCode::FAILURE;
        }
        vec![("stdin".to_string(), buf)]
    } else {
        let mut inputs = Vec::new();
        for path in &args.files {
            if path.as_os_str() == "-" {
                let mut buf = Vec::new();
                if io::stdin().read_to_end(&mut buf).is_err() {
                    eprintln!("error: could not read stdin");
                    return ExitCode::FAILURE;
                }
                inputs.push(("stdin".to_string(), buf));
            } else {
                match fs::read(path) {
                    Ok(bytes) => inputs.push((path.display().to_string(), bytes)),
                    Err(e) => {
                        eprintln!("error: {}: {e}", path.display());
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
        inputs
    };

    for (name, data) in &inputs {
        if args.x32 {
            let hash = xxh32(data, args.seed as u32);
            println!("{hash:08x}  {name}");
        } else {
            let hash = xxh64(data, args.seed);
            println!("{hash:016x}  {name}");
        }
    }

    ExitCode::SUCCESS
}
