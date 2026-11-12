//! `rune-murmur` command-line tool: murmurHash3 — pure-Rust implementation of the 32-bit and 128-bit variants.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_murmur::{murmurhash3_x64_128, murmurhash3_x86_32};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

/// `MurmurHash3` — 32-bit and 128-bit non-cryptographic hash.
#[derive(Parser)]
#[command(name = "rune-murmur", version, author)]
struct Args {
    /// Files to hash. Use `-` for stdin.
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Compute 128-bit hash (`MurmurHash3_x64_128`) instead of 32-bit.
    #[arg(long)]
    x128: bool,

    /// Seed value.
    #[arg(long, default_value_t = 0)]
    seed: u32,
}

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
        if args.x128 {
            let hash = murmurhash3_x64_128(data, args.seed);
            let lo = (hash & 0xffff_ffff_ffff_ffff) as u64;
            let hi = (hash >> 64) as u64;
            println!("{lo:016x}{hi:016x}  {name}");
        } else {
            let hash = murmurhash3_x86_32(data, args.seed);
            println!("{hash:08x}  {name}");
        }
    }

    ExitCode::SUCCESS
}
