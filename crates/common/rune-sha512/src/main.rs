//! `rune-sha512` command-line tool: compute SHA-512 hashes of byte slices and files.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use rune_sha512::{hash_bytes, hash_file};
use std::{
    io::{self, Read},
    process::ExitCode,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return hash_stdin();
    }
    let mut failed = false;
    for target in &args {
        if target == "-" {
            if hash_stdin() == ExitCode::FAILURE {
                failed = true;
            }
        } else {
            match hash_file(target) {
                Ok(digest) => println!("{digest}  {target}"),
                Err(error) => {
                    eprintln!("rune-sha512: {target}: {error}");
                    failed = true;
                }
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn hash_stdin() -> ExitCode {
    let mut buffer = Vec::new();
    if let Err(error) = io::stdin().read_to_end(&mut buffer) {
        eprintln!("rune-sha512: {error}");
        return ExitCode::FAILURE;
    }
    println!("{}  -", hash_bytes(&buffer));
    ExitCode::SUCCESS
}
