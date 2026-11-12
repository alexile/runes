//! `rune-fnv` command-line tool: fNV-1 and FNV-1a hash functions for byte slices and strings (32 and 64-bit).

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use rune_fnv::fnv1a_64;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("usage: rune-fnv <file|-> [file ...]");
        return ExitCode::FAILURE;
    }

    let mut any_error = false;

    for path in &args[1..] {
        match compute(path) {
            Ok(hash) => println!("{hash:016x}  {path}"),
            Err(err) => {
                eprintln!("rune-fnv: {path}: {err}");
                any_error = true;
            }
        }
    }

    if any_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn compute(path: &str) -> io::Result<u64> {
    let data = if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        fs::read(path)?
    };
    Ok(fnv1a_64(&data))
}
