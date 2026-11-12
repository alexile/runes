//! `rune-crc32` command-line tool: compute CRC-32 checksums of byte slices and files (IEEE 802.3 / Ethernet polynomial).

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use rune_crc32::{checksum, checksum_file};
use std::env;
use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("usage: rune-crc32 <file|-> [file ...]");
        return ExitCode::FAILURE;
    }

    let mut any_error = false;

    for path in &args[1..] {
        match compute(path) {
            Ok(crc) => println!("{crc:08x}  {path}"),
            Err(err) => {
                eprintln!("rune-crc32: {path}: {err}");
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

fn compute(path: &str) -> io::Result<u32> {
    if path == "-" {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;
        Ok(checksum(&data))
    } else {
        checksum_file(path)
    }
}
