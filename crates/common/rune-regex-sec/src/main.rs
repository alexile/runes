//! `rune-regex-sec` command-line tool: security-focused regex patterns for detecting IPs, CVEs, hashes, secrets, and PII in text.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use rune_regex_sec::scan;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("usage: rune-regex-sec <file|-> [file ...]");
        return ExitCode::FAILURE;
    }

    let mut any_error = false;

    for path in &args[1..] {
        let text = match read_input(path) {
            Ok(t) => t,
            Err(err) => {
                eprintln!("rune-regex-sec: {path}: {err}");
                any_error = true;
                continue;
            }
        };

        for finding in scan(&text) {
            println!("{}\t{}\t{}", path, finding.category, finding.value);
        }
    }

    if any_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn read_input(path: &str) -> io::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        Ok(fs::read_to_string(path)?)
    }
}
