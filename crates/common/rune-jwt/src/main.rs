//! `rune-jwt` command-line tool: decode and inspect JWT claims without verification — tear open any token for debugging and CTF work.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use rune_jwt::decode;
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("usage: rune-jwt <token>");
        return ExitCode::FAILURE;
    }

    let token = &args[1];

    match decode(token) {
        Ok(decoded) => {
            println!("=== Header ===");
            println!("{}", pretty_json(&decoded.header));
            println!("\n=== Payload ===");
            println!("{}", pretty_json(&decoded.payload));
            println!("\n=== Signature ===");
            println!("{}", decoded.signature);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("rune-jwt: {err}");
            ExitCode::FAILURE
        }
    }
}

fn pretty_json(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}
