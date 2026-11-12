//! `rune-url-encode` command-line tool: uRL percent-encoding and decoding for byte slices and strings.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use rune_url_encode::{decode, encode};
use std::env;
use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    let (is_decode, inputs) = match args.as_slice() {
        [_, flag, rest @ ..] if flag == "-d" || flag == "--decode" => (true, rest.to_vec()),
        [_, rest @ ..] => (false, rest.to_vec()),
        _ => {
            eprintln!("usage: rune-url-encode [-d] <value|-> [value ...]");
            return ExitCode::FAILURE;
        }
    };

    let inputs = if inputs.is_empty() {
        let mut data = String::new();
        if io::stdin().read_to_string(&mut data).is_err() {
            eprintln!("rune-url-encode: failed to read stdin");
            return ExitCode::FAILURE;
        }
        vec![data.trim_end_matches('\n').to_owned()]
    } else {
        inputs
    };

    let mut any_error = false;

    for input in &inputs {
        if is_decode {
            match decode(input) {
                Ok(output) => println!("{output}"),
                Err(err) => {
                    eprintln!("rune-url-encode: {err}");
                    any_error = true;
                }
            }
        } else {
            println!("{}", encode(input));
        }
    }

    if any_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
