//! `rune-tokenize` command-line tool: approximate token counting, budget checking, text truncation, and overlapping chunk splitting for LLM context windows.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, Read};
use std::process::ExitCode;

use rune_tokenize::{TokenCounter, TokenizerProfile};

const USAGE: &str = "usage: rune-tokenize [-m MODEL|PROFILE] [-b MAX_TOKENS] [FILE|-]

Prints the estimated token count of FILE (or stdin).

  -m, --model NAME   tokenizer profile (simple, cl100k, o200k, claude, llama3,
                     llama2) or a model name such as gpt-4o; default: simple
  -b, --budget N     exit with status 1 if the count exceeds N
  -h, --help         show this help";

fn main() -> ExitCode {
    let mut profile = TokenizerProfile::Simple;
    let mut budget: Option<usize> = None;
    let mut input: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-m" | "--model" | "-p" | "--profile" => {
                let Some(name) = args.next() else {
                    eprintln!("rune-tokenize: {arg} needs a value\n\n{USAGE}");
                    return ExitCode::from(2);
                };
                match name.parse() {
                    Ok(p) => profile = p,
                    Err(e) => {
                        eprintln!("rune-tokenize: {name}: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            "-b" | "--budget" => {
                budget = args.next().and_then(|n| n.parse().ok());
                if budget.is_none() {
                    eprintln!("rune-tokenize: {arg} needs a non-negative integer\n\n{USAGE}");
                    return ExitCode::from(2);
                }
            }
            _ if input.is_none() => input = Some(arg),
            _ => {
                eprintln!("rune-tokenize: unexpected argument {arg}\n\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    let text = match input.as_deref() {
        None | Some("-") => {
            let mut buf = String::new();
            if io::stdin().read_to_string(&mut buf).is_err() {
                eprintln!("rune-tokenize: failed to read stdin");
                return ExitCode::FAILURE;
            }
            buf
        }
        Some(path) => match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("rune-tokenize: {path}: {e}");
                return ExitCode::FAILURE;
            }
        },
    };

    let tokens = profile.count_tokens(&text);
    println!("{tokens}");
    match budget {
        Some(max) if tokens > max => {
            eprintln!("rune-tokenize: {tokens} tokens exceed the budget of {max}");
            ExitCode::FAILURE
        }
        _ => ExitCode::SUCCESS,
    }
}
