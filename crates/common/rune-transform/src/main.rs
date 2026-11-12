//! `rune-transform` command-line tool: run bytes through a chain of named
//! transforms, Burp Decoder style.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::{self, Read, Write};
use std::process::ExitCode;

use clap::Parser;
use rune_transform::{TransformRegistry, smart_decode};

/// Run bytes through a chain of named transforms (encode, decode, hash,
/// compress).
#[derive(Parser)]
#[command(name = "rune-transform", version, about)]
struct Cli {
    /// Step specs in order, e.g. `base64:decode gzip:decode` or `"sha256|hex"`.
    chain: Vec<String>,
    /// Input text; read from stdin when omitted.
    #[arg(short, long)]
    input: Option<String>,
    /// Run the chain backwards (decode every step, last step first).
    #[arg(short, long)]
    reverse: bool,
    /// Peel layered base64/URL/hex encodings off the input instead.
    #[arg(long, conflicts_with_all = ["chain", "reverse"])]
    smart: bool,
    /// List the built-in transforms and exit.
    #[arg(short, long, conflicts_with_all = ["chain", "reverse", "smart"])]
    list: bool,
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), String> {
    let registry = TransformRegistry::builtin();
    if cli.list {
        for transform in registry.iter() {
            let way = if transform.is_reversible() {
                "<->"
            } else {
                " ->"
            };
            println!(
                "{:<20} {way} {:<12} {}",
                transform.id(),
                transform.category(),
                transform.description()
            );
        }
        return Ok(());
    }

    let input = if let Some(text) = &cli.input {
        text.clone().into_bytes()
    } else {
        let mut buffer = Vec::new();
        io::stdin()
            .read_to_end(&mut buffer)
            .map_err(|error| format!("reading stdin: {error}"))?;
        buffer
    };

    if cli.smart {
        let text = String::from_utf8_lossy(&input);
        for step in smart_decode(text.trim_end_matches(['\r', '\n'])) {
            println!("{:<14} {}", step.transform, step.output);
        }
        return Ok(());
    }

    let chain = registry
        .parse_chain(&cli.chain.join(" "))
        .map_err(|error| error.to_string())?;
    let output = if cli.reverse {
        chain.decode(&input)
    } else {
        chain.encode(&input)
    }
    .map_err(|error| error.to_string())?;
    io::stdout()
        .write_all(&output)
        .map_err(|error| format!("writing stdout: {error}"))
}
