//! `rune-wellknown` command-line tool: parse a saved `/.well-known`
//! resource and print its model.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_wellknown::{WellKnown, parse_body};

/// Parse a saved /.well-known resource (security.txt, mta-sts.txt,
/// openid-configuration, assetlinks.json, apple-app-site-association) and
/// print the typed model. Nothing is fetched.
#[derive(Parser)]
#[command(name = "rune-wellknown", version, about)]
struct Cli {
    /// Resource name or path, e.g. `mta-sts.txt` or `/.well-known/assetlinks.json`.
    resource: String,
    /// File holding the body; read from stdin when omitted or `-`.
    file: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Some(kind) = WellKnown::from_path(&cli.resource) else {
        let names: Vec<_> = WellKnown::ALL.iter().map(|k| k.name()).collect();
        eprintln!(
            "error: unknown resource {:?}; expected one of {}",
            cli.resource,
            names.join(", ")
        );
        return ExitCode::FAILURE;
    };
    let text = match &cli.file {
        Some(path) if path.as_os_str() != "-" => std::fs::read_to_string(path),
        _ => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf).map(|_| buf)
        }
    };
    let text = match text {
        Ok(t) => t,
        Err(err) => {
            eprintln!("error: reading input: {err}");
            return ExitCode::FAILURE;
        }
    };
    match parse_body(kind, &text) {
        Ok(resource) => {
            println!("{resource:#?}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
