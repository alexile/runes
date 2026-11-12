//! `rune-cors` command-line tool: analyze the CORS headers of a response,
//! or print the probe origins to send.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::Read;
use std::process::ExitCode;

use clap::Parser;
use rune_cors::{CorsHeaders, Exchange, Options, Origin, probes, run};

/// Analyze CORS response headers for dangerous origin, credential and
/// allowlist combinations.
///
/// Headers come from `-H` or, when none are given, from a raw response
/// header block on stdin (e.g. `curl -sI -H 'Origin: …' URL`).
#[derive(Parser)]
#[command(name = "rune-cors", version, about)]
struct Cli {
    /// Origin of the site under test, e.g. `https://example.com`.
    #[arg(long)]
    target: Option<Origin>,
    /// An origin the site deliberately shares with (repeatable).
    #[arg(long = "trusted", value_name = "ORIGIN")]
    trusted: Vec<Origin>,
    /// Treat subdomains of the target and trusted origins as trusted.
    #[arg(long)]
    trust_subdomains: bool,
    /// The Origin header the request carried.
    #[arg(long)]
    origin: Option<String>,
    /// A response header, `Name: value` (repeatable).
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    headers: Vec<String>,
    /// Print the probe origins for --target and exit.
    #[arg(long, requires = "target")]
    probes: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.probes {
        for p in cli.target.as_ref().map(probes).unwrap_or_default() {
            println!("{:<18} {}", p.class.as_str(), p.origin);
        }
        return ExitCode::SUCCESS;
    }
    let headers = if cli.headers.is_empty() {
        let mut buf = String::new();
        if let Err(err) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("error: reading stdin: {err}");
            return ExitCode::FAILURE;
        }
        CorsHeaders::parse_block(&buf)
    } else {
        CorsHeaders::parse_block(&cli.headers.join("\n"))
    };
    let mut options = Options::default().with_trust_subdomains(cli.trust_subdomains);
    options.target = cli.target;
    options.trusted = cli.trusted;
    let report = run(&[Exchange::new(cli.origin.as_deref(), headers)], &options);
    for row in &report.rows {
        println!(
            "origin={} class={} reflected={} exposure={}",
            row.origin.as_deref().unwrap_or("-"),
            row.class.map_or("-", |c| c.as_str()),
            row.reflected,
            row.exposure
        );
    }
    for w in &report.weaknesses {
        println!(
            "{:<13} {:<36} {}",
            w.severity.as_str(),
            w.kind.check_id(),
            w.message
        );
    }
    ExitCode::SUCCESS
}
