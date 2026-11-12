//! `rune-csp` command-line tool: parse, analyze and canonicalize a
//! Content-Security-Policy header.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::Read;
use std::process::ExitCode;

use clap::Parser;
use rune_csp::{Options, run};

/// Parse, analyze and canonicalize a Content-Security-Policy header value.
#[derive(Parser)]
#[command(name = "rune-csp", version, about)]
struct Cli {
    /// Header value to analyze; read from stdin when omitted.
    policy: Option<String>,
    /// The policy is delivered as Content-Security-Policy-Report-Only.
    #[arg(long)]
    report_only: bool,
    /// Print only the canonical policy.
    #[arg(long)]
    canonical: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let header = if let Some(p) = cli.policy {
        p
    } else {
        let mut buf = String::new();
        if let Err(err) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("error: reading stdin: {err}");
            return ExitCode::FAILURE;
        }
        buf
    };
    let report = run(
        header.trim(),
        &Options::default().with_report_only(cli.report_only),
    );
    println!("{}", report.canonical());
    if cli.canonical {
        return ExitCode::SUCCESS;
    }
    for w in &report.weaknesses {
        println!(
            "{:<13} {:<28} {}",
            w.severity.as_str(),
            w.kind.check_id(),
            w.message
        );
    }
    ExitCode::SUCCESS
}
