//! `rune-referrer-policy` command-line tool: analyze a Referrer-Policy
//! header value or a referrer meta value.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::Read;
use std::process::ExitCode;

use clap::Parser;
use rune_referrer_policy::{Options, RequestKind, run, run_meta};

/// Analyze a Referrer-Policy header value and flag leak-prone policies.
/// Nothing is fetched: pass the header value.
#[derive(Parser)]
#[command(name = "rune-referrer-policy", version, about)]
struct Cli {
    /// Header value to analyze; read from stdin when omitted.
    header: Option<String>,
    /// The value is a `<meta name="referrer">` content attribute.
    #[arg(long)]
    meta: bool,
    /// The page makes no cross-origin requests or links.
    #[arg(long)]
    same_origin_only: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let value = if let Some(h) = cli.header {
        h
    } else {
        let mut buf = String::new();
        if let Err(err) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("error: reading stdin: {err}");
            return ExitCode::FAILURE;
        }
        buf
    };
    let options = Options::default().with_cross_origin(!cli.same_origin_only);
    let report = if cli.meta {
        run_meta(value.trim(), &options)
    } else {
        run(value.trim(), &options)
    };
    let policy = report.effective();
    let sent: Vec<String> = RequestKind::ALL
        .iter()
        .map(|k| format!("{k:?}={:?}", policy.referrer(*k)))
        .collect();
    let default_note = if report.policy.is_some() {
        ""
    } else {
        " (browser default)"
    };
    println!("{policy}{default_note}: {}", sent.join(" "));
    for w in &report.weaknesses {
        println!(
            "{:<13} {:<38} {}",
            w.severity.as_str(),
            w.kind.check_id(),
            w.message
        );
    }
    ExitCode::SUCCESS
}
