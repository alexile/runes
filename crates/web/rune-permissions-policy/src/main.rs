//! `rune-permissions-policy` command-line tool: analyze a
//! Permissions-Policy (or legacy Feature-Policy) header value.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::Read;
use std::process::ExitCode;

use clap::Parser;
use rune_permissions_policy::{Options, RECOMMENDED_RESTRICTED, run, run_feature_policy};

/// Analyze a Permissions-Policy header value and flag over-permissive
/// grants. Nothing is fetched: pass the header value.
#[derive(Parser)]
#[command(name = "rune-permissions-policy", version, about)]
struct Cli {
    /// Header value to analyze; read from stdin when omitted.
    header: Option<String>,
    /// The value is a legacy Feature-Policy header.
    #[arg(long)]
    feature_policy: bool,
    /// Also require camera, microphone, geolocation, payment, usb and
    /// display-capture to be declared.
    #[arg(long)]
    strict: bool,
    /// Print the policy converted to Permissions-Policy syntax.
    #[arg(long)]
    migrate: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let header = if let Some(h) = cli.header {
        h
    } else {
        let mut buf = String::new();
        if let Err(err) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("error: reading stdin: {err}");
            return ExitCode::FAILURE;
        }
        buf
    };
    let mut options = Options::default();
    if cli.strict {
        options = options.with_restricted_features(RECOMMENDED_RESTRICTED.iter().copied());
    }
    let report = if cli.feature_policy {
        run_feature_policy(header.trim(), &options)
    } else {
        run(header.trim(), &options)
    };
    match (&report.policy, &report.error) {
        (Some(p), _) if cli.migrate => println!("{}", p.to_permissions_policy()),
        (Some(p), _) => println!("{p}"),
        (None, Some(e)) => println!("invalid: {e}"),
        (None, None) => {}
    }
    for w in &report.weaknesses {
        println!(
            "{:<13} {:<42} {}",
            w.severity.as_str(),
            w.kind.check_id(),
            w.message
        );
    }
    ExitCode::SUCCESS
}
