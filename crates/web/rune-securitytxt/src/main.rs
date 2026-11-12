//! `rune-securitytxt` command-line tool: validate a security.txt file
//! against RFC 9116.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use rune_securitytxt::{Options, Timestamp, run};

/// Validate a security.txt file (RFC 9116). Nothing is fetched: pass the
/// file, or pipe it in.
#[derive(Parser)]
#[command(name = "rune-securitytxt", version, about)]
struct Cli {
    /// File to validate; read from stdin when omitted or `-`.
    file: Option<PathBuf>,
    /// The URL the file was retrieved from, checked against Canonical.
    #[arg(long, value_name = "URL")]
    url: Option<String>,
    /// Check expiry against this RFC 3339 time instead of the clock.
    #[arg(long, value_name = "DATE-TIME")]
    now: Option<String>,
    /// Treat a missing signature as a low-severity weakness.
    #[arg(long)]
    require_signature: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let text = match &cli.file {
        Some(path) if path.as_os_str() != "-" => match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(err) => {
                eprintln!("error: reading {}: {err}", path.display());
                return ExitCode::FAILURE;
            }
        },
        _ => {
            let mut buf = String::new();
            if let Err(err) = std::io::stdin().read_to_string(&mut buf) {
                eprintln!("error: reading stdin: {err}");
                return ExitCode::FAILURE;
            }
            buf
        }
    };
    let now = match &cli.now {
        Some(s) => match Timestamp::parse(s) {
            Ok(t) => t,
            Err(err) => {
                eprintln!("error: --now: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => Timestamp::from_unix_seconds(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
        ),
    };
    let mut options = Options::default()
        .with_now(now)
        .with_require_signature(cli.require_signature);
    if let Some(url) = cli.url {
        options = options.with_retrieved_from(url);
    }
    let report = run(&text, &options);
    if let Some(doc) = &report.security_txt {
        for contact in doc.contacts() {
            println!("contact  {contact}");
        }
        if let Some(expires) = doc.expires() {
            println!("expires  {expires}");
        }
        println!("signed   {}", if doc.is_signed() { "yes" } else { "no" });
    }
    for w in &report.weaknesses {
        let line = w.line.map(|l| format!("line {l}: ")).unwrap_or_default();
        println!(
            "{:<13} {:<34} {line}{}",
            w.severity.as_str(),
            w.kind.check_id(),
            w.message
        );
    }
    if report.is_valid() {
        println!("valid");
        ExitCode::SUCCESS
    } else {
        println!("invalid");
        ExitCode::FAILURE
    }
}
