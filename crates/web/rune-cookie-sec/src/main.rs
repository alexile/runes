//! `rune-cookie-sec` command-line tool: analyze `Set-Cookie` header values.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::Read;
use std::process::ExitCode;
use std::time::SystemTime;

use clap::Parser;
use rune_cookie_sec::{Options, run_fields};

/// Analyze Set-Cookie header values for weak security attributes.
#[derive(Parser)]
#[command(name = "rune-cookie-sec", version, about)]
struct Cli {
    /// Set-Cookie values to analyze; read from stdin (one per line) when
    /// omitted.
    headers: Vec<String>,
    /// URL of the request that received the cookies (checks Domain and the
    /// transport).
    #[arg(long)]
    url: Option<url::Url>,
    /// The cookies came over plain HTTP.
    #[arg(long)]
    http: bool,
    /// Treat every cookie as a session cookie.
    #[arg(long)]
    sensitive: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let headers = if cli.headers.is_empty() {
        let mut buf = String::new();
        if let Err(err) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("error: reading stdin: {err}");
            return ExitCode::FAILURE;
        }
        buf.lines()
            .map(|l| {
                let l = l.trim();
                // Accept whole header lines too.
                l.split_once(':')
                    .filter(|(name, _)| name.trim().eq_ignore_ascii_case("set-cookie"))
                    .map_or(l, |(_, v)| v.trim())
                    .to_owned()
            })
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        cli.headers
    };
    let mut options = Options::default()
        .with_now(SystemTime::now())
        .with_all_sensitive(cli.sensitive);
    if let Some(url) = cli.url {
        options = options.with_request_url(url);
    }
    if cli.http {
        options = options.with_https(false);
    }
    let report = run_fields(headers.iter().map(String::as_str), &options);
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
