//! `rune-hsts` command-line tool: analyze a Strict-Transport-Security
//! header, check preload eligibility, and look a host up in a preload list.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_hsts::{HttpBehavior, Options, PreloadList, Site, check_preload, run};

/// Analyze a Strict-Transport-Security header value and check HSTS preload
/// eligibility. Nothing is fetched: pass the header and observations.
#[derive(Parser)]
#[command(name = "rune-hsts", version, about)]
struct Cli {
    /// Header value to analyze; read from stdin when omitted.
    header: Option<String>,
    /// The header came over plain HTTP.
    #[arg(long)]
    http: bool,
    /// Check preload eligibility of this domain, using the header as its
    /// HTTPS response header.
    #[arg(long, value_name = "DOMAIN")]
    preload: Option<String>,
    /// With --preload: the Location that `http://DOMAIN/` redirects to.
    #[arg(long, value_name = "URL", requires = "preload")]
    http_redirect: Option<String>,
    /// With --preload: `http://DOMAIN/` answers without redirecting.
    #[arg(long, requires = "preload", conflicts_with = "http_redirect")]
    http_no_redirect: bool,
    /// Look the host up in a preload list: a plain domain list, or
    /// Chromium's `transport_security_state_static.json` (`.json`).
    #[arg(long, value_name = "FILE", requires = "lookup")]
    list: Option<PathBuf>,
    /// With --list: the host to look up.
    #[arg(long, value_name = "HOST", requires = "list")]
    lookup: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let (Some(path), Some(host)) = (&cli.list, &cli.lookup) {
        return lookup(path, host);
    }
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
    let header = header.trim();
    let report = run(
        header,
        &Options::default().with_insecure_transport(cli.http),
    );
    match (&report.hsts, &report.error) {
        (Some(h), _) => println!("{h}"),
        (None, Some(e)) => println!("invalid: {e}"),
        (None, None) => {}
    }
    for w in &report.weaknesses {
        println!(
            "{:<13} {:<32} {}",
            w.severity.as_str(),
            w.kind.check_id(),
            w.message
        );
    }
    if let Some(domain) = cli.preload {
        let http = match (cli.http_redirect, cli.http_no_redirect) {
            (Some(location), _) => HttpBehavior::Redirect { location },
            (None, true) => HttpBehavior::NoRedirect,
            (None, false) => HttpBehavior::Unknown,
        };
        let e = check_preload(&Site::new(domain).with_https_header(header).with_http(http));
        if e.is_eligible() {
            println!("{}: preload-eligible", e.domain);
        } else {
            println!("{}: not preload-eligible", e.domain);
            for i in &e.issues {
                println!("  {:<38} {}", i.kind.check_id(), i.message);
            }
        }
    }
    ExitCode::SUCCESS
}

fn lookup(path: &PathBuf, host: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("error: reading {}: {err}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let list = if path.extension().is_some_and(|e| e == "json") {
        PreloadList::from_chromium_json(&text)
    } else {
        PreloadList::parse(&text)
    };
    let list = match list {
        Ok(l) => l,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    match list.lookup(host) {
        Some(m) if m.is_hsts() => {
            let how = if m.exact {
                "exact entry"
            } else {
                "includeSubDomains"
            };
            println!("{host}: preloaded via {} ({how})", m.entry.name);
            ExitCode::SUCCESS
        }
        Some(m) => {
            println!("{host}: listed via {} without force-https", m.entry.name);
            ExitCode::from(1)
        }
        None => {
            println!("{host}: not preloaded");
            ExitCode::from(1)
        }
    }
}
