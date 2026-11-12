//! `rune-x509` command-line tool: summarize certificates and validate a chain.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use rune_x509::{Certificate, Policy, Purpose, TrustStore, VerifyOptions, parse_pem, verify_chain};

/// Summarize X.509 certificates; with --roots, validate the chain.
#[derive(Parser)]
#[command(name = "rune-x509", version, about)]
struct Cli {
    /// PEM bundle (leaf first, then intermediates) or a single DER file.
    certs: PathBuf,
    /// PEM bundle of trust anchors; validates the chain against it.
    #[arg(long)]
    roots: Option<PathBuf>,
    /// Host name or IP address the leaf must cover.
    #[arg(long)]
    host: Option<String>,
    /// Validation time in Unix seconds (default: now).
    #[arg(long)]
    time: Option<i64>,
    /// Validate for a TLS client (mTLS) instead of a server.
    #[arg(long)]
    client: bool,
}

fn read_certs(path: &Path) -> Result<Vec<Certificate>, String> {
    let bytes = std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let certs = if bytes.starts_with(b"-----") || bytes.windows(11).any(|w| w == b"-----BEGIN ") {
        parse_pem(&bytes)
    } else {
        Certificate::from_der(&bytes).map(|cert| vec![cert])
    };
    certs.map_err(|err| format!("{}: {err}", path.display()))
}

fn print_summary(index: usize, cert: &Certificate) {
    let s = cert.summary();
    println!("[{index}] {}", s.subject);
    println!("    issuer:      {}", s.issuer);
    println!("    serial:      {}", s.serial);
    println!(
        "    validity:    {} .. {} (unix)",
        s.not_before, s.not_after
    );
    println!("    key:         {}", s.public_key);
    println!("    signature:   {}", s.signature_algorithm);
    if !s.subject_alt_names.is_empty() {
        let sans: Vec<String> = s
            .subject_alt_names
            .iter()
            .map(ToString::to_string)
            .collect();
        println!("    SANs:        {}", sans.join(", "));
    }
    println!("    CA:          {}", s.is_ca());
    println!("    self-signed: {}", s.self_signed);
    println!("    SCTs:        {}", s.sct_count);
    println!("    SHA-256:     {}", s.sha256_fingerprint_hex());
    for weakness in cert.weaknesses(&Policy::default()) {
        println!("    weakness:    {weakness}");
    }
}

fn run(cli: &Cli) -> Result<bool, String> {
    let certs = read_certs(&cli.certs)?;
    let Some((leaf, intermediates)) = certs.split_first() else {
        return Err(format!("{}: no certificate", cli.certs.display()));
    };
    for (index, cert) in certs.iter().enumerate() {
        print_summary(index, cert);
    }
    let Some(roots) = &cli.roots else {
        return Ok(true);
    };
    let store: TrustStore = read_certs(roots)?.into_iter().collect();
    let mut options = VerifyOptions::default();
    if let Some(time) = cli.time {
        options = options.with_time(time);
    }
    if let Some(host) = &cli.host {
        options = options.with_hostname(host.clone());
    }
    if cli.client {
        options = options.with_purpose(Purpose::ClientAuth);
    }
    let report = verify_chain(leaf, intermediates, &store, &options);
    println!();
    let path: Vec<&str> = report
        .path
        .iter()
        .map(|cert| cert.summary().subject.as_str())
        .collect();
    println!("path: {}", path.join(" <- "));
    for issue in &report.issues {
        println!("{:?}: {issue}", issue.severity());
    }
    let trusted = report.is_trusted();
    println!("{}", if trusted { "trusted" } else { "NOT trusted" });
    Ok(trusted)
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}
