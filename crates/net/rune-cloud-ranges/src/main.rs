//! `rune-cloud-ranges` command-line tool: load downloaded cloud/CDN range
//! files and tell which provider (and whether a CDN) serves each address.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_cloud_ranges::{
    CloudRanges, Dataset, Error, Provider, SOURCES, parse_aws, parse_azure, parse_digitalocean,
    parse_fastly, parse_google, parse_oracle,
};

/// Attribute IP addresses to cloud and CDN providers using their published
/// range files (download them first; `--sources` lists the URLs).
#[derive(Parser)]
#[command(name = "rune-cloud-ranges", version, about)]
struct Cli {
    /// Print the official source URLs and exit.
    #[arg(long)]
    sources: bool,
    /// AWS ip-ranges.json.
    #[arg(long)]
    aws: Vec<PathBuf>,
    /// Google cloud.json or goog.json.
    #[arg(long)]
    google: Vec<PathBuf>,
    /// Azure Service Tags JSON.
    #[arg(long)]
    azure: Vec<PathBuf>,
    /// Cloudflare ips-v4 / ips-v6 list.
    #[arg(long)]
    cloudflare: Vec<PathBuf>,
    /// Fastly public-ip-list JSON.
    #[arg(long)]
    fastly: Vec<PathBuf>,
    /// Oracle `public_ip_ranges.json`.
    #[arg(long)]
    oracle: Vec<PathBuf>,
    /// `DigitalOcean` geofeed CSV.
    #[arg(long)]
    digitalocean: Vec<PathBuf>,
    /// Any CIDR-per-line list, as NAME=FILE (NAME `akamai` marks it as CDN).
    #[arg(long, value_name = "NAME=FILE")]
    list: Vec<String>,
    /// Addresses to look up.
    #[arg(required_unless_present = "sources")]
    addrs: Vec<IpAddr>,
}

fn load(
    table: &mut CloudRanges,
    paths: &[PathBuf],
    parse: impl Fn(&str) -> Result<Dataset, Error>,
) -> Result<(), String> {
    for path in paths {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let dataset = parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        table.extend(dataset.ranges);
    }
    Ok(())
}

fn build(cli: &Cli) -> Result<CloudRanges, String> {
    let mut table = CloudRanges::new();
    load(&mut table, &cli.aws, parse_aws)?;
    load(&mut table, &cli.google, parse_google)?;
    load(&mut table, &cli.azure, parse_azure)?;
    load(&mut table, &cli.fastly, parse_fastly)?;
    load(&mut table, &cli.oracle, parse_oracle)?;
    load(&mut table, &cli.digitalocean, parse_digitalocean)?;
    load(&mut table, &cli.cloudflare, |t| {
        rune_cloud_ranges::parse_cidr_list(t, &Provider::Cloudflare)
    })?;
    for spec in &cli.list {
        let (name, path) = spec
            .split_once('=')
            .ok_or_else(|| format!("--list {spec:?}: expected NAME=FILE"))?;
        let provider = match name {
            "akamai" => Provider::Akamai,
            other => Provider::Other(other.to_owned()),
        };
        load(&mut table, &[PathBuf::from(path)], |t| {
            rune_cloud_ranges::parse_cidr_list(t, &provider)
        })?;
    }
    Ok(table)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.sources {
        for s in SOURCES {
            let note = if s.direct { "" } else { "\t(download page)" };
            println!("{}\t{}{note}", s.provider, s.url);
        }
        return ExitCode::SUCCESS;
    }
    let table = match build(&cli) {
        Ok(table) => table,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    for &ip in &cli.addrs {
        let hits = table.longest(ip);
        let Some(first) = hits.first() else {
            println!("{ip}\t-");
            continue;
        };
        let services: Vec<&str> = hits.iter().filter_map(|r| r.service.as_deref()).collect();
        println!(
            "{ip}\t{}\t{}\tregion={}\tservice={}\tcdn={}",
            first.provider,
            first.prefix,
            first.region.as_deref().unwrap_or("-"),
            if services.is_empty() {
                "-".to_owned()
            } else {
                services.join(",")
            },
            table.is_cdn(ip),
        );
    }
    ExitCode::SUCCESS
}
