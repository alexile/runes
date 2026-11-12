//! `rune-rdap` command-line tool: look up a domain, IP address or network,
//! ASN, nameserver or entity handle over RDAP and print a summary.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::process::ExitCode;

use clap::Parser;
use rune_rdap::client::{Client, Options, ReqwestFetcher};
use rune_rdap::model::{Entity, Event, Role, Status};
use rune_rdap::{Object, Query};

/// Look up registration data over RDAP (IANA bootstrap, RFC 9224).
#[derive(Parser)]
#[command(name = "rune-rdap", version, about)]
struct Cli {
    /// Domain, IP address, CIDR block, AS number (AS15169) or entity handle.
    query: Vec<String>,
    /// Where to fetch the bootstrap files from.
    #[arg(long, default_value = rune_rdap::bootstrap::IANA_BASE)]
    bootstrap: String,
    /// Look the names up as nameservers rather than domains.
    #[arg(long)]
    nameserver: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> ExitCode {
    let fetcher = match ReqwestFetcher::new() {
        Ok(f) => f,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let client = Client::new(
        fetcher,
        Options::default().with_bootstrap_base(cli.bootstrap),
    );
    let mut status = ExitCode::SUCCESS;
    for input in &cli.query {
        let query = if cli.nameserver {
            Query::nameserver(input)
        } else {
            Query::parse(input)
        };
        let result = match query {
            Ok(q) => client.lookup(&q).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(found) => {
                println!("# {input} ({})", found.final_url);
                print_object(&found.object);
            }
            Err(err) => {
                eprintln!("{input}: error: {err}");
                status = ExitCode::FAILURE;
            }
        }
    }
    status
}

fn print_object(object: &Object) {
    println!("class: {}", object.class_name());
    if let Some(handle) = object.handle() {
        println!("handle: {handle}");
    }
    match object {
        Object::Domain(d) => {
            if let Some(name) = d.name() {
                println!("name: {name}");
            }
            if let Some(r) = d.registrar_name() {
                println!("registrar: {r}");
            }
            for ns in d.nameserver_names() {
                println!("nameserver: {ns}");
            }
        }
        Object::IpNetwork(n) => {
            if let (Some(a), Some(b)) = (&n.start_address, &n.end_address) {
                println!("range: {a} - {b}");
            }
            for c in &n.cidrs {
                println!("cidr: {}/{}", c.prefix, c.length);
            }
            print_opt("name", n.name.as_deref());
            print_opt("country", n.country.as_deref());
        }
        Object::Autnum(a) => {
            if let (Some(s), Some(e)) = (a.start_autnum, a.end_autnum) {
                println!("range: AS{s} - AS{e}");
            }
            print_opt("name", a.name.as_deref());
            print_opt("country", a.country.as_deref());
        }
        Object::Nameserver(n) => print_opt("name", n.name()),
        Object::Entity(e) => print_entity(e),
        _ => {}
    }
    print_status(object.status());
    print_events(object.events());
    for e in object.entities() {
        print_entity(e);
    }
}

fn print_opt(label: &str, value: Option<&str>) {
    if let Some(v) = value {
        println!("{label}: {v}");
    }
}

fn print_status(status: &[Status]) {
    for s in status {
        println!("status: {s}");
    }
}

fn print_events(events: &[Event]) {
    for e in events {
        println!("event: {} {}", e.action, e.date.as_deref().unwrap_or("?"));
    }
}

fn print_entity(e: &Entity) {
    let roles: Vec<&str> = e.roles.iter().map(Role::as_str).collect();
    let name = e
        .contact
        .as_ref()
        .and_then(|c| c.name.as_deref().or(c.org.as_deref()))
        .unwrap_or("");
    println!(
        "entity: [{}] {} {name}",
        roles.join(","),
        e.handle.as_deref().unwrap_or("-")
    );
    if let Some(c) = &e.contact {
        for m in &c.emails {
            println!("  email: {m}");
        }
    }
    for child in &e.entities {
        print_entity(child);
    }
}
