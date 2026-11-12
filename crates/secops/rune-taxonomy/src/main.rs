//! `rune-taxonomy` command-line tool: resolve CWE, CAPEC, ATT&CK, OWASP and
//! ASVS ids against the embedded datasets.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::process::ExitCode;

use clap::Parser;
use rune_finding::Taxonomy;
use rune_taxonomy::Entry;

/// Resolve security taxonomy ids (CWE-79, CAPEC-66, T1059.007, A03:2021,
/// API1:2023, V5.3.4) and print their names and mappings. Exits with status
/// 1 if any id is malformed or unknown.
#[derive(Parser)]
#[command(name = "rune-taxonomy", version, about)]
struct Cli {
    /// Ids to resolve. The taxonomy is inferred from the notation; ASVS ids
    /// are looked up in the edition given by --asvs.
    #[arg(required = true)]
    ids: Vec<String>,
    /// ASVS edition for `V…` ids: 4 (4.0.3) or 5 (5.0.0).
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u8).range(4..=5))]
    asvs: u8,
    /// Print the embedded dataset versions and exit.
    #[arg(long, exclusive = true)]
    sources: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.sources {
        for source in rune_taxonomy::sources() {
            println!("{}\t{}", source.dataset, source.version);
        }
        return ExitCode::SUCCESS;
    }
    let asvs = if cli.asvs == 4 {
        Taxonomy::Asvs4
    } else {
        Taxonomy::Asvs5
    };
    let mut failed = false;
    for id in &cli.ids {
        match rune_taxonomy::resolve_id(&infer(id, &asvs), id) {
            Ok(entry) => print_entry(entry),
            Err(err) => {
                eprintln!("{id}: {err}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// The taxonomy an id's notation belongs to.
fn infer(id: &str, asvs: &Taxonomy) -> Taxonomy {
    if id.starts_with("CWE-") {
        Taxonomy::Cwe
    } else if id.starts_with("CAPEC-") {
        Taxonomy::Capec
    } else if id.starts_with('V') {
        asvs.clone()
    } else if id.starts_with('T') {
        Taxonomy::Attack
    } else {
        rune_finding::TaxonomyRef::owasp(id).framework
    }
}

fn print_entry(entry: Entry) {
    println!("{}\t{}", entry.id(), entry.name().unwrap_or("-"));
    let line = |label: &str, ids: Vec<String>| {
        if !ids.is_empty() {
            println!("  {label}: {}", ids.join(", "));
        }
    };
    match entry {
        Entry::Cwe(cwe) => {
            line(
                "parents",
                cwe.parents.iter().map(ToString::to_string).collect(),
            );
            line("owasp", cwe.owasp.iter().map(ToString::to_string).collect());
            line("capec", cwe.capec.iter().map(ToString::to_string).collect());
        }
        Entry::Capec(capec) => {
            line("cwe", capec.cwes.iter().map(ToString::to_string).collect());
            line(
                "attack",
                capec.attack.iter().map(ToString::to_string).collect(),
            );
        }
        Entry::Technique(technique) => {
            line(
                "tactics",
                technique
                    .tactics
                    .iter()
                    .map(|t| t.name.to_owned())
                    .collect(),
            );
            line(
                "capec",
                technique.capec.iter().map(ToString::to_string).collect(),
            );
        }
        Entry::Owasp(category) => {
            line(
                "cwe",
                category.cwes.iter().map(ToString::to_string).collect(),
            );
        }
        Entry::Asvs(item) => {
            line(
                "level",
                item.level.iter().map(|l| format!("L{l}")).collect(),
            );
            line("cwe", item.cwes.iter().map(ToString::to_string).collect());
        }
        _ => {}
    }
}
