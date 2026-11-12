//! `rune-idna` command-line tool: convert internationalized domain names
//! and check them for homographs.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rune_idna::{
    AsciiRules, DomainReport, Error, LookalikeIndex, Options, SpoofPolicy, confusable_kind,
    punycode, skeleton,
};

/// Convert internationalized domain names and check them for homographs.
#[derive(Parser)]
#[command(name = "rune-idna", version, about)]
struct Cli {
    /// Use the registration profile: hyphen checks and the IDNA2008 repertoire.
    #[arg(long, global = true)]
    registration: bool,
    /// Allow `_` and other ASCII outside letters, digits and hyphens.
    #[arg(long, global = true)]
    no_std3: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Convert to the ASCII form (UTS #46 `ToASCII`).
    ToAscii {
        /// Domain names.
        domains: Vec<String>,
    },
    /// Convert to the Unicode form (UTS #46 `ToUnicode`).
    ToUnicode {
        /// Domain names.
        domains: Vec<String>,
    },
    /// Punycode-encode one label (no `xn--` prefix).
    Encode {
        /// Label.
        label: String,
    },
    /// Decode one Punycode label (no `xn--` prefix).
    Decode {
        /// Label.
        label: String,
    },
    /// Print the UTS #39 skeleton of strings.
    Skeleton {
        /// Strings.
        strings: Vec<String>,
    },
    /// Analyse domains for homographs; exits 1 if any is suspicious.
    Check {
        /// Domain names.
        domains: Vec<String>,
        /// Known domain names to look for look-alikes of.
        #[arg(long = "known", value_name = "DOMAIN")]
        known: Vec<String>,
    },
    /// Whether two strings are confusable; exits 1 if they are not.
    Confusable {
        /// First string.
        a: String,
        /// Second string.
        b: String,
    },
}

fn check(domains: &[String], known: &[String], options: &Options) -> Result<bool, Error> {
    let policy = SpoofPolicy::default();
    let mut index = LookalikeIndex::new(options.clone());
    for name in known {
        index.insert(name)?;
    }
    let mut clean = true;
    for domain in domains {
        let report = DomainReport::analyze(domain, options)?;
        let lookalikes = index.find(domain)?;
        let suspicious = report.is_suspicious(&policy) || !lookalikes.is_empty();
        clean &= !suspicious;
        println!(
            "{domain}\t{}\t{}\t{}\t{}",
            if suspicious { "SUSPICIOUS" } else { "ok" },
            report.ascii,
            report.display(&policy),
            report.restriction_level()
        );
        for label in report.labels.iter().filter(|l| l.is_suspicious(&policy)) {
            println!(
                "  label {:?}: {}, scripts {}, skeleton {:?}{}",
                label.unicode,
                label.restriction_level,
                label.scripts,
                label.skeleton,
                if label.ascii_lookalike {
                    ", looks like ASCII"
                } else {
                    ""
                }
            );
        }
        for name in lookalikes {
            println!("  looks like {name}");
        }
    }
    Ok(clean)
}

fn run(cli: Cli) -> Result<bool, Error> {
    let mut options = if cli.registration {
        Options::registration()
    } else {
        Options::lookup()
    };
    if cli.no_std3 {
        options = options.with_ascii_rules(AsciiRules::Url);
    }
    match cli.command {
        Command::ToAscii { domains } => {
            for d in domains {
                println!("{}", rune_idna::to_ascii(&d, &options)?);
            }
        }
        Command::ToUnicode { domains } => {
            for d in domains {
                println!("{}", rune_idna::to_unicode(&d, &options)?);
            }
        }
        Command::Encode { label } => println!("{}", punycode::encode(&label)?),
        Command::Decode { label } => println!("{}", punycode::decode(&label)?),
        Command::Skeleton { strings } => {
            for s in strings {
                println!("{}", skeleton(&s));
            }
        }
        Command::Check { domains, known } => return check(&domains, &known, &options),
        Command::Confusable { a, b } => {
            let kind = confusable_kind(&a, &b);
            match kind {
                Some(kind) => println!("confusable ({kind:?})"),
                None => println!("not confusable"),
            }
            return Ok(kind.is_some());
        }
    }
    Ok(true)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}
