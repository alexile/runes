//! `rune-wordlist` command-line tool: create keys, build and sign packs,
//! verify them, stream their lists and install updates into a store.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rand::RngCore as _;
use rune_wordlist::{
    InstallOptions, Keyring, ListKind, Options, Pack, PackBuilder, PublicKey, ReadOptions,
    SecretKey, Store, UpdateOutcome, Verify, Version,
};

/// Versioned, Ed25519-signed wordlist and payload packs.
#[derive(Parser)]
#[command(name = "rune-wordlist", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a signing key; prints the public key to trust.
    Keygen {
        /// Where to write the secret key (hex seed). Must not exist.
        #[arg(long)]
        out: PathBuf,
    },
    /// Hash the lists in a directory and write the signed manifest.
    Build {
        /// The pack directory.
        dir: PathBuf,
        /// File holding the secret key.
        #[arg(long)]
        key: PathBuf,
        /// Pack name.
        #[arg(long)]
        name: String,
        /// Pack version, MAJOR.MINOR.PATCH.
        #[arg(long)]
        version: Version,
        /// Pack description.
        #[arg(long)]
        description: Option<String>,
        /// A wordlist, as NAME=PATH (path relative to the pack directory).
        #[arg(long = "list", value_name = "NAME=PATH")]
        lists: Vec<String>,
        /// A payload list, as NAME=PATH.
        #[arg(long = "payload", value_name = "NAME=PATH")]
        payloads: Vec<String>,
    },
    /// Verify a pack's signature and every list.
    Verify {
        /// The pack directory.
        dir: PathBuf,
        #[command(flatten)]
        trust: Trust,
    },
    /// Stream one list to stdout, failing if it was tampered with.
    Cat {
        /// The pack directory.
        dir: PathBuf,
        /// The list's name.
        list: String,
        /// Skip lines starting with '#'.
        #[arg(long)]
        skip_comments: bool,
        #[command(flatten)]
        trust: Trust,
    },
    /// Install or update a pack in a store (refuses rollbacks).
    Install {
        /// The candidate pack directory.
        source: PathBuf,
        /// The store directory.
        #[arg(long)]
        store: PathBuf,
        /// Accept a version that is not newer than the installed one.
        #[arg(long)]
        allow_downgrade: bool,
        #[command(flatten)]
        trust: Trust,
    },
}

#[derive(clap::Args)]
struct Trust {
    /// A trusted public key (64 hex digits). Repeatable.
    #[arg(long = "pubkey", value_name = "HEX", required = true)]
    pubkeys: Vec<String>,
}

impl Trust {
    fn keyring(&self) -> Result<Keyring, rune_wordlist::Error> {
        self.pubkeys.iter().try_fold(Keyring::new(), |ring, hex| {
            Ok(ring.with_key(PublicKey::from_hex(hex)?))
        })
    }
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Keygen { out } => {
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            let key = SecretKey::from_seed(&seed);
            seed.fill(0);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&out)?;
            writeln!(file, "{}", key.to_hex())?;
            println!("{}", key.public_key().to_hex());
        }
        Command::Build {
            dir,
            key,
            name,
            version,
            description,
            lists,
            payloads,
        } => {
            let key = SecretKey::from_hex(&std::fs::read_to_string(key)?)?;
            let mut builder = PackBuilder::new(name, version)?;
            if let Some(d) = description {
                builder = builder.description(d);
            }
            let tagged = lists
                .iter()
                .map(|l| (l, ListKind::Wordlist))
                .chain(payloads.iter().map(|l| (l, ListKind::Payload)));
            for (spec, kind) in tagged {
                let (n, p) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("expected NAME=PATH, got {spec:?}"))?;
                builder = builder.list(n, p, kind)?;
            }
            let manifest = builder.write(&dir, &key)?;
            println!(
                "{} {} signed by {} ({} lists)",
                manifest.name,
                manifest.version,
                manifest.key_id,
                manifest.lists.len()
            );
        }
        Command::Verify { dir, trust } => {
            let pack = Pack::open(&dir, &trust.keyring()?, &Options::default())?;
            let m = pack.manifest();
            println!("ok: {} {} signed by {}", m.name, m.version, m.key_id);
            for l in &m.lists {
                println!("  {}\t{}\t{} bytes", l.name, l.path, l.size);
            }
        }
        Command::Cat {
            dir,
            list,
            skip_comments,
            trust,
        } => {
            let options = Options::default()
                .with_verify(Verify::Eager)
                .with_read(ReadOptions::default().with_skip_comments(skip_comments));
            let pack = Pack::open(&dir, &trust.keyring()?, &options)?;
            let mut reader = pack.list(&list)?;
            let stdout = std::io::stdout();
            let mut out = std::io::BufWriter::new(stdout.lock());
            let mut buf = Vec::new();
            while reader.read_entry(&mut buf)? {
                out.write_all(&buf)?;
                out.write_all(b"\n")?;
            }
            out.flush()?;
        }
        Command::Install {
            source,
            store,
            allow_downgrade,
            trust,
        } => {
            let options = InstallOptions::default().with_allow_downgrade(allow_downgrade);
            let outcome = Store::new(store).install(&source, &trust.keyring()?, &options)?;
            match outcome {
                UpdateOutcome::Installed { version } => println!("installed {version}"),
                UpdateOutcome::Upgraded { from, to } => println!("upgraded {from} -> {to}"),
                UpdateOutcome::Replaced { from, to } => println!("replaced {from} with {to}"),
                _ => println!("done"),
            }
        }
    }
    Ok(())
}
