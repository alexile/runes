//! `rune-checkpoint` command-line tool: resumable-cursor/offset persistence for restartable stream consumers.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};
use rune_checkpoint::CheckpointStore;
use std::process::ExitCode;

/// Save and inspect resumable stream-consumer offsets.
#[derive(Parser)]
#[command(name = "rune-checkpoint")]
struct Args {
    /// Path to the JSON checkpoint store.
    #[arg(long, default_value = "checkpoints.json")]
    store: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Save an offset for a source.
    Save { source_id: String, offset: u64 },
    /// Load the offset for a source.
    Load { source_id: String },
    /// List every saved source and offset.
    List,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let store = CheckpointStore::new(&args.store);

    let result = match args.command {
        Command::Save { source_id, offset } => store.save(&source_id, offset).map(|()| {
            println!("saved {source_id} = {offset}");
        }),
        Command::Load { source_id } => store.load(&source_id).map(|offset| match offset {
            Some(offset) => println!("{offset}"),
            None => println!("(none)"),
        }),
        Command::List => store.load_all().map(|entries| {
            let mut entries: Vec<_> = entries.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (source_id, offset) in entries {
                println!("{source_id}\t{offset}");
            }
        }),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("rune-checkpoint: {err}");
            ExitCode::FAILURE
        }
    }
}
