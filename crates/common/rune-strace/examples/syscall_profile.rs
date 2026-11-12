//! Traces a command and prints the system calls it made, most frequent
//! first: the starting point for a seccomp allowlist.
//!
//! Run with `cargo run -p rune-strace --example syscall_profile -- ls /`.

// Examples report on stdout.
#![allow(clippy::print_stdout)]

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::{Command, Stdio};

    let mut args = std::env::args_os().skip(1);
    let Some(program) = args.next() else {
        return Err("usage: syscall_profile <program> [args...]".into());
    };
    let mut command = Command::new(program);
    command.args(args).stdout(Stdio::null());
    let report = rune_strace::trace(&mut command, &rune_strace::Options::default())?;

    let mut calls: Vec<_> = report.profile.iter().collect();
    calls.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    for (id, count) in &calls {
        let native = if id.is_native() { "" } else { " (non-native)" };
        println!("{:>8}  #{}{native}", count, id.nr);
    }
    println!(
        "{} distinct calls, {} total, {} processes, exit {:?}",
        calls.len(),
        report.profile.total(),
        report.processes,
        report.exit
    );
    println!("allowlist: {:?}", report.profile.numbers());
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
