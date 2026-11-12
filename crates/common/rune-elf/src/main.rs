//! `rune-elf` command-line tool: lightweight ELF binary parser: header, sections, segments, security flags (PIE, NX, RELRO, stack canary, FORTIFY).

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

/// Parse ELF binaries and report security hardening flags.
#[derive(Parser)]
#[command(name = "rune-elf", version, author)]
struct Args {
    /// ELF files to analyse.
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Output machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let mut had_error = false;

    for path in &args.files {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: {}: {e}", path.display());
                had_error = true;
                continue;
            }
        };

        match rune_elf::parse(&bytes) {
            Ok(elf) if args.json => print_json(&path.display().to_string(), &elf),
            Ok(elf) => print_text(&path.display().to_string(), &elf),
            Err(e) => {
                eprintln!("{}: {e}", path.display());
                had_error = true;
            }
        }
    }

    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn print_text(name: &str, elf: &rune_elf::Elf) {
    let h = &elf.header;
    println!("{name}");
    println!("  type:    {}", h.elf_type);
    println!("  class:   {}", h.class);
    println!("  machine: {}", h.machine);
    println!("  entry:   0x{:x}", h.entry);

    let s = &elf.security;
    println!("  security:");
    println!("    PIE:          {}", flag(s.pie));
    println!("    NX stack:     {}", flag(s.nx_stack));
    println!("    RELRO:        {}", flag(s.relro));
    println!("    Stack canary: {}", flag(s.stack_canary));
    println!("    FORTIFY:      {}", flag(s.fortify));
    println!("    Stripped:     {}", flag(s.stripped));
    println!("    Score:        {}/6", s.score());

    if let Some(interp) = &elf.interpreter {
        println!("  interpreter: {interp}");
    }
    if !elf.needed_libs.is_empty() {
        println!("  libs:");
        for lib in &elf.needed_libs {
            println!("    {lib}");
        }
    }

    let imports: Vec<_> = elf
        .dynamic_symbols
        .iter()
        .filter(|s| s.is_undefined() && s.is_function())
        .collect();
    if !imports.is_empty() {
        println!("  imports ({}):", imports.len());
        for sym in imports.iter().take(20) {
            println!("    {}", sym.name);
        }
        if imports.len() > 20 {
            println!("    … ({} more)", imports.len() - 20);
        }
    }
    println!();
}

fn print_json(name: &str, elf: &rune_elf::Elf) {
    let h = &elf.header;
    let s = &elf.security;
    let imports: Vec<_> = elf
        .dynamic_symbols
        .iter()
        .filter(|sym| sym.is_undefined() && sym.is_function())
        .map(|sym| json_str(&sym.name))
        .collect();
    let libs: Vec<_> = elf.needed_libs.iter().map(|l| json_str(l)).collect();
    let interpreter = elf
        .interpreter
        .as_ref()
        .map_or_else(|| "null".to_string(), |interp| json_str(interp));
    println!(
        "{{\"file\":{},\"type\":\"{}\",\"class\":\"{}\",\"machine\":\"{}\",\"entry\":\"0x{:x}\",\
         \"interpreter\":{interpreter},\
         \"security\":{{\"pie\":{},\"nx_stack\":{},\"relro\":{},\"stack_canary\":{},\"fortify\":{},\"stripped\":{},\"score\":{}}},\
         \"libs\":[{}],\"imports\":[{}]}}",
        json_str(name),
        h.elf_type,
        h.class,
        h.machine,
        h.entry,
        s.pie,
        s.nx_stack,
        s.relro,
        s.stack_canary,
        s.fortify,
        s.stripped,
        s.score(),
        libs.join(","),
        imports.join(",")
    );
}

const fn flag(b: bool) -> &'static str {
    if b { "yes" } else { "NO" }
}

/// `s` as a JSON string literal. Symbol, library and interpreter names come
/// from the file being analysed, so quotes, backslashes and control bytes
/// are escaped.
fn json_str(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::json_str;

    // Regression: names from the binary were printed into the JSON
    // output unescaped, so a crafted symbol name broke (or injected into) it.
    #[test]
    fn json_strings_are_escaped() {
        assert_eq!(json_str("libc.so.6"), "\"libc.so.6\"");
        assert_eq!(json_str("a\"b\\c\nd\u{1}"), "\"a\\\"b\\\\c\\nd\\u0001\"");
    }
}
