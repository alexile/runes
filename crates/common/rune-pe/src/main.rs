//! `rune-pe` command-line tool: lightweight PE (Windows executable) parser: headers, sections, imports, exports, security flags (ASLR, DEP, CFG, `SafeSEH`).

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_pe::{parse, suspicious_imports};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

/// Parse PE binaries and report security hardening flags, imports, and exports.
#[derive(Parser)]
#[command(name = "rune-pe", version, author)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent CLI flag"
)]
struct Args {
    /// PE files to analyse.
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Show suspicious imports (malware indicators).
    #[arg(long)]
    suspicious: bool,

    /// Show full import table.
    #[arg(long)]
    imports: bool,

    /// Show export table.
    #[arg(long)]
    exports: bool,

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

        match parse(&bytes) {
            Err(e) => {
                eprintln!("{}: {e}", path.display());
                had_error = true;
            }
            Ok(pe) if args.json => print_json(&path.display().to_string(), &pe),
            Ok(pe) => print_text(&path.display().to_string(), &pe, &args),
        }
    }

    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

const fn flag(b: bool) -> &'static str {
    if b { "yes" } else { "NO" }
}

fn print_text(name: &str, pe: &rune_pe::Pe, args: &Args) {
    let h = &pe.header;
    let s = &pe.security;
    println!("{name}");
    println!(
        "  format:   {} ({}{})",
        h.magic,
        h.machine,
        if h.is_dll() { ", DLL" } else { "" }
    );
    println!("  entry:    0x{:x}", h.entry_point);
    println!("  security:");
    println!("    ASLR:            {}", flag(s.aslr));
    println!("    High-entropy VA: {}", flag(s.high_entropy_va));
    println!("    DEP/NX:          {}", flag(s.dep));
    println!("    CFG:             {}", flag(s.cfg));
    println!("    SafeSEH/No-SEH:  {}", flag(s.no_seh));
    println!("    Force Integrity: {}", flag(s.force_integrity));
    println!("    Signed:          {}", flag(s.signed));
    println!("    Score:           {}/5", s.score());

    if args.imports || args.suspicious {
        let sus = suspicious_imports(pe);
        if !sus.is_empty() {
            println!("  suspicious imports:");
            for (dll, func) in &sus {
                println!("    {dll}!{func}");
            }
        }
    }

    if args.imports {
        println!("  imports:");
        for imp in &pe.imports {
            println!("    {} ({} functions)", imp.dll, imp.functions.len());
            if args.imports {
                for func in imp.functions.iter().take(10) {
                    println!("      {}", func.display_name());
                }
                if imp.functions.len() > 10 {
                    println!("      … ({} more)", imp.functions.len() - 10);
                }
            }
        }
    }

    if args.exports && !pe.exports.is_empty() {
        println!("  exports ({}):", pe.exports.len());
        for exp in pe.exports.iter().take(20) {
            let name = exp.name.as_deref().unwrap_or("?");
            println!("    {:>5}  {name}", exp.ordinal);
        }
        if pe.exports.len() > 20 {
            println!("    … ({} more)", pe.exports.len() - 20);
        }
    }
    println!();
}

fn print_json(name: &str, pe: &rune_pe::Pe) {
    let h = &pe.header;
    let s = &pe.security;
    let sus = suspicious_imports(pe);
    let sus_json: Vec<_> = sus
        .iter()
        .map(|(dll, func)| json_str(&format!("{dll}!{func}")))
        .collect();
    let dlls: Vec<_> = pe.imports.iter().map(|i| json_str(&i.dll)).collect();
    println!(
        "{{\"file\":{},\"format\":\"{}\",\"machine\":\"{}\",\"entry\":\"0x{:x}\",\
         \"security\":{{\"aslr\":{},\"dep\":{},\"cfg\":{},\"no_seh\":{},\"force_integrity\":{},\"signed\":{},\"score\":{}}},\
         \"dlls\":[{}],\"suspicious\":[{}]}}",
        json_str(name),
        h.magic,
        h.machine,
        h.entry_point,
        s.aslr,
        s.dep,
        s.cfg,
        s.no_seh,
        s.force_integrity,
        s.signed,
        s.score(),
        dlls.join(","),
        sus_json.join(",")
    );
}

/// `s` as a JSON string literal. DLL and function names come from the file
/// being analysed, so quotes, backslashes and control bytes are escaped.
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
    // output unescaped, so a crafted DLL name broke (or injected into) it.
    #[test]
    fn json_strings_are_escaped() {
        assert_eq!(json_str("KERNEL32.dll"), "\"KERNEL32.dll\"");
        assert_eq!(json_str("a\"b\\c\nd\u{1}"), "\"a\\\"b\\\\c\\nd\\u0001\"");
    }
}
