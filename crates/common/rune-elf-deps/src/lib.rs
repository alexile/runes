//! Transitive shared-library dependency closure resolution for ELF
//! binaries — the same information `ldd` reports, computed without
//! either `ldd` or `readelf`.
//!
//! # Why not `ldd`
//!
//! `ldd`'s own manual page warns: "you should never employ ldd on an
//! untrusted executable, since this may result in the execution of
//! arbitrary code" — in its default mode `ldd` can invoke the dynamic
//! linker *against* the target binary rather than merely inspecting it.
//! Anything resolving dependencies of a binary that isn't already fully
//! trusted (a project-local build artifact, say) must never do that.
//!
//! # Why not `readelf` either
//!
//! `readelf` is a safe, static-inspection tool, but shelling out to it
//! costs a process spawn per binary and requires `binutils` to be
//! installed. [`resolve_library_closure`] instead parses each binary's
//! `DT_NEEDED`/`PT_INTERP` data directly via [`rune_elf::parse`] — pure
//! Rust, no subprocess, no unsafe. The one remaining subprocess is
//! `ldconfig -p`, used to resolve a soname (`libc.so.6`) to an absolute
//! path via glibc's own prebuilt library cache — a static, read-only
//! operation `ldconfig -p` performs without loading or executing
//! anything, and there's no equivalent to parse that binary cache format
//! directly without depending on glibc's own (undocumented, versioned)
//! on-disk layout.
//!
//! # Example
//!
//! The closure always includes each binary's `PT_INTERP` dynamic linker. This
//! example writes a minimal ELF executable whose interpreter is
//! `/lib/ld-example.so.1` to a temporary file and resolves it. The input file
//! is only read, never executed:
//!
//! ```rust
//! use std::path::PathBuf;
//!
//! use rune_elf_deps::resolve_library_closure;
//!
//! fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
//!     buf[off..off + bytes.len()].copy_from_slice(bytes);
//! }
//!
//! // ELF64 header + one PT_INTERP program header + the interpreter path.
//! let interp = b"/lib/ld-example.so.1\0";
//! let mut image = vec![0u8; 64 + 56];
//! put(&mut image, 0, b"\x7fELF\x02\x01\x01"); // ELFCLASS64, little-endian, v1
//! put(&mut image, 16, &2u16.to_le_bytes()); // e_type: ET_EXEC
//! put(&mut image, 32, &64u64.to_le_bytes()); // e_phoff
//! put(&mut image, 54, &56u16.to_le_bytes()); // e_phentsize
//! put(&mut image, 56, &1u16.to_le_bytes()); // e_phnum
//! put(&mut image, 64, &3u32.to_le_bytes()); // p_type: PT_INTERP
//! put(&mut image, 64 + 8, &120u64.to_le_bytes()); // p_offset
//! put(&mut image, 64 + 32, &(interp.len() as u64).to_le_bytes()); // p_filesz
//! image.extend_from_slice(interp);
//!
//! let path = std::env::temp_dir().join(format!("rune-elf-deps-doc-{}", std::process::id()));
//! std::fs::write(&path, &image).unwrap();
//! let closure = resolve_library_closure(&[path.clone()]);
//! std::fs::remove_file(&path).unwrap();
//!
//! assert!(closure.contains(&PathBuf::from("/lib/ld-example.so.1")));
//! // Everything else is glibc's NSS modules found on this host, if any.
//! assert!(closure.iter().all(|p| p.is_absolute()));
//! ```
//!
//! # Multiarch caches
//!
//! A multiarch host's `ldconfig` cache lists several ABI variants of the
//! same soname back to back (native 64-bit, x32, i386, ...) with no
//! guaranteed native-first ordering. A naive first-hit-wins lookup can
//! bind the wrong-architecture file, which the caller's own (correctly
//! architected) dynamic linker then can't load. `native_arch_tag`
//! filters the cache down to the host's own architecture before picking
//! a hit.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use rune_elf::parse;

/// Resolve the transitive closure of shared-library dependencies for
/// `binaries`, plus glibc's NSS modules.
///
/// NSS modules (`libnss_dns.so.2`, `libnss_files.so.2`, ...) are `dlopen`'d at
/// runtime based on `/etc/nsswitch.conf` — e.g. whenever `getaddrinfo` resolves
/// a hostname — and never appear in any binary's own dependency list, so
/// binaries that need DNS/user/group resolution would otherwise be missing a
/// dependency in a way that's hard to connect back to a missing library.
///
/// Returns absolute host paths, deduplicated. Purely static analysis:
/// never executes `binaries` or anything found while walking their
/// dependency graph.
#[must_use]
pub fn resolve_library_closure(binaries: &[PathBuf]) -> Vec<PathBuf> {
    let cache = ldconfig_cache();
    let mut closure: HashSet<PathBuf> = HashSet::new();
    let mut queue: Vec<PathBuf> = binaries.to_vec();
    let mut visited: HashSet<PathBuf> = HashSet::new();

    while let Some(path) = queue.pop() {
        if !visited.insert(path.clone()) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(elf) = parse(&bytes) else {
            continue;
        };
        if let Some(interp) = elf.interpreter {
            let interp = PathBuf::from(interp);
            if closure.insert(interp.clone()) {
                queue.push(interp);
            }
        }
        for name in elf.needed_libs {
            if let Some(resolved) = resolve_soname(&name, &cache)
                && closure.insert(resolved.clone())
            {
                queue.push(resolved);
            }
        }
    }

    closure.extend(find_nss_modules());
    let mut result: Vec<PathBuf> = closure.into_iter().collect();
    result.sort();
    result
}

fn ldconfig_cache() -> HashMap<String, PathBuf> {
    let mut map = HashMap::new();
    let Ok(output) = Command::new("ldconfig").arg("-p").output() else {
        return map;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let native_tag = native_arch_tag();
    for line in text.lines() {
        // "\tlibc.so.6 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libc.so.6"
        let Some((name_and_tag, path_part)) = line.split_once("=>") else {
            continue;
        };
        let Some(name) = name_and_tag.split_whitespace().next() else {
            continue;
        };
        let path = path_part.trim();
        if !path.starts_with('/') {
            continue;
        }
        if let Some(tag) = native_tag
            && !name_and_tag.contains(tag)
        {
            continue;
        }
        // First (native-arch) hit wins.
        map.entry(name.to_string())
            .or_insert_with(|| PathBuf::from(path));
    }
    map
}

/// The ABI tag `ldconfig -p` prints next to entries matching this
/// process's own architecture (e.g. `"(libc6,x86-64)"` on `x86_64`),
/// distinguishing them from other-ABI variants like x32 or i386 on the
/// same multiarch host. `None` on an architecture this isn't aware of —
/// callers then accept any tag, falling back to whatever
/// [`LIBRARY_SEARCH_DIRS`] finds on disk rather than trusting a possibly
/// wrong `ldconfig` hit.
fn native_arch_tag() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("x86-64"),
        "aarch64" => Some("AArch64"),
        _ => None,
    }
}

/// The library directories NSS modules and, as a fallback when a soname
/// is missing from the `ldconfig` cache, other shared libraries
/// conventionally live in — covers the common Debian/Ubuntu multiarch
/// layout as well as the plainer `/lib64`-style layout other
/// distributions use.
const LIBRARY_SEARCH_DIRS: &[&str] = &[
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
];

fn resolve_soname(name: &str, cache: &HashMap<String, PathBuf>) -> Option<PathBuf> {
    if let Some(path) = cache.get(name) {
        return Some(path.clone());
    }
    for dir in LIBRARY_SEARCH_DIRS {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

const NSS_MODULE_NAMES: &[&str] = &[
    "libnss_dns.so.2",
    "libnss_files.so.2",
    "libnss_compat.so.2",
    "libnss_myhostname.so.2",
    "libresolv.so.2",
];

fn find_nss_modules() -> Vec<PathBuf> {
    let mut found = Vec::new();
    for dir in LIBRARY_SEARCH_DIRS {
        for name in NSS_MODULE_NAMES {
            let candidate = Path::new(dir).join(name);
            if candidate.is_file() {
                found.push(candidate);
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_dependencies_of_a_real_dynamic_binary() {
        let sh = PathBuf::from("/usr/bin/sh");
        if !sh.is_file() {
            return;
        }
        let closure = resolve_library_closure(&[sh]);
        assert!(
            closure
                .iter()
                .any(|p| p.to_string_lossy().contains("libc.so")),
            "expected libc in the dependency closure, got {closure:?}"
        );
    }

    #[test]
    fn resolves_the_elf_interpreter_too() {
        let sh = PathBuf::from("/usr/bin/sh");
        if !sh.is_file() {
            return;
        }
        let closure = resolve_library_closure(&[sh]);
        assert!(
            closure
                .iter()
                .any(|p| p.to_string_lossy().contains("ld-linux")),
            "expected the ELF interpreter (dynamic linker) in the closure, got {closure:?}"
        );
    }

    #[test]
    fn empty_input_yields_empty_closure_besides_nss() {
        let closure = resolve_library_closure(&[]);
        for path in &closure {
            let name = path.file_name().unwrap().to_string_lossy();
            assert!(
                NSS_MODULE_NAMES.contains(&name.as_ref()),
                "unexpected entry with no input binaries: {path:?}"
            );
        }
    }

    #[test]
    fn nonexistent_binary_does_not_panic() {
        let closure =
            resolve_library_closure(&[PathBuf::from("/definitely/not/a/real/binary/anywhere")]);
        for path in &closure {
            let name = path.file_name().unwrap().to_string_lossy();
            assert!(NSS_MODULE_NAMES.contains(&name.as_ref()));
        }
    }

    #[test]
    fn never_shells_out_to_ldd_or_readelf() {
        // Regression guard for the actual reason this crate exists:
        // dependency resolution must never run `ldd` (which documents
        // that it can execute the target binary) or shell out to
        // `readelf` at all (ELF inspection is pure-Rust via rune_elf).
        let source = include_str!("lib.rs");
        assert!(
            !source
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .any(|l| {
                    l.contains("\"ldd\"")
                        || l.contains("Command::new(\"ldd\")")
                        || l.contains("\"readelf\"")
                        || l.contains("Command::new(\"readelf\")")
                }),
            "must not shell out to ldd or readelf"
        );
    }
}
