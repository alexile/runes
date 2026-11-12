//! Parses the committed PE fixtures in `tests/fixtures/` and checks every
//! field the parser reports.
//!
//! The fixtures are tiny hand-laid images written by `support::fixtures()`.
//! `fixtures_match_the_builder` keeps the files and the builder in step: run
//! it with `RUNE_PE_BLESS=1` to rewrite the files after changing the builder.

mod support;

use std::path::PathBuf;

use rune_pe::{Pe, PeError, PeMagic, parse, suspicious_imports};
use support::{FILE_ALIGN, PeSpec, SectionSpec, Thunk, dll, idata, scn};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[allow(
    clippy::panic,
    reason = "test helper: a missing fixture fails the test"
)]
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[allow(
    clippy::panic,
    reason = "test helper: a missing fixture fails the test"
)]
fn parse_fixture(name: &str) -> Pe {
    parse(&fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

type FlagGetter = fn(&rune_pe::SecurityFlags) -> bool;

#[test]
fn fixtures_match_the_builder() {
    let bless = std::env::var_os("RUNE_PE_BLESS").is_some();
    for (name, bytes) in support::fixtures() {
        assert!(bytes.len() <= 8 * 1024, "{name} is not a small fixture");
        if bless {
            std::fs::write(fixture_path(name), &bytes).unwrap();
        }
        assert!(
            fixture(name) == bytes,
            "{name} differs from the builder; rerun with RUNE_PE_BLESS=1"
        );
    }
}

#[test]
fn pe64_console_executable_headers() {
    let pe = parse_fixture("pe64-console-imports.exe");
    let h = &pe.header;
    assert_eq!(h.magic, PeMagic::Pe64);
    assert_eq!(h.machine.to_string(), "x86-64");
    assert!(h.is_exe() && !h.is_dll());
    assert_eq!(h.number_of_sections, 2);
    assert_eq!(h.timestamp, 0x6500_0000);
    assert_eq!(h.image_base, 0x1_4000_0000);
    assert_eq!(h.entry_point, 0x1000);
    assert_eq!(h.size_of_image, 0x3000);
    assert_eq!((h.linker_major, h.linker_minor), (14, 36));
    assert_eq!(h.subsystem, 3);
}

#[test]
fn pe64_console_executable_sections() {
    let pe = parse_fixture("pe64-console-imports.exe");
    let names: Vec<_> = pe.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, [".text", ".rdata"]);

    let text = &pe.sections[0];
    assert_eq!((text.virtual_address, text.virtual_size), (0x1000, 16));
    assert_eq!((text.raw_offset, text.raw_size), (0x200, 0x200));
    assert!(text.is_executable() && text.contains_code() && !text.is_writable());

    let rdata = &pe.sections[1];
    assert_eq!(rdata.raw_offset, 0x400);
    assert!(!rdata.is_executable() && !rdata.contains_code() && !rdata.is_writable());
}

#[test]
fn pe64_imports_by_name_and_ordinal() {
    let pe = parse_fixture("pe64-console-imports.exe");
    let dlls: Vec<_> = pe.imports.iter().map(|i| i.dll.as_str()).collect();
    assert_eq!(dlls, ["KERNEL32.dll", "USER32.dll"]);

    let kernel32: Vec<_> = pe.imports[0]
        .functions
        .iter()
        .map(|f| (f.name.as_deref(), f.hint, f.ordinal))
        .collect();
    assert_eq!(
        kernel32,
        [
            (Some("GetProcAddress"), Some(0x2b7), None),
            (Some("VirtualAlloc"), Some(0x5e1), None),
            (Some("ExitProcess"), Some(0x166), None),
        ]
    );

    let user32: Vec<_> = pe.imports[1]
        .functions
        .iter()
        .map(rune_pe::ImportFunction::display_name)
        .collect();
    assert_eq!(user32, ["MessageBoxA", "#17"]);
    assert_eq!(pe.imports[1].functions[1].ordinal, Some(17));
    assert_eq!(pe.imports[1].functions[1].hint, None);
    assert!(pe.exports.is_empty());
}

#[test]
fn pe64_suspicious_imports() {
    let pe = parse_fixture("pe64-console-imports.exe");
    assert_eq!(
        suspicious_imports(&pe),
        [
            ("KERNEL32.dll".to_string(), "GetProcAddress".to_string()),
            ("KERNEL32.dll".to_string(), "VirtualAlloc".to_string()),
        ]
    );
}

#[test]
fn pe64_every_hardening_flag_and_signature() {
    let s = parse_fixture("pe64-console-imports.exe").security;
    assert!(s.aslr && s.high_entropy_va && s.dep && s.cfg);
    assert!(s.no_seh && s.force_integrity && s.signed);
    assert_eq!(s.score(), 5);
}

#[test]
fn pe32_dll_headers_and_flags() {
    let pe = parse_fixture("pe32-dll-exports.dll");
    assert_eq!(pe.header.magic, PeMagic::Pe32);
    assert_eq!(pe.header.machine.to_string(), "i386");
    assert!(pe.header.is_dll());
    assert_eq!(pe.header.image_base, 0x1000_0000);
    assert_eq!(pe.header.subsystem, 2);
    assert!(pe.imports.is_empty());

    let s = &pe.security;
    assert!(s.aslr && s.dep && s.no_seh);
    assert!(!s.high_entropy_va && !s.cfg && !s.force_integrity && !s.signed);
    assert_eq!(s.score(), 3);
}

#[test]
fn pe32_exports_named_and_by_ordinal_only() {
    let pe = parse_fixture("pe32-dll-exports.dll");
    let exports: Vec<_> = pe
        .exports
        .iter()
        .map(|e| (e.ordinal, e.name.as_deref(), e.rva))
        .collect();
    // Ordinal 7 is an unused (zero) slot; ordinal 6 has no name.
    assert_eq!(
        exports,
        [
            (5, Some("Beta"), 0x1000),
            (6, None, 0x1004),
            (8, Some("Alpha"), 0x1008),
        ]
    );
}

#[test]
fn packed_image_shows_its_tells() {
    let pe = parse_fixture("pe32-upx-packed.exe");
    let names: Vec<_> = pe.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["UPX0", "UPX1", ".rsrc"]);

    // An empty-on-disk section reserving the unpacked image...
    let upx0 = &pe.sections[0];
    assert_eq!((upx0.raw_size, upx0.raw_offset), (0, 0));
    assert_eq!(upx0.virtual_size, 0x11000);
    // ...and writable + executable sections, the entry point in the stub.
    let wx: Vec<_> = pe
        .sections
        .iter()
        .filter(|s| s.is_writable() && s.is_executable())
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(wx, ["UPX0", "UPX1"]);
    let entry = pe.header.entry_point;
    let upx1 = &pe.sections[1];
    assert!((upx1.virtual_address..upx1.virtual_address + upx1.virtual_size).contains(&entry));

    // The bare loader imports, two of them on the suspicious list.
    assert_eq!(pe.imports.len(), 1);
    assert_eq!(pe.imports[0].dll, "KERNEL32.DLL");
    assert_eq!(pe.imports[0].functions.len(), 4);
    let hits: Vec<_> = suspicious_imports(&pe)
        .into_iter()
        .map(|(_, f)| f)
        .collect();
    assert_eq!(hits, ["LoadLibraryA", "GetProcAddress"]);

    // No hardening at all.
    assert_eq!(pe.security.score(), 0);
    assert!(!pe.security.high_entropy_va && !pe.security.signed);
}

#[test]
fn truncated_section_table_yields_the_sections_present() {
    let pe = parse_fixture("malformed-truncated-sections.exe");
    assert_eq!(pe.header.number_of_sections, u16::MAX);
    assert_eq!(pe.sections.len(), 1);
    assert_eq!(pe.sections[0].name, ".text");
}

#[test]
fn lfanew_past_the_end_is_rejected() {
    assert_eq!(
        parse(&fixture("malformed-lfanew-past-eof.exe")).unwrap_err(),
        PeError::BadPeOffset
    );
}

#[test]
fn hostile_tables_stay_bounded() {
    let bytes = fixture("malformed-hostile-tables.exe");
    let pe = parse(&bytes).unwrap();
    assert!(pe.exports.len() <= bytes.len() / 4);
    assert!(
        pe.exports
            .iter()
            .filter_map(|e| e.name.as_deref())
            .all(|n| n.len() <= 4096)
    );
    assert_eq!(pe.imports.len(), 97);
    assert!(pe.imports.iter().all(|i| i.dll == "evil.dll"));
    let functions: usize = pe.imports.iter().map(|i| i.functions.len()).sum();
    assert!(functions <= 65_536);
    // Every thunk resolves to the same 1 KiB run of 'A' (or nowhere).
    assert!(
        pe.imports
            .iter()
            .flat_map(|i| &i.functions)
            .all(|f| f.name.as_ref().is_some_and(|n| n.len() == 1021))
    );
}

#[test]
fn every_truncation_of_a_valid_image_is_handled() {
    for (name, bytes) in support::fixtures() {
        // The hostile image is slow to parse in debug builds; sample it.
        let step = if name.starts_with("malformed-hostile") {
            61
        } else {
            1
        };
        for len in (0..bytes.len()).step_by(step) {
            let _ = parse(&bytes[..len]);
        }
    }
}

#[test]
fn truncated_headers_report_the_right_error() {
    let bytes = fixture("pe64-console-imports.exe");
    assert_eq!(parse(&bytes[..63]).unwrap_err(), PeError::TooShort);
    // e_lfanew = 0x40: the PE signature itself is cut off.
    assert_eq!(parse(&bytes[..0x42]).unwrap_err(), PeError::BadPeOffset);
    // Signature present, COFF header cut short.
    assert_eq!(parse(&bytes[..0x50]).unwrap_err(), PeError::OutOfBounds);
    // COFF header present, optional header cut short.
    assert_eq!(parse(&bytes[..0x80]).unwrap_err(), PeError::OutOfBounds);
}

#[test]
fn unknown_optional_header_magic_is_rejected() {
    let mut bytes = fixture("pe64-console-imports.exe");
    bytes[0x58..0x5a].copy_from_slice(&0x107u16.to_le_bytes()); // ROM image
    assert_eq!(parse(&bytes).unwrap_err(), PeError::UnknownMagic(0x107));
}

#[test]
fn bad_pe_signature_is_rejected() {
    let mut bytes = fixture("pe32-dll-exports.dll");
    bytes[0x42] = b'X';
    assert_eq!(parse(&bytes).unwrap_err(), PeError::BadPeSignature);
}

// Regression: data directories past `NumberOfRvaAndSizes` were still
// read, so stale or attacker-chosen bytes produced phantom imports.
#[test]
fn directories_beyond_number_of_rva_and_sizes_are_ignored() {
    let mut bytes = fixture("pe64-console-imports.exe");
    let count = 0x58 + 108;
    for (n, imports) in [(16u32, 2), (2, 2), (1, 0), (0, 0)] {
        bytes[count..count + 4].copy_from_slice(&n.to_le_bytes());
        let pe = parse(&bytes).unwrap();
        assert_eq!(pe.imports.len(), imports, "NumberOfRvaAndSizes = {n}");
        assert_eq!(pe.security.signed, n > 4, "NumberOfRvaAndSizes = {n}");
    }
}

// Regression: with a short optional header, the section table bytes
// that follow it were read as the import directory.
#[test]
fn directories_beyond_the_optional_header_are_ignored() {
    let (data, import_dir) = idata(0x1000, true, &[("A.dll", &[Thunk::Name(0, "F")])]);
    let mut spec = PeSpec::new(true);
    spec.rva_count = 0; // optional header ends before the directories
    spec.directories[1] = import_dir;
    // The first section header's VirtualSize lands where directory 1
    // (imports) would be, and equals the real import table's RVA.
    spec.sections = vec![SectionSpec {
        name: b".idata",
        virtual_address: 0x1000,
        virtual_size: 0x1000,
        data,
        characteristics: scn::INITIALIZED_DATA | scn::READ,
    }];
    let mut bytes = spec.build();
    let count = 0x58 + 108;
    bytes[count..count + 4].copy_from_slice(&16u32.to_le_bytes());
    let pe = parse(&bytes).unwrap();
    assert_eq!(pe.sections.len(), 1);
    assert!(pe.imports.is_empty(), "{:?}", pe.imports);
}

#[test]
fn each_dll_characteristic_maps_to_one_flag() {
    let cases: [(u16, FlagGetter, u8); 6] = [
        (dll::DYNAMIC_BASE, |s| s.aslr, 1),
        (dll::HIGH_ENTROPY_VA, |s| s.high_entropy_va, 0),
        (dll::NX_COMPAT, |s| s.dep, 1),
        (dll::GUARD_CF, |s| s.cfg, 1),
        (dll::NO_SEH, |s| s.no_seh, 1),
        (dll::FORCE_INTEGRITY, |s| s.force_integrity, 1),
    ];
    for pe64 in [false, true] {
        for (bit, get, score) in cases {
            let mut spec = PeSpec::new(pe64);
            spec.dll_characteristics = bit;
            let s = parse(&spec.build()).unwrap().security;
            assert!(get(&s), "bit 0x{bit:04x}, pe64 = {pe64}");
            let set = [
                s.aslr,
                s.high_entropy_va,
                s.dep,
                s.cfg,
                s.no_seh,
                s.force_integrity,
                s.signed,
            ];
            assert_eq!(set.iter().filter(|&&b| b).count(), 1, "bit 0x{bit:04x}");
            assert_eq!(s.score(), score, "bit 0x{bit:04x}");
        }
    }
}

#[test]
fn unrelated_dll_characteristics_set_no_flag() {
    let mut spec = PeSpec::new(true);
    spec.dll_characteristics = dll::TERMINAL_SERVER_AWARE | 0x0800 | 0x1000 | 0x2000;
    let s = parse(&spec.build()).unwrap().security;
    assert_eq!(s.score(), 0);
    assert!(!s.high_entropy_va && !s.signed);
}

#[test]
fn an_empty_security_directory_is_not_signed() {
    for dir in [(0x400, 0), (0, 8)] {
        let mut spec = PeSpec::new(false);
        spec.directories[4] = dir;
        assert!(!parse(&spec.build()).unwrap().security.signed, "{dir:?}");
    }
}

#[test]
fn rva_lookup_uses_raw_size_when_larger_than_virtual_size() {
    // VirtualSize 0 (some linkers) still maps through SizeOfRawData.
    let (data, import_dir) = idata(0x3000, false, &[("B.dll", &[Thunk::Ordinal(3)])]);
    let mut spec = PeSpec::new(false);
    spec.directories[1] = import_dir;
    spec.sections = vec![SectionSpec {
        name: b".idata",
        virtual_address: 0x3000,
        virtual_size: 0,
        data,
        characteristics: scn::INITIALIZED_DATA | scn::READ,
    }];
    let pe = parse(&spec.build()).unwrap();
    assert_eq!(pe.imports.len(), 1);
    assert_eq!(pe.imports[0].functions[0].display_name(), "#3");
    assert_eq!(pe.sections[0].raw_size as usize, FILE_ALIGN);
}

#[test]
fn section_names_use_all_eight_bytes_and_tolerate_non_utf8() {
    let mut spec = PeSpec::new(true);
    spec.sections = vec![
        SectionSpec {
            name: b".textbss",
            virtual_address: 0x1000,
            virtual_size: 0x10,
            data: Vec::new(),
            characteristics: 0,
        },
        SectionSpec {
            name: b"\xff\xfeab",
            virtual_address: 0x2000,
            virtual_size: 0x10,
            data: Vec::new(),
            characteristics: 0,
        },
    ];
    let pe = parse(&spec.build()).unwrap();
    assert_eq!(pe.sections[0].name, ".textbss");
    assert_eq!(pe.sections[1].name, "\u{fffd}\u{fffd}ab");
}
