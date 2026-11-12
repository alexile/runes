//! Parses the committed ELF fixtures in `tests/fixtures/` and builder-made
//! images covering both classes and byte orders.
//!
//! The `x86_64-*` fixtures are real binaries (4–8 KiB) built with GCC 15.2
//! against glibc 2.43 from a ten-line C program (`strcpy` + `printf` of
//! `argv[0]`) and a one-function library. Common flags:
//! `-Wl,--build-id=none -Wl,-z,noseparate-code -Wl,--hash-style=gnu
//! -fno-asynchronous-unwind-tables -Wl,-z,max-page-size=0x1000`, plus:
//!
//! | fixture              | extra flags                                                                                   |
//! | -------------------- | --------------------------------------------------------------------------------------------- |
//! | `pie-full-hardened`  | `-s -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 -Wl,-z,relro,-z,now`          |
//! | `nopie-unhardened`   | `-s -no-pie -fno-stack-protector -U_FORTIFY_SOURCE -O0 -Wl,-z,norelro,-z,lazy,-z,execstack`   |
//! | `pie-partial-relro`  | `-s -Os -fPIE -pie -fno-stack-protector -U_FORTIFY_SOURCE -Wl,-z,relro,-z,lazy`               |
//! | `pie-not-stripped`   | `-Os -fPIE -pie -fstack-protector-strong -Wl,-z,relro,-z,now`                                 |
//! | `libshared.so`       | `-s -Os -shared -fPIC -Wl,-z,relro,-z,now`                                                    |
//!
//! The `builder-*` fixtures come from `support::fixtures()`;
//! `fixtures_match_the_builder` keeps them in step (run it with
//! `RUNE_ELF_BLESS=1` to rewrite them).

mod support;

use std::path::PathBuf;

use rune_elf::{Elf, ElfClass, ElfError, ElfType, Endian, SectionType, SegmentType, parse};
use support::{
    BASE, Content, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1, DT_NEEDED, DynOpts, ElfSpec, Format,
    GLOBAL_FUNC, PT_INTERP, PT_LOAD, SecSpec, SegSpec, WEAK_OBJECT, dynamic_image, section_offset,
};

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

#[allow(clippy::panic, reason = "test helper: a bad fixture fails the test")]
fn parse_fixture(name: &str) -> Elf {
    parse(&fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn symbol_names(elf: &Elf) -> Vec<&str> {
    elf.dynamic_symbols
        .iter()
        .map(|s| s.name.as_str())
        .collect()
}

/// `(pie, nx_stack, relro, bind_now, stack_canary, fortify, stripped)`.
const fn flags(elf: &Elf) -> [bool; 7] {
    let s = &elf.security;
    [
        s.pie,
        s.nx_stack,
        s.relro,
        s.bind_now,
        s.stack_canary,
        s.fortify,
        s.stripped,
    ]
}

#[test]
fn fixtures_match_the_builder() {
    let bless = std::env::var_os("RUNE_ELF_BLESS").is_some();
    for (name, bytes) in support::fixtures() {
        assert!(bytes.len() <= 4096, "{name} is not a small fixture");
        if bless {
            std::fs::write(fixture_path(name), &bytes).unwrap();
        }
        assert!(
            fixture(name) == bytes,
            "{name} differs from the builder; rerun with RUNE_ELF_BLESS=1"
        );
    }
}

#[test]
fn real_pie_with_full_hardening() {
    let elf = parse_fixture("x86_64-pie-full-hardened");
    assert_eq!(elf.header.class, ElfClass::Elf64);
    assert_eq!(elf.header.endian, Endian::Little);
    assert_eq!(elf.header.elf_type, ElfType::Shared);
    assert_eq!(elf.header.machine.to_string(), "x86-64");
    assert_eq!(
        elf.interpreter.as_deref(),
        Some("/lib64/ld-linux-x86-64.so.2")
    );
    assert_eq!(elf.needed_libs, ["libc.so.6"]);
    let names = symbol_names(&elf);
    for expected in ["__stack_chk_fail", "__strcpy_chk", "__printf_chk"] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    // PIE, NX, full RELRO, canary, FORTIFY; stripped.
    assert_eq!(flags(&elf), [true; 7]);
    assert_eq!(elf.security.score(), 6);
}

#[test]
fn real_non_pie_without_hardening() {
    let elf = parse_fixture("x86_64-nopie-unhardened");
    assert_eq!(elf.header.elf_type, ElfType::Executable);
    assert_eq!(elf.header.entry, 0x40_0490);
    assert_eq!(elf.needed_libs, ["libc.so.6"]);
    let stack = elf
        .segments
        .iter()
        .find(|s| s.segment_type == SegmentType::GnuStack)
        .unwrap();
    assert!(stack.is_executable() && stack.is_writable() && stack.is_readable());
    assert!(
        !elf.segments
            .iter()
            .any(|s| s.segment_type == SegmentType::GnuRelro)
    );
    assert_eq!(
        symbol_names(&elf),
        ["__libc_start_main", "strcpy", "printf", "__gmon_start__"]
    );
    assert!(
        elf.dynamic_symbols
            .iter()
            .all(rune_elf::DynSym::is_undefined)
    );
    assert_eq!(
        flags(&elf),
        [false, false, false, false, false, false, true]
    );
    assert_eq!(elf.security.score(), 0);
}

#[test]
fn real_pie_with_partial_relro() {
    let elf = parse_fixture("x86_64-pie-partial-relro");
    // PIE, NX, RELRO without BIND_NOW, no canary, no FORTIFY.
    assert_eq!(flags(&elf), [true, true, true, false, false, false, true]);
    assert_eq!(elf.security.score(), 3);
}

#[test]
fn real_unstripped_binary_has_a_symtab() {
    let elf = parse_fixture("x86_64-pie-not-stripped");
    assert!(!elf.security.stripped);
    assert!(
        elf.sections
            .iter()
            .any(|s| s.name == ".symtab" && s.section_type == SectionType::SymTab)
    );
    assert!(elf.security.stack_canary && elf.security.bind_now);
}

#[test]
fn real_sections_are_named_and_typed() {
    let elf = parse_fixture("x86_64-pie-full-hardened");
    let find = |name: &str| elf.sections.iter().find(|s| s.name == name).unwrap();
    assert_eq!(elf.sections[0].section_type, SectionType::Null);
    assert_eq!(find(".interp").section_type, SectionType::ProgBits);
    assert_eq!(find(".dynsym").section_type, SectionType::DynSym);
    assert_eq!(find(".dynstr").section_type, SectionType::StrTab);
    assert_eq!(find(".dynamic").section_type, SectionType::Dynamic);
    assert_eq!(find(".gnu.hash").section_type, SectionType::GnuHash);
    assert_eq!(
        find(".gnu.version").section_type,
        SectionType::GnuVersionSym
    );
    assert_eq!(
        find(".gnu.version_r").section_type,
        SectionType::GnuVersionNeed
    );
    assert_eq!(find(".rela.dyn").section_type, SectionType::Rela);
    assert_eq!(find(".init_array").section_type, SectionType::InitArray);
    assert_eq!(find(".fini_array").section_type, SectionType::FiniArray);
    assert_eq!(find(".bss").section_type, SectionType::NoBits);
    let text = find(".text");
    assert!(text.is_executable() && !text.is_writable());
    let data = find(".data");
    assert!(data.is_writable() && !data.is_executable());
}

#[test]
fn real_shared_library() {
    let elf = parse_fixture("x86_64-libshared.so");
    assert_eq!(elf.header.elf_type, ElfType::Shared);
    assert_eq!(elf.interpreter, None);
    assert_eq!(elf.needed_libs, Vec::<String>::new());
    let export = elf
        .dynamic_symbols
        .iter()
        .find(|s| s.name == "rune_add")
        .unwrap();
    assert!(export.is_function() && export.is_global() && !export.is_undefined());
    assert!(elf.security.relro && elf.security.bind_now && elf.security.nx_stack);
}

#[test]
fn every_class_and_byte_order_parses_the_same() {
    for format in Format::ALL {
        let opts = DynOpts {
            needed: vec!["libc.so.6", "libm.so.6"],
            symbols: vec![
                ("__stack_chk_fail", 0, 0, GLOBAL_FUNC),
                ("__memcpy_chk", 0, 0, GLOBAL_FUNC),
                ("exported", BASE + 0x100, 16, GLOBAL_FUNC),
                ("weak_data", BASE + 0x200, 8, WEAK_OBJECT),
            ],
            dyn_extra: vec![(DT_FLAGS_1, 0x0800_0001)],
            relro: true,
            ..DynOpts::default()
        };
        let elf = parse(&dynamic_image(format, 3, &opts).build()).unwrap();
        let what = format!("elf64={} big={}", format.elf64, format.big);
        let class = if format.elf64 {
            ElfClass::Elf64
        } else {
            ElfClass::Elf32
        };
        let endian = if format.big {
            Endian::Big
        } else {
            Endian::Little
        };
        assert_eq!(
            (elf.header.class, elf.header.endian),
            (class, endian),
            "{what}"
        );
        assert_eq!(elf.header.entry, BASE + 0x100, "{what}");
        assert_eq!(elf.interpreter.as_deref(), Some("/lib/ld.so.1"), "{what}");
        assert_eq!(elf.needed_libs, ["libc.so.6", "libm.so.6"], "{what}");
        assert_eq!(
            symbol_names(&elf),
            ["__stack_chk_fail", "__memcpy_chk", "exported", "weak_data"],
            "{what}"
        );
        let exported = &elf.dynamic_symbols[2];
        assert_eq!(
            (exported.value, exported.size),
            (BASE + 0x100, 16),
            "{what}"
        );
        assert!(exported.is_function() && exported.is_global(), "{what}");
        let weak = &elf.dynamic_symbols[3];
        assert_eq!((weak.binding, weak.sym_type), (2, 1), "{what}");
        assert_eq!(flags(&elf), [true; 7], "{what}");
    }
}

// Regression: `bind_now` looked for a `__dl_bind_not_lazy` symbol that
// no toolchain emits, so it was never set; it now reads the dynamic tags.
#[test]
fn bind_now_comes_from_any_of_the_three_dynamic_tags() {
    let cases = [
        (vec![], false),
        (vec![(DT_BIND_NOW, 0)], true),
        (vec![(DT_FLAGS, 0x8)], true),
        (vec![(DT_FLAGS, 0x2)], false), // DF_SYMBOLIC only
        (vec![(DT_FLAGS_1, 0x1)], true),
        (vec![(DT_FLAGS_1, 0x0800_0000)], false), // DF_1_PIE only
    ];
    for format in Format::ALL {
        for (extra, expected) in &cases {
            let opts = DynOpts {
                dyn_extra: extra.clone(),
                ..DynOpts::default()
            };
            let elf = parse(&dynamic_image(format, 3, &opts).build()).unwrap();
            assert_eq!(elf.security.bind_now, *expected, "{extra:?}");
        }
    }
}

// Regression: entries after DT_NULL (padding, or garbage) were still
// read as DT_NEEDED.
#[test]
fn the_dynamic_section_ends_at_dt_null() {
    let mut spec = dynamic_image(Format::LE64, 3, &DynOpts::default());
    let dynamic = spec
        .sections
        .iter_mut()
        .find(|s| s.name == ".dynamic")
        .unwrap();
    // Append a DT_NEEDED naming "libc.so.6" (offset 1) after the DT_NULL.
    dynamic.data.extend(support::dynamic(
        Format::LE64,
        &[(DT_NEEDED, 1), (DT_BIND_NOW, 0)],
    ));
    let elf = parse(&spec.build()).unwrap();
    assert_eq!(elf.needed_libs, ["libc.so.6"]);
    assert!(!elf.security.bind_now);
}

// Regression: the dynamic string table was found only by the name
// `.dynstr`; the `sh_link` of `.dynsym` / `.dynamic` is what the spec uses.
#[test]
fn string_tables_are_found_through_sh_link() {
    let opts = DynOpts {
        symbols: vec![("__stack_chk_fail", 0, 0, GLOBAL_FUNC)],
        ..DynOpts::default()
    };
    let mut spec = dynamic_image(Format::BE32, 2, &opts);
    for s in &mut spec.sections {
        if s.name == ".dynstr" {
            s.name = ".renamed";
        }
    }
    let elf = parse(&spec.build()).unwrap();
    assert_eq!(elf.needed_libs, ["libc.so.6"]);
    assert!(elf.security.stack_canary);
}

// Regression: without section headers (`sstrip`), DT_NEEDED and the
// binding flags were lost; they now come from PT_DYNAMIC, with DT_STRTAB
// mapped through PT_LOAD.
#[test]
fn sstripped_binaries_use_pt_dynamic() {
    for format in Format::ALL {
        let opts = DynOpts {
            needed: vec!["libz.so.1", "libc.so.6"],
            dyn_extra: vec![(DT_FLAGS, 0x8)],
            ..DynOpts::default()
        };
        let mut spec = dynamic_image(format, 2, &opts);
        spec.strip_section_headers = true;
        let elf = parse(&spec.build()).unwrap();
        assert!(elf.sections.is_empty());
        assert_eq!(elf.needed_libs, ["libz.so.1", "libc.so.6"]);
        assert!(elf.security.bind_now && elf.security.stripped);
        assert_eq!(elf.interpreter.as_deref(), Some("/lib/ld.so.1"));
    }
}

#[test]
fn dt_strtab_outside_every_load_segment_yields_no_libraries() {
    let mut spec = dynamic_image(Format::LE64, 2, &DynOpts::default());
    spec.strip_section_headers = true;
    for seg in &mut spec.segments {
        if seg.p_type == PT_LOAD {
            seg.content = Content::Empty;
            seg.vaddr = 0x9999_0000;
        }
    }
    let elf = parse(&spec.build()).unwrap();
    assert_eq!(elf.needed_libs, Vec::<String>::new());
}

// Regression: the interpreter path was read up to the next NUL
// anywhere in the file, ignoring the PT_INTERP segment size.
#[test]
fn interpreter_path_must_end_inside_its_segment() {
    let mut spec = ElfSpec::new(Format::LE64, 2);
    spec.sections = vec![SecSpec {
        name: ".interp",
        sh_type: support::SHT_PROGBITS,
        flags: 2,
        data: b"/lib/ld.so".to_vec(), // no NUL
        link: None,
    }];
    spec.segments = vec![SegSpec {
        p_type: PT_INTERP,
        flags: 4,
        vaddr: 0,
        content: Content::Section(0),
    }];
    let elf = parse(&spec.build()).unwrap();
    assert_eq!(elf.interpreter.as_deref(), Some(""));
}

#[test]
fn no_gnu_stack_means_an_executable_stack() {
    let opts = DynOpts {
        gnu_stack_flags: None,
        ..DynOpts::default()
    };
    let elf = parse(&dynamic_image(Format::LE32, 2, &opts).build()).unwrap();
    assert!(!elf.security.nx_stack);
    let opts = DynOpts {
        gnu_stack_flags: Some(7),
        ..DynOpts::default()
    };
    let elf = parse(&dynamic_image(Format::LE32, 2, &opts).build()).unwrap();
    assert!(!elf.security.nx_stack);
}

#[test]
fn canary_and_fortify_symbols() {
    let cases: [(&[&'static str], bool, bool); 5] = [
        (&["__stack_chk_fail"], true, false),
        (&["__stack_chk_guard"], true, false),
        (&["__sprintf_chk"], false, true),
        (&["my_chk", "stack_chk"], false, false),
        (&["memcpy", "printf"], false, false),
    ];
    for (names, canary, fortify) in cases {
        let opts = DynOpts {
            symbols: names.iter().map(|&n| (n, 0, 0, GLOBAL_FUNC)).collect(),
            ..DynOpts::default()
        };
        let elf = parse(&dynamic_image(Format::LE64, 3, &opts).build()).unwrap();
        assert_eq!(elf.security.stack_canary, canary, "{names:?}");
        assert_eq!(elf.security.fortify, fortify, "{names:?}");
    }
}

#[test]
fn elf_types() {
    for (e_type, expected) in [
        (1, ElfType::Relocatable),
        (2, ElfType::Executable),
        (3, ElfType::Shared),
        (4, ElfType::Core),
        (0xfe00, ElfType::Other(0xfe00)),
    ] {
        let elf = parse(&ElfSpec::new(Format::BE64, e_type).build()).unwrap();
        assert_eq!(elf.header.elf_type, expected);
        assert_eq!(elf.security.pie, e_type == 3);
    }
}

// Regression: header tables with entries smaller than the standard
// size made every read run into the next entry; they are now ignored.
#[test]
fn undersized_header_table_entries_are_ignored() {
    let mut image = dynamic_image(Format::LE64, 3, &DynOpts::default()).build();
    image[58..60].copy_from_slice(&8u16.to_le_bytes()); // e_shentsize
    image[54..56].copy_from_slice(&8u16.to_le_bytes()); // e_phentsize
    let elf = parse(&image).unwrap();
    assert!(elf.sections.is_empty() && elf.segments.is_empty());
}

#[test]
fn truncated_images_error_or_parse_partially() {
    for format in Format::ALL {
        let image = dynamic_image(format, 3, &DynOpts::default()).build();
        for len in 0..image.len() {
            match parse(&image[..len]) {
                Ok(_) | Err(ElfError::OutOfBounds) => {}
                Err(ElfError::TooShort) => assert!(len < 64),
                Err(e) => unreachable!("{e} at {len}"),
            }
        }
    }
}

#[test]
fn header_errors() {
    let mut image = ElfSpec::new(Format::LE64, 2).build();
    image[5] = 3;
    assert_eq!(parse(&image).unwrap_err(), ElfError::UnknownEncoding(3));
    image[4] = 0;
    assert_eq!(parse(&image).unwrap_err(), ElfError::UnknownClass(0));
    assert_eq!(parse(&image[..63]).unwrap_err(), ElfError::TooShort);
}

#[test]
fn string_table_section_is_typed() {
    let image = dynamic_image(Format::LE64, 3, &DynOpts::default()).build();
    let elf = parse(&image).unwrap();
    let shstrtab = elf.sections.iter().find(|s| s.name == ".shstrtab").unwrap();
    assert_eq!(shstrtab.section_type, SectionType::StrTab);
    let spec = dynamic_image(Format::LE64, 3, &DynOpts::default());
    let dynstr = elf.sections.iter().find(|s| s.name == ".dynstr").unwrap();
    assert_eq!(dynstr.file_offset, section_offset(&spec, 1) as u64);
}
