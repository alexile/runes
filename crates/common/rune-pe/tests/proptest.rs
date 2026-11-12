//! Property tests: `parse` never panics, and what it returns stays within
//! the bounds the parser documents, on arbitrary bytes and on random
//! mutations of the valid fixtures.

mod support;

use proptest::prelude::*;
use rune_pe::{Pe, parse, suspicious_imports};

/// Invariants every successful parse must hold for an input of `len` bytes.
fn check(pe: &Pe, len: usize) {
    assert!(pe.sections.len() <= usize::from(pe.header.number_of_sections));
    assert!(pe.sections.len() <= len / 40);
    assert!(pe.exports.len() <= 65_536 && pe.exports.len() <= len / 4);
    assert!(pe.imports.len() <= 4096 && pe.imports.len() <= len / 20);
    let functions: usize = pe.imports.iter().map(|i| i.functions.len()).sum();
    assert!(functions <= 65_536);
    let names = pe
        .imports
        .iter()
        .map(|i| i.dll.as_str())
        .chain(
            pe.imports
                .iter()
                .flat_map(|i| &i.functions)
                .filter_map(|f| f.name.as_deref()),
        )
        .chain(pe.exports.iter().filter_map(|e| e.name.as_deref()));
    for name in names {
        assert!(name.len() <= 4096);
    }
    assert!(pe.imports.iter().all(|i| !i.dll.is_empty()));
    assert!(pe.exports.iter().all(|e| e.rva != 0));
    assert!(pe.security.score() <= 5);
    let _ = suspicious_imports(pe);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(pe) = parse(&bytes) {
            check(&pe, bytes.len());
        }
    }

    #[test]
    fn arbitrary_bytes_behind_a_valid_header_never_panic(
        tail in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        // A DOS header and signature in front, so the fuzzing reaches the
        // COFF and optional headers instead of stopping at the magic.
        let mut bytes = vec![0u8; 0x44];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c] = 0x40;
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes.extend_from_slice(&tail);
        if let Ok(pe) = parse(&bytes) {
            check(&pe, bytes.len());
        }
    }

    #[test]
    fn mutated_fixtures_never_panic(
        which in 0usize..6,
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..16),
        cut in any::<prop::sample::Index>(),
    ) {
        let (_, mut bytes) = support::fixtures().swap_remove(which);
        for (at, value) in edits {
            let i = at.index(bytes.len());
            bytes[i] = value;
        }
        let len = cut.index(bytes.len() + 1);
        bytes.truncate(len.max(bytes.len() / 2));
        if let Ok(pe) = parse(&bytes) {
            check(&pe, bytes.len());
        }
    }

    #[test]
    fn parse_is_deterministic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        prop_assert_eq!(
            format!("{:?}", parse(&bytes)),
            format!("{:?}", parse(&bytes))
        );
    }
}
