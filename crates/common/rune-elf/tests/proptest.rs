//! Property tests: `parse` never panics, and what it returns stays within
//! the bounds the parser documents, on arbitrary bytes and on random
//! mutations of valid images of every class and byte order.

mod support;

use proptest::prelude::*;
use rune_elf::{Elf, parse};
use support::{DynOpts, Format, GLOBAL_FUNC, dynamic_image};

/// Invariants every successful parse must hold for an input of `len` bytes.
fn check(elf: &Elf, len: usize) {
    assert!(elf.sections.len() <= len / 40);
    assert!(elf.segments.len() <= len / 32);
    assert!(elf.dynamic_symbols.len() <= len / 16);
    assert!(elf.needed_libs.len() <= len / 8);
    let names = elf
        .sections
        .iter()
        .map(|s| s.name.as_str())
        .chain(elf.dynamic_symbols.iter().map(|s| s.name.as_str()))
        .chain(elf.needed_libs.iter().map(String::as_str))
        .chain(elf.interpreter.as_deref());
    for name in names {
        assert!(name.len() <= 4096);
    }
    assert!(elf.dynamic_symbols.iter().all(|s| !s.name.is_empty()));
    assert!(elf.needed_libs.iter().all(|l| !l.is_empty()));
    assert!(elf.security.score() <= 6);
    let _ = format!(
        "{} {} {}",
        elf.header.class, elf.header.elf_type, elf.header.machine
    );
}

fn valid_images() -> Vec<Vec<u8>> {
    let opts = DynOpts {
        symbols: vec![("__stack_chk_fail", 0, 0, GLOBAL_FUNC)],
        relro: true,
        ..DynOpts::default()
    };
    let mut images: Vec<_> = Format::ALL
        .iter()
        .map(|&f| dynamic_image(f, 3, &opts).build())
        .collect();
    images.extend(support::fixtures().into_iter().map(|(_, bytes)| bytes));
    images
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(elf) = parse(&bytes) {
            check(&elf, bytes.len());
        }
    }

    #[test]
    fn arbitrary_bytes_behind_a_valid_ident_never_panic(
        class in 1u8..=2,
        data in 1u8..=2,
        tail in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        // A valid e_ident in front, so the fuzzing reaches the header
        // tables instead of stopping at the magic.
        let mut bytes = vec![0x7f, b'E', b'L', b'F', class, data, 1, 0];
        bytes.extend_from_slice(&tail);
        if let Ok(elf) = parse(&bytes) {
            check(&elf, bytes.len());
        }
    }

    #[test]
    fn mutated_images_never_panic(
        which in 0usize..7,
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..16),
        cut in any::<prop::sample::Index>(),
    ) {
        let mut bytes = valid_images().swap_remove(which);
        for (at, value) in edits {
            let i = at.index(bytes.len());
            bytes[i] = value;
        }
        let len = cut.index(bytes.len() + 1);
        bytes.truncate(len.max(bytes.len() / 2));
        if let Ok(elf) = parse(&bytes) {
            check(&elf, bytes.len());
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
