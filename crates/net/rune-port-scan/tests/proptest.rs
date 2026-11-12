//! Property tests for port lists and banner hints.

use proptest::prelude::*;
use rune_port_scan::{PortSet, banner_hint, os_hint};

proptest! {
    /// Display is canonical: it parses back to the same ordered set.
    #[test]
    fn port_set_round_trips(ports in proptest::collection::vec(1u16..=u16::MAX, 1..200)) {
        let set: PortSet = ports.iter().copied().collect();
        let text = set.to_string();
        let back = PortSet::parse(&text).unwrap();
        prop_assert_eq!(back.as_slice(), set.as_slice());
        prop_assert_eq!(back.to_string(), text);
    }

    /// Ranges expand to exactly their members.
    #[test]
    fn ranges_expand(start in 1u16..=u16::MAX, len in 0u16..500) {
        let end = start.saturating_add(len);
        let set = PortSet::parse(&format!("{start}-{end}")).unwrap();
        prop_assert_eq!(set.len(), usize::from(end - start) + 1);
        prop_assert!(set.contains(start) && set.contains(end));
    }

    /// The parser never panics on arbitrary text.
    #[test]
    fn parse_never_panics(text in "\\PC{0,64}") {
        let _ = PortSet::parse(&text);
    }

    /// Hints never panic and keep fields bounded on arbitrary bytes.
    #[test]
    fn hints_are_bounded(banner in proptest::collection::vec(any::<u8>(), 0..2048)) {
        if let Some(hint) = banner_hint(&banner) {
            prop_assert!(hint.product.map_or(0, |p| p.chars().count()) <= 64);
            prop_assert!(hint.version.map_or(0, |v| v.chars().count()) <= 64);
        }
        let _ = os_hint(&banner);
    }
}
