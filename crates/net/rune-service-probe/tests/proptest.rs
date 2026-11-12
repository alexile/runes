//! Properties of the banner helpers and the driver budgets.

use proptest::prelude::*;
use rune_service_probe::banner::{BannerProbe, printable, split_line};
use rune_service_probe::{End, Options, Target, simulate};

proptest! {
    #[test]
    fn printable_is_printable_ascii_and_bounded(bytes in proptest::collection::vec(any::<u8>(), 0..512), max in 0usize..600) {
        let out = printable(&bytes, max);
        prop_assert!(out.bytes().all(|b| (0x20..=0x7e).contains(&b)));
        prop_assert!(out.len() <= 4 * max.min(bytes.len()));
    }

    #[test]
    fn printable_keeps_plain_text(text in "[ -\\[\\]-~]{0,200}") {
        prop_assert_eq!(printable(text.as_bytes(), usize::MAX), text);
    }

    #[test]
    fn split_line_rejoins(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        if let Some((line, rest)) = split_line(&bytes) {
            prop_assert!(!line.contains(&b'\n'));
            prop_assert!(bytes.ends_with(rest));
            prop_assert!(bytes.starts_with(line));
        } else {
            prop_assert!(!bytes.contains(&b'\n'));
        }
    }

    #[test]
    fn banner_probe_respects_budgets(
        replies in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..16),
        max_read in 1usize..256,
        max_exchanges in 0usize..8,
    ) {
        let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
        let options = Options::default().with_max_read_bytes(max_read).with_max_exchanges(max_exchanges);
        let sim = simulate(&BannerProbe::new(), &Target::new("h", 1), &replies, &options).unwrap();
        prop_assert!(sim.sent.is_empty());
        if let Ok(info) = sim.result {
            let banner = info.banner.unwrap_or_default();
            prop_assert!(banner.len() <= 4 * max_read);
        } else {
            prop_assert!(matches!(sim.end, End::Closed | End::ExchangeLimit | End::ReadLimit));
        }
    }
}
