//! Property tests: HTTP-dates and entity tags round-trip through their
//! textual form, and the parsers never panic on arbitrary input.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use proptest::prelude::*;
use rune_axum_cache::{EntityTag, EntityTagList, HttpDate};

/// `9999-12-31T23:59:59Z`.
const MAX_SECS: u64 = 253_402_300_799;

fn tag() -> impl Strategy<Value = EntityTag> {
    ("[!#-~]{0,16}", any::<bool>()).prop_map(|(value, weak)| {
        if weak {
            EntityTag::weak(value).unwrap()
        } else {
            EntityTag::strong(value).unwrap()
        }
    })
}

proptest! {
    #[test]
    fn date_round_trips(secs in 0..=MAX_SECS) {
        let date = HttpDate::from_unix_secs(secs).unwrap();
        let text = date.to_string();
        prop_assert_eq!(text.len(), 29);
        prop_assert_eq!(HttpDate::parse(&text), Ok(date));
    }

    #[test]
    fn date_order_matches_seconds(a in 0..=MAX_SECS, b in 0..=MAX_SECS) {
        let (da, db) = (HttpDate::from_unix_secs(a).unwrap(), HttpDate::from_unix_secs(b).unwrap());
        prop_assert_eq!(da.cmp(&db), a.cmp(&b));
    }

    #[test]
    fn tag_round_trips(tag in tag()) {
        prop_assert_eq!(EntityTag::parse(&tag.to_string()), Ok(tag.clone()));
        prop_assert!(tag.weak_eq(&tag));
        prop_assert_eq!(tag.strong_eq(&tag), !tag.is_weak());
    }

    #[test]
    fn tag_list_round_trips(tags in prop::collection::vec(tag(), 1..6)) {
        let list = EntityTagList::Tags(tags.clone());
        let parsed = EntityTagList::parse(&list.to_string()).unwrap();
        prop_assert_eq!(&parsed, &list);
        for t in &tags {
            prop_assert!(parsed.matches_weak(t));
        }
    }

    #[test]
    fn parsers_never_panic(text in "\\PC{0,40}") {
        let _ = HttpDate::parse(&text);
        let _ = EntityTag::parse(&text);
        let _ = EntityTagList::parse(&text);
    }

    #[test]
    fn date_parser_never_panics_on_near_misses(
        day in "[A-Za-z]{3,9}", rest in "[ ,0-9A-Za-z:-]{18,26}",
    ) {
        let _ = HttpDate::parse(&format!("{day}, {rest}"));
        let _ = HttpDate::parse(&format!("{day} {rest}"));
    }
}
