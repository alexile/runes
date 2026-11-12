//! Property tests for the request id and `traceparent` codecs.

use proptest::prelude::*;
use rune_axum_requestid::{RequestId, TraceParent};

proptest! {
    #[test]
    fn traceparent_round_trips(
        trace in any::<[u8; 16]>().prop_filter("non-zero", |t| *t != [0; 16]),
        parent in any::<[u8; 8]>().prop_filter("non-zero", |p| *p != [0; 8]),
        flags in any::<u8>(),
    ) {
        let tp = TraceParent::from_parts(trace, parent, flags).unwrap();
        let text = tp.to_string();
        prop_assert_eq!(text.len(), 55);
        prop_assert_eq!(TraceParent::parse(&text).unwrap(), tp);
        prop_assert_eq!(tp.to_header_value(), text.as_str());
    }

    #[test]
    fn traceparent_parse_never_panics(s in any::<String>()) {
        if let Ok(tp) = TraceParent::parse(&s) {
            // Whatever parses re-encodes canonically and parses back.
            prop_assert_eq!(TraceParent::parse(&tp.to_string()).unwrap(), tp);
        }
    }

    #[test]
    fn traceparent_bytes_never_panic(b in proptest::collection::vec(any::<u8>(), 0..80)) {
        let _ = TraceParent::parse_bytes(&b);
    }

    #[test]
    fn request_id_round_trips(s in "[!-~]{1,128}") {
        let id = RequestId::new(&s).unwrap();
        prop_assert_eq!(id.as_str(), s.as_str());
        prop_assert_eq!(id.header_value().as_bytes(), s.as_bytes());
    }

    #[test]
    fn accepted_request_ids_are_log_safe(s in any::<String>()) {
        if let Ok(id) = RequestId::new(&s) {
            prop_assert!(id.as_str().bytes().all(|b| b.is_ascii_graphic()));
            prop_assert!(id.as_str().len() <= 128);
        }
    }

    #[test]
    fn uuid_v4_is_well_formed(bytes in any::<[u8; 16]>()) {
        let id = RequestId::uuid_v4(bytes);
        let s = id.as_str();
        prop_assert_eq!(s.len(), 36);
        prop_assert_eq!(&s[14..15], "4");
        prop_assert!(matches!(&s[19..20], "8" | "9" | "a" | "b"));
    }
}
