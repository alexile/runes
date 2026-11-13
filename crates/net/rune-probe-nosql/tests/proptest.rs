//! The readers and probe sessions never panic on arbitrary server bytes,
//! BSON round-trips, and probes send only their fixed requests.

use proptest::prelude::*;
use rune_probe_nosql::bson::{Bson, Document};
use rune_probe_nosql::{all_probes, http, mongodb, redis};
use rune_service_probe::{Options, Target, simulate};

proptest! {
    #[test]
    fn readers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512), eof in any::<bool>()) {
        let _ = redis::parse_reply(&bytes);
        let _ = Document::parse(&bytes);
        let _ = mongodb::parse_reply(&bytes);
        let _ = http::parse_response(&bytes, eof);
    }

    #[test]
    fn readers_survive_mutated_documents(
        keys in proptest::collection::vec("[a-z]{1,8}", 1..8),
        edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..6),
    ) {
        // Corrupt a valid document so the element decoders get exercised,
        // which random bytes rarely reach.
        let elements: Vec<(&str, Bson)> = keys
            .iter()
            .map(|k| (k.as_str(), Bson::String(k.clone())))
            .collect();
        let mut bytes = Document::encode(&elements);
        for (at, byte) in edits {
            let at = at % bytes.len();
            bytes[at] = byte;
        }
        let _ = Document::parse(&bytes);
        let reply = mongodb::op_msg(1, &bytes);
        let _ = mongodb::parse_reply(&reply);
    }

    #[test]
    fn bson_round_trips(
        entries in proptest::collection::vec(("[a-z]{1,8}", any::<i32>(), any::<i64>(), "[ -~]{0,16}", any::<bool>()), 0..8)
    ) {
        let mut elements = Vec::new();
        for (key, a, b, s, t) in &entries {
            elements.push((key.as_str(), Bson::Int32(*a)));
            elements.push((key.as_str(), Bson::Int64(*b)));
            elements.push((key.as_str(), Bson::String(s.clone())));
            elements.push((key.as_str(), Bson::Bool(*t)));
        }
        let bytes = Document::encode(&elements);
        let (doc, used) = Document::parse(&bytes).unwrap();
        prop_assert_eq!(used, bytes.len());
        prop_assert_eq!(doc.elements.len(), elements.len());
        for ((k, v), (k2, v2)) in doc.elements.iter().zip(&elements) {
            prop_assert_eq!(k, k2);
            // Strings are printable-escaped; the generated ones are plain
            // except for backslashes.
            if let (Bson::String(a), Bson::String(b)) = (v, v2) {
                prop_assert_eq!(a, &b.replace('\\', "\\\\"));
            } else {
                prop_assert_eq!(v, v2);
            }
        }
    }

    #[test]
    fn redis_bulk_round_trips(body in proptest::collection::vec(any::<u8>(), 0..300)) {
        let mut raw = format!("${}\r\n", body.len()).into_bytes();
        raw.extend_from_slice(&body);
        raw.extend_from_slice(b"\r\n");
        let (reply, used) = redis::parse_reply(&raw).unwrap();
        prop_assert_eq!(used, raw.len());
        prop_assert_eq!(reply, redis::Reply::Bulk(Some(body)));
    }

    #[test]
    fn sessions_survive_arbitrary_replies(
        replies in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..96), 0..8),
        max_read in 1usize..512,
    ) {
        let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
        let options = Options::default().with_max_read_bytes(max_read);
        let target = Target::new("fuzz", 1);
        for probe in all_probes() {
            let sim = simulate(probe.as_ref(), &target, &replies, &options).unwrap();
            prop_assert!(sim.sent.len() <= 3);
            if let Ok(info) = sim.result {
                prop_assert_eq!(info.service, probe.id());
            }
        }
    }
}
