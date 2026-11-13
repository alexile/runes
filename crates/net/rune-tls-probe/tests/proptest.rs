//! Properties: offers always encode to parseable hellos carrying exactly
//! the offered suites, and the response reader never panics.

#![allow(clippy::unwrap_used, reason = "test code")]

use proptest::prelude::*;
use rune_tls_hello::{CipherSuite, ClientHello, ProtocolVersion};
use rune_tls_probe::{Offer, ResponseReader, ScanOptions, Scanner};

fn version() -> impl Strategy<Value = ProtocolVersion> {
    prop::sample::select(rune_tls_probe::ALL_VERSIONS.to_vec())
}

proptest! {
    #[test]
    fn offers_round_trip(
        version in version(),
        suites in prop::collection::vec(any::<u16>(), 0..200),
        compression in any::<bool>(),
        fallback in any::<bool>(),
        name in "[a-z]{1,20}(\\.[a-z]{1,10}){0,3}",
    ) {
        let suites: Vec<CipherSuite> = suites.into_iter().map(CipherSuite).collect();
        let offer = Offer::new(version, suites.clone())
            .with_compression(compression)
            .with_fallback_scsv(fallback)
            .with_server_name(name);
        let hello = ClientHello::parse_records(&offer.to_records([3; 32]).unwrap()).unwrap();
        prop_assert_eq!(&hello.cipher_suites[..suites.len()], &suites[..]);
        prop_assert_eq!(hello.offers_fallback_scsv(), fallback || suites.contains(&CipherSuite::TLS_FALLBACK_SCSV));
        prop_assert_eq!(hello.max_version(), version);
    }

    #[test]
    fn reader_never_panics(chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..300), 0..8)) {
        let mut reader = ResponseReader::new();
        for chunk in &chunks {
            if reader.feed(chunk).is_some() {
                break;
            }
        }
        let _ = reader.finish();
    }

    #[test]
    fn scanner_terminates_on_arbitrary_answers(answers in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 1..16)) {
        let mut scanner = Scanner::new(ScanOptions::default().with_max_attempts(64));
        let mut i = 0;
        while let Some(_offer) = scanner.next_offer() {
            let mut reader = ResponseReader::new();
            let answer = &answers[i % answers.len()];
            let outcome = reader.feed(answer).unwrap_or_else(|| reader.finish());
            scanner.record(&outcome);
            i += 1;
            prop_assert!(i <= 64);
        }
        let report = scanner.finish();
        prop_assert!(report.attempts <= 64);
    }
}

mod hostile_answers {
    use proptest::prelude::*;
    use rune_tls_hello::{CipherSuite, Extension, ProtocolVersion, ServerHello};
    use rune_tls_probe::jarm::{self, Entry, Fingerprint, Order};
    use rune_tls_probe::policy::{Grade, Policy};
    use rune_tls_probe::{
        KeyExchange, KeyExchangeKind, MAX_RESPONSE_BYTES, Offer, Report, ResponseReader,
        VersionResult,
    };

    /// A plausible `ServerHello` followed by a certificate, key exchange and
    /// hello-done, to mutate.
    fn server_flight(suite: u16) -> Vec<u8> {
        let mut out = ServerHello::new()
            .with_cipher_suite(CipherSuite(suite))
            .with_extension(Extension::renegotiation_info(&[]).unwrap())
            .with_extension(Extension::alpn(["h2"]).unwrap())
            .to_records(ProtocolVersion::TLS_1_2, 16_384)
            .unwrap();
        out.extend([
            22, 3, 3, 0, 24, 11, 0, 0, 3, 0, 0, 0, 12, 0, 0, 9, 0, 2, 0xff, 0xff, 0, 1, 2, 0, 0,
            14, 0, 0, 0,
        ]);
        out
    }

    fn mutated() -> impl Strategy<Value = Vec<u8>> {
        (
            prop::sample::select(vec![0xc02f_u16, 0x009e, 0x002f, 0x1301]),
            prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..8),
            any::<prop::sample::Index>(),
        )
            .prop_map(|(suite, flips, cut)| {
                let mut bytes = server_flight(suite);
                for (at, value) in flips {
                    let i = at.index(bytes.len());
                    bytes[i] = value;
                }
                let keep = cut.index(bytes.len() + 1);
                bytes.truncate(keep.max(1));
                bytes
            })
    }

    fn feed_all<T>(chunks: &[Vec<u8>], mut feed: impl FnMut(&[u8]) -> Option<T>) -> Option<T> {
        chunks.iter().find_map(|c| feed(c))
    }

    proptest! {
        #[test]
        fn jarm_reader_never_panics(chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..400), 0..8)) {
            let mut reader = jarm::ResponseReader::new();
            let entry = feed_all(&chunks, |c| reader.feed(c)).unwrap_or_else(|| reader.finish());
            let text = entry.to_string();
            prop_assert_eq!(text.matches('|').count(), 3);
        }

        #[test]
        fn mutated_server_hellos_never_panic(bytes in mutated(), split in any::<prop::sample::Index>()) {
            let at = split.index(bytes.len());
            let (a, b) = bytes.split_at(at);
            let chunks = [a.to_vec(), b.to_vec()];

            let _ = Entry::parse(&bytes);
            let mut reader = jarm::ResponseReader::new();
            let _ = feed_all(&chunks, |c| reader.feed(c)).unwrap_or_else(|| reader.finish());

            for read_kx in [false, true] {
                let offer = Offer::new(ProtocolVersion::TLS_1_2, []).with_read_key_exchange(read_kx);
                let mut reader = ResponseReader::for_offer(&offer);
                let _ = feed_all(&chunks, |c| reader.feed(c)).unwrap_or_else(|| reader.finish());
            }
        }

        /// However the bytes come, both readers decide within their caps.
        #[test]
        fn readers_decide_within_their_caps(byte in any::<u8>(), header in prop::collection::vec(any::<u8>(), 0..9)) {
            let mut jarm_reader = jarm::ResponseReader::new();
            let mut fed = 0;
            let mut decided = jarm_reader.feed(&header).is_some();
            fed += header.len();
            while !decided {
                decided = jarm_reader.feed(&[byte; 1024]).is_some();
                fed += 1024;
                prop_assert!(fed <= jarm::MAX_RESPONSE_BYTES + 2048);
            }

            let offer = Offer::new(ProtocolVersion::TLS_1_2, []).with_read_key_exchange(true);
            let mut reader = ResponseReader::for_offer(&offer);
            let mut fed = 0;
            let mut decided = reader.feed(&server_flight(0x009e)[..60]).is_some();
            while !decided {
                decided = reader.feed(&[byte; 4096]).is_some();
                fed += 4096;
                prop_assert!(fed <= MAX_RESPONSE_BYTES + 8192);
            }
        }

        #[test]
        fn key_exchange_parse_never_panics(body in prop::collection::vec(any::<u8>(), 0..600)) {
            for kind in [KeyExchangeKind::Dhe, KeyExchangeKind::Ecdhe] {
                if let Some(KeyExchange::Dhe { prime_bits }) = KeyExchange::parse(kind, &body) {
                    prop_assert!(prime_bits as usize <= body.len() * 8);
                }
            }
        }

        #[test]
        fn hash_accepts_anything(raw in "[0-9a-f|,h2/.-]{0,200}") {
            let _ = jarm::hash(&raw);
            let _ = jarm::decode(&raw);
        }

        #[test]
        fn fingerprints_round_trip_through_decode(
            picks in prop::collection::vec(prop::option::of((0usize..69, 0u16..6, "[a-z0-9]{0,8}", prop::collection::vec(any::<u16>(), 0..6))), 10),
        ) {
            let sample = jarm::PROBES[0].cipher_suites(&[0; 32]);
            let entries: Vec<Entry> = picks
                .iter()
                .map(|p| match p {
                    None => Entry::NoAnswer,
                    Some((i, v, alpn, ext)) => Entry::answered(sample[*i].0, 0x0300 + v, alpn.clone(), ext.clone()),
                })
                .collect();
            let fp = Fingerprint::new(entries.clone().try_into().unwrap());
            let hash = fp.hash();
            prop_assert_eq!(hash.len(), jarm::HASH_LEN);
            prop_assert_eq!(&hash, &jarm::hash(&fp.raw()));
            let decoded = jarm::decode(&hash).unwrap();
            for (entry, answer) in entries.iter().zip(decoded.answers) {
                match (entry, answer) {
                    (Entry::NoAnswer, None) => {}
                    (Entry::Answered { cipher_suite, version, .. }, Some(a)) => {
                        prop_assert_eq!(a.cipher_suite.map(|s| s.0), Some(*cipher_suite));
                        prop_assert_eq!(a.version.map(|v| v.0), Some(*version));
                    }
                    _ => prop_assert!(false, "answer mismatch"),
                }
            }
        }

        #[test]
        fn orders_keep_every_item(len in 0usize..80) {
            let items: Vec<usize> = (0..len).collect();
            for order in [Order::Forward, Order::Reverse, Order::MiddleOut] {
                let mut out = order.apply(&items);
                out.sort_unstable();
                prop_assert_eq!(&out, &items);
            }
            let top = Order::TopHalf.apply(&items);
            let bottom = Order::BottomHalf.apply(&items);
            prop_assert_eq!(top.len() + bottom.len(), len);
        }

        #[test]
        fn grading_is_total(
            versions in prop::collection::vec((prop::sample::select(rune_tls_probe::ALL_VERSIONS.to_vec()), any::<bool>(), prop::collection::vec(any::<u16>(), 0..12)), 0..6),
        ) {
            let mut scan = Report::default();
            for (version, supported, suites) in versions {
                let mut result = VersionResult::new(version);
                result.supported = supported;
                result.cipher_suites = suites.into_iter().map(CipherSuite).collect();
                scan.versions.push(result);
            }
            for policy in [Policy::modern(), Policy::intermediate(), Policy::old()] {
                let report = policy.grade(&scan);
                let clean = report.failures().next().is_none() && report.warnings().next().is_none();
                prop_assert_eq!(report.grade == Grade::A, clean && report.speaks_tls);
                prop_assert_eq!(report.reasons.is_empty(), report.grade == Grade::A);
            }
        }
    }
}
