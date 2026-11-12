//! Properties: offers always encode to parseable hellos carrying exactly
//! the offered suites, and the response reader never panics.

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
