//! The parsers never panic, and corrupting a certificate never makes it
//! verify.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use proptest::prelude::*;
use rune_x509::{Certificate, TrustStore, VerifyOptions, parse_pem, verify_chain};

fn fixture(name: &str) -> Certificate {
    let path = format!("{}/tests/fixtures/{name}.pem", env!("CARGO_MANIFEST_DIR"));
    Certificate::from_pem(&std::fs::read(path).unwrap()).unwrap()
}

/// Byte range of `tbsCertificate` in a certificate whose outer and TBS
/// lengths both use the two-byte long form (true for the fixtures).
fn tbs_range(der: &[u8]) -> (usize, usize) {
    assert_eq!(der[..2], [0x30, 0x82]);
    assert_eq!(der[4..6], [0x30, 0x82]);
    let len = usize::from(der[6]) << 8 | usize::from(der[7]);
    (4, 8 + len)
}

proptest! {
    #[test]
    fn der_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = Certificate::from_der(&bytes);
    }

    #[test]
    fn pem_never_panics(text in "\\PC*") {
        let _ = parse_pem(text.as_bytes());
        let wrapped = format!("-----BEGIN CERTIFICATE-----\n{text}\n-----END CERTIFICATE-----\n");
        let _ = parse_pem(wrapped.as_bytes());
    }

    #[test]
    fn flipped_bit_never_verifies(index in any::<prop::sample::Index>(), bit in 0u8..8) {
        // Only the signed part: bytes outside tbsCertificate (the outer
        // header, the signature itself) are not covered by the signature,
        // and the parser tolerates some non-DER encodings there.
        let leaf = fixture("leaf");
        let mut der = leaf.der().to_vec();
        let (start, end) = tbs_range(&der);
        let at = start + index.index(end - start);
        der[at] ^= 1 << bit;
        if let Ok(corrupt) = Certificate::from_der(&der) {
            let store = TrustStore::new().with(fixture("root"));
            let options = VerifyOptions::default().with_time(1_780_272_000);
            let report = verify_chain(&corrupt, &[fixture("inter")], &store, &options);
            prop_assert!(!report.is_trusted() || corrupt == leaf);
        }
    }
}

/// Every fixture's DER, the seeds for the mutation tests below.
fn seeds() -> Vec<Vec<u8>> {
    let dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let mut seeds: Vec<Vec<u8>> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension()? == "pem").then_some(path)
        })
        .flat_map(|path| parse_pem(&std::fs::read(path).unwrap()).unwrap())
        .map(|cert| cert.der().to_vec())
        .collect();
    seeds.sort();
    seeds
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn mutated_der_never_panics(
        seed in any::<prop::sample::Index>(),
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>(), 0u8..3), 1..8),
        cut in any::<prop::sample::Index>(),
    ) {
        let seeds = seeds();
        let mut der = seeds[seed.index(seeds.len())].clone();
        for (at, byte, op) in edits {
            if der.is_empty() {
                break;
            }
            let at = at.index(der.len());
            match op {
                0 => der[at] = byte,
                1 => der[at] ^= 1 << (byte % 8),
                _ => {
                    der.insert(at, byte);
                }
            }
        }
        if cut.index(4) == 0 {
            der.truncate(cut.index(der.len() + 1));
        }
        if let Ok(cert) = Certificate::from_der(&der) {
            // Everything reachable from a parsed certificate must hold up too.
            let summary = cert.summary();
            let _ = format!("{summary:?}");
            for san in &summary.subject_alt_names {
                let _ = san.to_string();
            }
            let _ = cert.to_pem();
            let _ = cert.matches_host("www.example.com");
            let _ = cert.matches_host("192.0.2.1");
            let _ = cert.verify_signed_by(&cert);
            let _ = cert.weaknesses(&rune_x509::Policy::default());
            let store = TrustStore::new().with(fixture("root"));
            let options = VerifyOptions::default().with_time(1_780_272_000);
            let _ = verify_chain(&cert, &[fixture("inter"), cert.clone()], &store, &options);
        }
    }
}
