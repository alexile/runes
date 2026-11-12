//! Properties: negotiation never panics and only picks offered codings the
//! client accepts; compression round-trips for every enabled coding.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::io::Read;

use proptest::prelude::*;
use rune_axum_compression::{Encoding, Level, compress, negotiate};

fn decompress(encoding: Encoding, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match encoding {
        Encoding::Gzip => {
            flate2::read::GzDecoder::new(data)
                .read_to_end(&mut out)
                .unwrap();
        }
        Encoding::Deflate => {
            flate2::read::ZlibDecoder::new(data)
                .read_to_end(&mut out)
                .unwrap();
        }
        #[cfg(feature = "br")]
        Encoding::Brotli => {
            brotli::Decompressor::new(data, 4096)
                .read_to_end(&mut out)
                .unwrap();
        }
        #[cfg(feature = "zstd")]
        Encoding::Zstd => out = zstd::decode_all(data).unwrap(),
        _ => out = data.to_vec(),
    }
    out
}

proptest! {
    #[test]
    fn negotiate_never_panics(header in ".*") {
        let picked = negotiate(&header, &Encoding::PREFERENCE);
        prop_assert!(picked.is_enabled());
    }

    #[test]
    fn zeroed_coding_is_never_picked(
        enc in prop::sample::select(Encoding::PREFERENCE.to_vec()),
        rest in prop::collection::vec((0usize..3, 1u8..10), 0..4),
    ) {
        let others: Vec<_> = Encoding::PREFERENCE.into_iter().filter(|e| *e != enc).collect();
        let mut header = rest
            .iter()
            .map(|(i, q)| format!("{};q=0.{q}, ", others[*i].as_str()))
            .collect::<Vec<_>>()
            .concat();
        header.push_str(enc.as_str());
        header.push_str(";q=0");
        prop_assert_eq!(negotiate(&header, &[enc]), Encoding::Identity);
        prop_assert_ne!(negotiate(&header, &Encoding::PREFERENCE), enc);
    }

    #[test]
    fn negotiate_picks_listed_coding(
        header in "((gzip|deflate|br|zstd|identity|\\*|x-gzip|foo)(;q=(0|1|0\\.[0-9]{1,3}))?, ?){0,6}",
    ) {
        let picked = negotiate(&header, &Encoding::PREFERENCE);
        if picked != Encoding::Identity {
            prop_assert!(header.contains(picked.as_str()) || header.contains('*'));
        }
    }

    #[test]
    fn round_trip(data in prop::collection::vec(any::<u8>(), 0..4096), level in 0u32..12) {
        for enc in Encoding::PREFERENCE.into_iter().filter(|e| e.is_enabled()) {
            let packed = compress(enc, Level::Precise(level), &data).unwrap();
            prop_assert_eq!(decompress(enc, &packed), data.clone());
        }
    }
}
