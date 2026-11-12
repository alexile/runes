//! Property tests: round trips, case handling, error reporting, and
//! agreement between the different decoders.

use std::fmt::Write as _;
use std::io::{Read, Write};

use proptest::prelude::*;
use rune_hex::{
    DecodeOptions, HexError, ct, decode, decode_array, decode_to_slice, display, encode,
    encode_to_slice, encode_upper, encode_upper_to_slice,
    io::{DecodeReader, DecodeWriter, EncodeReader, EncodeWriter},
};

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..200)
}

fn not_hex() -> impl Strategy<Value = u8> {
    any::<u8>().prop_filter("not a hex digit", |b| !b.is_ascii_hexdigit())
}

proptest! {
    #[test]
    fn round_trips(data in bytes()) {
        prop_assert_eq!(decode(encode(&data)), Ok(data.clone()));
        prop_assert_eq!(decode(encode_upper(&data)), Ok(data.clone()));
        prop_assert_eq!(decode(format!("0x{}", encode(&data))), Ok(data.clone()));
        prop_assert_eq!(ct::decode(encode_upper(&data)), Ok(data));
    }

    #[test]
    fn upper_and_lower_agree(data in bytes()) {
        let lower = encode(&data);
        let upper = encode_upper(&data);
        prop_assert_eq!(&upper, &lower.to_ascii_uppercase());
        prop_assert!(lower.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        prop_assert_eq!(lower.len(), data.len() * 2);
        prop_assert_eq!(format!("{:X}", display(&data)), upper);
        prop_assert_eq!(display(&data).to_string(), lower.as_str());
        // Matches the standard library's formatting of each byte.
        let reference = data.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });
        prop_assert_eq!(lower, reference);
    }

    #[test]
    fn slice_apis_match_allocating_ones(data in bytes(), extra in 0usize..4) {
        let mut text = vec![b'#'; data.len() * 2 + extra];
        prop_assert_eq!(encode_to_slice(&data, &mut text).map(|s| s.to_owned()), Ok(encode(&data)));
        prop_assert_eq!(&text[data.len() * 2..], &vec![b'#'; extra][..]);
        prop_assert_eq!(encode_upper_to_slice(&data, &mut text).map(|s| s.to_owned()), Ok(encode_upper(&data)));

        let mut out = vec![0u8; data.len() + extra];
        prop_assert_eq!(decode_to_slice(&text[..data.len() * 2], &mut out).map(|b| b.to_vec()), Ok(data.clone()));
        prop_assert_eq!(ct::decode_to_slice(&text[..data.len() * 2], &mut out).map(|b| b.to_vec()), Ok(data.clone()));

        if !data.is_empty() {
            prop_assert_eq!(
                encode_to_slice(&data, &mut vec![0u8; data.len() * 2 - 1]).map(|s| s.len()),
                Err(HexError::BufferTooSmall { needed: data.len() * 2, available: data.len() * 2 - 1 })
            );
        }
    }

    #[test]
    fn odd_length_is_rejected(text in "([0-9a-fA-F]{2}){0,20}[0-9a-fA-F]") {
        prop_assert_eq!(decode(&text), Err(HexError::OddLength));
        prop_assert_eq!(ct::decode(&text), Err(HexError::OddLength));
        prop_assert_eq!(DecodeOptions::lenient().decode(&text), Err(HexError::OddLength));
        let mut w = DecodeWriter::new(Vec::new());
        prop_assert!(w.write_all(text.as_bytes()).is_ok());
        prop_assert!(w.finish().is_err());
    }

    #[test]
    fn invalid_bytes_are_located(data in bytes(), at in any::<prop::sample::Index>(), bad in not_hex()) {
        let mut text = encode(&data).into_bytes();
        text.push(b'0');
        text.push(b'0');
        let at = at.index(text.len());
        text[at] = bad;
        // "0x" at the very start is a valid prefix, not an error.
        prop_assume!(!(at == 1 && text[0] == b'0' && (bad | 0x20) == b'x'));
        let expected = HexError::InvalidByte { byte: bad, offset: at };
        prop_assert_eq!(decode(&text), Err(expected));
        prop_assert_eq!(decode_to_slice(&text, &mut vec![0; text.len()]).map(|b| b.len()), Err(expected));
        prop_assert_eq!(ct::decode(&text), Err(HexError::Invalid));
        let mut out = Vec::new();
        let err = DecodeReader::new(&text[..]).read_to_end(&mut out).unwrap_err();
        prop_assert_eq!(err.to_string(), expected.to_string());
    }

    #[test]
    fn valid_text_re_encodes(text in "([0-9a-fA-F]{2}){0,40}") {
        let bytes = decode(&text);
        prop_assert_eq!(bytes.as_ref().map(encode), Ok(text.to_lowercase()));
        prop_assert_eq!(ct::decode(&text), bytes);
    }

    #[test]
    fn tolerant_decoding_skips_between_bytes(
        data in bytes(),
        gaps in prop::collection::vec("[ \t\r\n:-]{0,3}", 0..201),
    ) {
        let digits = encode(&data);
        let mut text = String::new();
        for (i, pair) in digits.as_bytes().chunks(2).enumerate() {
            text.push_str(gaps.get(i).map_or("", String::as_str));
            text.push_str(std::str::from_utf8(pair).unwrap_or_default());
        }
        text.push_str(gaps.last().map_or("", String::as_str));
        prop_assert_eq!(DecodeOptions::lenient().decode(&text), Ok(data.clone()));
        let mut buf = vec![0u8; data.len()];
        prop_assert_eq!(DecodeOptions::lenient().decode_to_slice(&text, &mut buf).map(|b| b.to_vec()), Ok(data));
    }

    #[test]
    fn streams_match_one_shot(data in bytes(), split in 1usize..40) {
        let mut enc = EncodeWriter::new(Vec::new()).uppercase(true);
        for piece in data.chunks(split) {
            prop_assert!(enc.write_all(piece).is_ok());
        }
        let text = enc.into_inner();
        prop_assert_eq!(&text, &encode_upper(&data).into_bytes());

        let mut read_back = Vec::new();
        prop_assert!(EncodeReader::new(&data[..]).read_to_end(&mut read_back).is_ok());
        prop_assert_eq!(&read_back, &encode(&data).into_bytes());

        let mut dec = DecodeWriter::new(Vec::new());
        for piece in text.chunks(split) {
            prop_assert!(dec.write_all(piece).is_ok());
        }
        prop_assert_eq!(dec.finish().ok(), Some(data));
    }

    #[test]
    fn decoders_never_panic(text in prop_oneof![
        prop::collection::vec(any::<u8>(), 0..64),
        "(0x)?[0-9a-gA-G :x-]{0,48}".prop_map(String::into_bytes),
    ]) {
        let _ = decode(&text);
        let _ = ct::decode(&text);
        let _ = decode_array::<4>(&text);
        let _ = ct::decode_array::<4>(&text);
        let _ = DecodeOptions::lenient().decode(&text);
        let _ = DecodeOptions::lenient().decode_array::<3>(&text);
        let _ = decode_to_slice(&text, &mut [0u8; 5]);
        let _ = DecodeOptions::lenient().decode_to_slice(&text, &mut [0u8; 5]);
        let _ = DecodeReader::with_options(&text[..], DecodeOptions::lenient()).read_to_end(&mut Vec::new());
    }
}
