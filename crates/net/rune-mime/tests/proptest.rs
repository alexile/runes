//! Property tests: round trips, range invariants and no panics on arbitrary
//! input.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use proptest::prelude::*;
use rune_http_model::HeaderEntry;
use rune_mime::{
    Charset, ContentDisposition, MediaType, MimeError, MultipartOptions, Param, Part,
    detect_charset, encode_multipart, parse_multipart,
};

fn token() -> impl Strategy<Value = String> {
    "[A-Za-z0-9!#$%&'+.^_`|~-]{1,10}"
}

fn param() -> impl Strategy<Value = Param> {
    (token(), any::<String>(), any::<bool>()).prop_map(|(name, value, extended)| {
        if extended {
            Param::extended(&name, value).unwrap()
        } else {
            Param::new(&name, value).unwrap()
        }
    })
}

fn boundary() -> impl Strategy<Value = String> {
    "[A-Za-z0-9'()+_,./:=?-]{1,20}( [A-Za-z0-9]{1,5})?"
}

fn header() -> impl Strategy<Value = HeaderEntry> {
    (
        token(),
        "[!-~\u{a0}-\u{2ff}]([ -~\u{a0}-\u{2ff}]{0,20}[!-~])?|",
    )
        .prop_map(|(name, value)| HeaderEntry::new(name, value))
}

proptest! {
    #[test]
    fn media_type_round_trips(
        type_ in token(),
        subtype in token(),
        params in prop::collection::vec(param(), 0..4),
    ) {
        let mut mt = MediaType::new(&type_, &subtype).unwrap();
        mt.params = params;
        let text = mt.to_string();
        prop_assert_eq!(MediaType::parse(&text), Ok(mt), "{}", text);
        // Canonical: formatting the parsed value gives the same text.
        prop_assert_eq!(MediaType::parse(&text).unwrap().to_string(), text);
    }

    #[test]
    fn disposition_round_trips(kind in token(), params in prop::collection::vec(param(), 0..4)) {
        let mut cd = ContentDisposition::new(&kind).unwrap();
        cd.params = params;
        prop_assert_eq!(ContentDisposition::parse(&cd.to_string()), Ok(cd));
    }

    #[test]
    fn multipart_round_trips(
        boundary in boundary(),
        parts in prop::collection::vec(
            (prop::collection::vec(header(), 0..4), prop::collection::vec(any::<u8>(), 0..64)),
            0..6,
        ),
    ) {
        let parts: Vec<Part<'_>> = parts
            .iter()
            .map(|(headers, body)| Part::new(headers.clone(), body))
            .collect();
        let encoded = match encode_multipart(&boundary, &parts) {
            Err(MimeError::BoundaryInBody { .. }) => return Ok(()),
            other => other.unwrap(),
        };
        let parsed = parse_multipart(&encoded, &boundary, &MultipartOptions::default()).unwrap();
        prop_assert!(parsed.closed);
        prop_assert_eq!(parsed.preamble, b"");
        prop_assert_eq!(parsed.parts.len(), parts.len());
        for (back, part) in parsed.parts.iter().zip(&parts) {
            prop_assert_eq!(&back.headers, &part.headers);
            prop_assert_eq!(back.body, part.body);
            prop_assert_eq!(&encoded[back.body_range.clone()], back.body);
        }
    }

    #[test]
    fn multipart_never_panics_and_ranges_hold(
        body in prop::collection::vec(any::<u8>(), 0..256),
        boundary in "[a-z-]{1,3}",
        lenient in any::<bool>(),
    ) {
        let options = MultipartOptions::default()
            .with_require_close(!lenient)
            .with_max_parts(8)
            .with_max_header_bytes(32);
        if let Ok(parsed) = parse_multipart(&body, &boundary, &options) {
            prop_assert!(parsed.parts.len() <= 8);
            for part in &parsed.parts {
                prop_assert_eq!(&body[part.body_range.clone()], part.body);
                prop_assert!(part.headers_range.end == part.body_range.start);
                prop_assert!(part.headers_range.len() <= 32);
            }
        }
    }

    #[test]
    fn multipart_with_structure_never_panics(
        lines in prop::collection::vec(
            prop_oneof![
                Just("--b".to_owned()),
                Just("--b--".to_owned()),
                Just(String::new()),
                Just("A: 1".to_owned()),
                Just(" folded".to_owned()),
                "[ -~]{0,8}",
            ],
            0..16,
        ),
        crlf in any::<bool>(),
    ) {
        let body = lines.join(if crlf { "\r\n" } else { "\n" });
        let _ = parse_multipart(body.as_bytes(), "b", &MultipartOptions::default());
    }

    #[test]
    fn header_parsers_never_panic(text in any::<String>()) {
        if let Ok(mt) = MediaType::parse(&text) {
            prop_assert_eq!(MediaType::parse(&mt.to_string()), Ok(mt));
        }
        if let Ok(cd) = ContentDisposition::parse(&text) {
            prop_assert_eq!(ContentDisposition::parse(&cd.to_string()), Ok(cd));
        }
        let _ = Charset::from_label(&text);
    }

    #[test]
    fn charset_never_panics(body in prop::collection::vec(any::<u8>(), 0..256)) {
        let found = detect_charset(&body, None);
        for charset in [
            found.charset,
            Charset::Utf8,
            Charset::Utf16Le,
            Charset::Utf16Be,
            Charset::UsAscii,
            Charset::Iso8859_1,
            Charset::Windows1252,
        ] {
            if charset.is_decodable() {
                prop_assert!(charset.decode(&body).is_some());
            }
        }
    }

    #[test]
    fn latin1_decodes_every_byte(body in prop::collection::vec(any::<u8>(), 0..64)) {
        let text = Charset::Iso8859_1.decode(&body).unwrap();
        prop_assert_eq!(text.chars().count(), body.len());
    }
}
