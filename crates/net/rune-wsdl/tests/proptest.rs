//! Property tests: the importer never panics on arbitrary or mutated
//! input, and envelopes stay well-formed whatever values are inserted.

#![allow(clippy::unwrap_used, reason = "test helpers")]

mod common;

use std::collections::BTreeMap;

use common::{read_envelope, text_at};
use proptest::prelude::*;
use rune_wsdl::{InsertionLocation, Options, parse};

fn calculator() -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/calculator.wsdl",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).unwrap()
}

/// The largest char boundary at or before `index` (MSRV-safe
/// `floor_char_boundary`).
fn boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// XML-ish fragments biased toward WSDL and XSD vocabulary.
fn fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::from("<xs:element name=\"a\" type=\"xs:int\"/>")),
        Just(String::from(
            "<xs:complexType name=\"T\"><xs:sequence><xs:element name=\"r\" type=\"tns:T\"/></xs:sequence></xs:complexType>"
        )),
        Just(String::from("<xs:group ref=\"tns:G\"/>")),
        Just(String::from(
            "<message name=\"m\"><part name=\"p\" type=\"tns:T\"/></message>"
        )),
        Just(String::from("</")),
        Just(String::from("&amp;")),
        "[<>/=\"a-z: ]{0,12}",
    ]
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse(&bytes, &Options::default());
    }

    #[test]
    fn spliced_documents_never_panic(at in 0usize..4096, insert in fragment(), cut in 0usize..64) {
        let mut text = String::from_utf8(calculator()).unwrap();
        let at = boundary(&text, at);
        let end = boundary(&text, at + cut);
        text.replace_range(at..end, &insert);
        if let Ok(spec) = parse(text.as_bytes(), &Options::default().with_max_nodes(64)) {
            for operation in &spec.operations {
                read_envelope(&operation.envelope);
            }
        }
    }

    #[test]
    fn inserted_values_round_trip(value in "\\PC{0,24}") {
        let spec = parse(&calculator(), &Options::default()).unwrap();
        for operation in &spec.operations {
            let values: BTreeMap<String, String> = operation
                .insertion_points
                .iter()
                .filter(|point| point.location == InsertionLocation::Element)
                .map(|point| (point.name.clone(), value.clone()))
                .collect();
            let elements = read_envelope(&operation.envelope_with(&values));
            for name in values.keys() {
                prop_assert_eq!(text_at(&elements, &format!("/Envelope{name}")), value.as_str());
            }
        }
    }
}
