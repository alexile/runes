//! Property tests: compiling and evaluating arbitrary rules never panics,
//! and literal matchers agree with plain substring search.

use proptest::prelude::*;
use rune_http_model::{ExchangeId, HttpBody, HttpExchange, HttpRequest, HttpResponse};
use rune_matchers::{
    Extractor, ExtractorKind, MAX_EXTRACTED_VALUES, MatchCondition, Matcher, MatcherKind,
    ResponsePart,
};

fn exchange(body: Vec<u8>) -> HttpExchange {
    HttpExchange::new(
        ExchangeId(1),
        "proptest",
        HttpRequest::get("http://host.test/"),
    )
    .with_response(
        HttpResponse::new(200)
            .with_header("Set-Cookie", "a=b")
            .with_body(HttpBody::new(body)),
    )
}

fn parts() -> impl Strategy<Value = ResponsePart> {
    prop_oneof![
        Just(ResponsePart::Body),
        Just(ResponsePart::Headers),
        Just(ResponsePart::All),
        Just(ResponsePart::Raw),
        Just(ResponsePart::Url),
        ".{0,8}".prop_map(ResponsePart::Header),
    ]
}

proptest! {
    #[test]
    fn arbitrary_matchers_never_panic(
        pattern in ".{0,40}",
        body in proptest::collection::vec(any::<u8>(), 0..256),
        part in parts(),
        ci in any::<bool>(),
    ) {
        let ex = exchange(body);
        let kinds = [
            MatcherKind::Regex { regex: vec![pattern.clone()] },
            MatcherKind::Binary { binary: vec![pattern.clone()] },
            MatcherKind::JsonPointer { pointer: pattern.clone(), value: None },
            MatcherKind::Header { name: "set-cookie".into(), value: Some(pattern) },
        ];
        for kind in kinds {
            let mut matcher = Matcher::new(kind).with_part(part.clone());
            if ci {
                matcher = matcher.ignoring_case();
            }
            if let Ok(compiled) = matcher.compile() {
                let _ = compiled.matches(&ex);
            }
        }
    }

    #[test]
    fn arbitrary_extractors_never_panic(
        path in ".{0,40}",
        body in ".{0,256}",
        group in 0_usize..3,
    ) {
        let ex = exchange(body.into_bytes());
        let kinds = [
            ExtractorKind::Regex { regex: vec![path.clone()], group },
            ExtractorKind::Json { json: vec![path.clone()] },
            ExtractorKind::Xpath { xpath: vec![path.clone()], attribute: None },
            ExtractorKind::Xpath { xpath: vec!["//*".into()], attribute: Some(path.clone()) },
            ExtractorKind::Kval { kval: vec![path] },
        ];
        for kind in kinds {
            if let Ok(compiled) = Extractor::new(kind).compile() {
                prop_assert!(compiled.extract(&ex).len() <= MAX_EXTRACTED_VALUES);
            }
        }
    }

    #[test]
    fn xpath_never_panics_on_arbitrary_markup(body in "[<>/a-c =\"'&;!\\[\\]CDAT-]{0,200}") {
        let ex = exchange(body.into_bytes());
        for path in ["//a", "/a/b/text()", "//b/@c", "/*"] {
            let extractor = Extractor::new(ExtractorKind::Xpath {
                xpath: vec![path.into()],
                attribute: None,
            });
            prop_assert!(extractor.extract(&ex).is_ok());
        }
    }

    #[test]
    fn word_matcher_agrees_with_substring_search(
        word in "[a-z]{1,4}",
        body in "[a-z ]{0,64}",
    ) {
        let ex = exchange(body.clone().into_bytes());
        let hit = Matcher::word([word.as_str()]).matches(&ex).unwrap();
        prop_assert_eq!(hit, body.contains(&word));
        let negated = Matcher::word([word.as_str()]).negated().matches(&ex).unwrap();
        prop_assert_eq!(negated, !hit);
        let both = Matcher::word([word.as_str(), "zzzzz"])
            .with_condition(MatchCondition::And)
            .matches(&ex)
            .unwrap();
        prop_assert_eq!(both, hit && body.contains("zzzzz"));
    }
}
